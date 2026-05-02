import base64
import hashlib
import os
import secrets
import string
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware


# ── Configuratie ──────────────────────────────────────────────────────────────

load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

SERVER_SECRET = os.getenv("SERVER_SECRET")
DATABASE_URL  = os.getenv("DATABASE_URL", "")

# 🔴 Kritiek: weiger op te starten zonder encryptiesleutel
if not SERVER_SECRET:
    raise RuntimeError(
        "SERVER_SECRET is niet ingesteld. Voeg deze toe aan .env of Vercel Environment Variables."
    )


# ── Encryptie ─────────────────────────────────────────────────────────────────

def _fernet(token: str) -> Fernet:
    """Fernet-sleutel afgeleid van SERVER_SECRET + token (per-secret uniek)."""
    raw = hashlib.sha256((SERVER_SECRET + token).encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)

def versleutel(text: str, token: str) -> str:
    return _fernet(token).encrypt(text.encode()).decode()

def ontsleutel(ciphertext: str, token: str) -> str:
    return _fernet(token).decrypt(ciphertext.encode()).decode()

def hash_passphrase(pp: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 met per-secret salt — bestand tegen rainbow tables."""
    dk = hashlib.pbkdf2_hmac("sha256", pp.strip().encode(), salt.encode(), 200_000)
    return base64.b64encode(dk).decode()

def nieuw_salt() -> str:
    return secrets.token_hex(16)


# ── Database ──────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def get_cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
    conn = get_conn()
    cur  = get_cur(conn)

    # Hoofdtabel
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otp_secrets (
            id               SERIAL  PRIMARY KEY,
            token            TEXT    UNIQUE NOT NULL,
            ciphertext       TEXT    NOT NULL,
            expire_at        TEXT,
            views_left       INTEGER,
            one_step         INTEGER DEFAULT 0,
            allow_delete     INTEGER DEFAULT 0,
            passphrase       TEXT,
            passphrase_salt  TEXT,
            failed_attempts  INTEGER DEFAULT 0,
            locked_until     TEXT,
            created_at       TEXT    NOT NULL
        )
    """)

    # Migraties voor bestaande databases
    for col, definition in [
        ("passphrase_salt", "TEXT"),
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until",    "TEXT"),
    ]:
        try:
            cur.execute(f"ALTER TABLE otp_secrets ADD COLUMN IF NOT EXISTS {col} {definition}")
        except Exception:
            conn.rollback()

    # Audit log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otp_audit (
            id         SERIAL PRIMARY KEY,
            token      TEXT,
            event      TEXT,
            ip         TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def log_audit(conn, cur, token: str, event: str, ip: str):
    """Schrijf een audit-regel (valt stil bij fout — nooit blokkeren)."""
    try:
        cur.execute(
            "INSERT INTO otp_audit (token, event, ip, created_at) VALUES (%s, %s, %s, %s)",
            (token, event, ip, datetime.now().isoformat()),
        )
    except Exception:
        pass

try:
    init_db()
except Exception:
    pass


# ── Rate limiting ─────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self';"
        )
        return response


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    try:
        init_db()
    except Exception:
        pass
    yield

app = FastAPI(
    lifespan=lifespan,
    docs_url=None,       # 🔴 Swagger UI uitgeschakeld in productie
    redoc_url=None,      # 🔴 ReDoc uitgeschakeld in productie
    openapi_url=None,    # 🔴 OpenAPI schema niet publiek
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SecurityHeadersMiddleware)

BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
jinja_env = Environment(loader=FileSystemLoader(str(BASE / "templates")), cache_size=0)
templates = Jinja2Templates(env=jinja_env)


# ── Hulpfunctie: IP ophalen ───────────────────────────────────────────────────

def get_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


# ── Pagina's ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "home.html")


@app.get("/s/{token}", response_class=HTMLResponse)
async def secret_page(request: Request, token: str):
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM otp_secrets WHERE token = %s", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return templates.TemplateResponse(request, "expired.html",
            {"reden": "Deze link bestaat niet of is al verlopen."})

    if row["expire_at"] and datetime.now() > datetime.fromisoformat(row["expire_at"]):
        log_audit(conn, cur, token, "expired", get_ip(request))
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return templates.TemplateResponse(request, "expired.html",
            {"reden": "Deze link is verlopen."})

    if row["views_left"] is not None and row["views_left"] <= 0:
        log_audit(conn, cur, token, "max_views_reached", get_ip(request))
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return templates.TemplateResponse(request, "expired.html",
            {"reden": "Deze link is al het maximale aantal keren bekeken."})

    conn.close()
    return templates.TemplateResponse(request, "secret.html", {
        "token":          token,
        "one_step":       bool(row["one_step"]),
        "has_passphrase": bool(row["passphrase"]),
        "allow_delete":   bool(row["allow_delete"]),
    })


# ── API: geheim aanmaken ──────────────────────────────────────────────────────

@app.post("/api/secret/create")
@limiter.limit("20/minute")          # max 20 aanmaken per IP per minuut
async def create_secret(request: Request):
    data = await request.json()

    text = data.get("text", "").strip()
    if not text:
        raise HTTPException(400, "Geen tekst opgegeven")
    if len(text) > 1_048_576:
        raise HTTPException(400, "Tekst te lang (max 1 MB)")

    expire_hours = int(data.get("expire_hours", 168))
    expire_at    = (datetime.now() + timedelta(hours=expire_hours)).isoformat() \
                   if expire_hours > 0 else None

    views_raw  = int(data.get("views", 5))
    views_left = views_raw if views_raw > 0 else None

    one_step     = 1 if data.get("one_step")     else 0
    allow_delete = 1 if data.get("allow_delete") else 0

    passphrase_raw  = data.get("passphrase", "").strip()
    passphrase_salt = nieuw_salt() if passphrase_raw else None
    passphrase_hash = hash_passphrase(passphrase_raw, passphrase_salt) if passphrase_raw else None

    token      = secrets.token_urlsafe(10)
    ciphertext = versleutel(text, token)
    created_at = datetime.now().isoformat()

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        INSERT INTO otp_secrets
            (token, ciphertext, expire_at, views_left, one_step, allow_delete,
             passphrase, passphrase_salt, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (token, ciphertext, expire_at, views_left, one_step, allow_delete,
          passphrase_hash, passphrase_salt, created_at))

    log_audit(conn, cur, token, "created", get_ip(request))
    conn.commit()
    conn.close()

    return JSONResponse({"token": token})


# ── API: geheim onthullen ─────────────────────────────────────────────────────

@app.post("/api/secret/{token}/reveal")
@limiter.limit("30/minute")          # max 30 pogingen per IP per minuut
async def reveal_secret(token: str, request: Request):
    data             = await request.json()
    passphrase_input = data.get("passphrase", "").strip()
    ip               = get_ip(request)

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM otp_secrets WHERE token = %s", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(404, "Link bestaat niet of is verlopen")

    # Vervaldatum
    if row["expire_at"] and datetime.now() > datetime.fromisoformat(row["expire_at"]):
        log_audit(conn, cur, token, "expired", ip)
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(410, "Link is verlopen")

    # Max weergaven
    if row["views_left"] is not None and row["views_left"] <= 0:
        log_audit(conn, cur, token, "max_views_reached", ip)
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(410, "Link is al het maximale aantal keren bekeken")

    # Passphrase lockout controleren
    if row.get("locked_until"):
        if datetime.now() < datetime.fromisoformat(row["locked_until"]):
            conn.close()
            raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over 15 minuten opnieuw.")

    # Passphrase validatie
    if row["passphrase"]:
        salt = row.get("passphrase_salt") or ""
        if salt:
            # Nieuw formaat: PBKDF2 met salt
            invoer_hash = hash_passphrase(passphrase_input, salt)
        else:
            # Oud formaat: gewone SHA-256 (backwards compat)
            invoer_hash = hashlib.sha256(passphrase_input.encode()).hexdigest()

        if invoer_hash != row["passphrase"]:
            pogingen = (row.get("failed_attempts") or 0) + 1
            if pogingen >= 5:
                locked = (datetime.now() + timedelta(minutes=15)).isoformat()
                cur.execute(
                    "UPDATE otp_secrets SET failed_attempts=%s, locked_until=%s WHERE token=%s",
                    (pogingen, locked, token),
                )
                log_audit(conn, cur, token, "locked_out", ip)
            else:
                cur.execute(
                    "UPDATE otp_secrets SET failed_attempts=%s WHERE token=%s",
                    (pogingen, token),
                )
                log_audit(conn, cur, token, "failed_passphrase", ip)
            conn.commit()
            conn.close()
            raise HTTPException(403, "Onjuiste wachtwoordzin")

    # Ontsleutelen
    try:
        plaintext = ontsleutel(row["ciphertext"], token)
    except Exception:
        conn.close()
        raise HTTPException(500, "Ontsleuteling mislukt")

    # ── Atomair weergaven verlagen / verwijderen ──────────────────────────────
    if row["views_left"] is not None:
        # Atomaire UPDATE — voorkomt race condition bij gelijktijdige verzoeken
        cur.execute("""
            UPDATE otp_secrets SET views_left = views_left - 1
            WHERE token = %s AND views_left > 0
        """, (token,))
        new_views = row["views_left"] - 1
        if new_views <= 0:
            cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))

    log_audit(conn, cur, token, "revealed", ip)
    conn.commit()
    conn.close()

    return JSONResponse({"plaintext": plaintext})


# ── API: geheim verwijderen ───────────────────────────────────────────────────

@app.delete("/api/secret/{token}")
@limiter.limit("10/minute")
async def delete_secret(token: str, request: Request):
    ip   = get_ip(request)
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT allow_delete FROM otp_secrets WHERE token = %s", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(404, "Link niet gevonden")
    if not row["allow_delete"]:
        conn.close()
        raise HTTPException(403, "Verwijdering niet toegestaan voor deze link")

    cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
    log_audit(conn, cur, token, "deleted_by_recipient", ip)
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


# ── API: wachtwoord genereren ─────────────────────────────────────────────────

@app.get("/api/password/generate")
@limiter.limit("60/minute")
async def generate_password(request: Request, length: int = 20, upper: bool = True,
                             numbers: bool = True, symbols: bool = False):
    chars  = string.ascii_lowercase
    if upper:   chars += string.ascii_uppercase
    if numbers: chars += string.digits
    if symbols: chars += "!@#$%^&*"
    length   = max(8, min(64, length))
    password = "".join(secrets.choice(chars) for _ in range(length))
    return JSONResponse({"password": password})
