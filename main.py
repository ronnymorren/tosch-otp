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

# ── Configuratie ──────────────────────────────────────────────────────────────

load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

SERVER_SECRET = os.getenv("SERVER_SECRET", "tosch-otp-secret-2024")
DATABASE_URL  = os.getenv("DATABASE_URL", "")


# ── Encryptie ─────────────────────────────────────────────────────────────────

def _fernet(token: str) -> Fernet:
    """Maak een Fernet-sleutel afgeleid van SERVER_SECRET + token."""
    raw = hashlib.sha256((SERVER_SECRET + token).encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)

def versleutel(text: str, token: str) -> str:
    return _fernet(token).encrypt(text.encode()).decode()

def ontsleutel(ciphertext: str, token: str) -> str:
    return _fernet(token).decrypt(ciphertext.encode()).decode()

def hash_passphrase(pp: str) -> str:
    return hashlib.sha256(pp.strip().encode()).hexdigest()


# ── Database ──────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def get_cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otp_secrets (
            id           SERIAL  PRIMARY KEY,
            token        TEXT    UNIQUE NOT NULL,
            ciphertext   TEXT    NOT NULL,
            expire_at    TEXT,
            views_left   INTEGER,
            one_step     INTEGER DEFAULT 0,
            allow_delete INTEGER DEFAULT 0,
            passphrase   TEXT,
            created_at   TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()

try:
    init_db()
except Exception:
    pass


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app):
    try:
        init_db()
    except Exception:
        pass
    yield

app = FastAPI(lifespan=lifespan)

BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
jinja_env = Environment(loader=FileSystemLoader(str(BASE / "templates")), cache_size=0)
templates  = Jinja2Templates(env=jinja_env)


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

    # Tijdcontrole
    if row["expire_at"] and datetime.now() > datetime.fromisoformat(row["expire_at"]):
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        return templates.TemplateResponse(request, "expired.html",
            {"reden": "Deze link is verlopen."})

    # Weergavecontrole
    if row["views_left"] is not None and row["views_left"] <= 0:
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

    one_step        = 1 if data.get("one_step")     else 0
    allow_delete    = 1 if data.get("allow_delete") else 0
    passphrase_raw  = data.get("passphrase", "").strip()
    passphrase_hash = hash_passphrase(passphrase_raw) if passphrase_raw else None

    token      = secrets.token_urlsafe(10)
    ciphertext = versleutel(text, token)
    created_at = datetime.now().isoformat()

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("""
        INSERT INTO otp_secrets
            (token, ciphertext, expire_at, views_left, one_step, allow_delete, passphrase, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (token, ciphertext, expire_at, views_left, one_step, allow_delete,
          passphrase_hash, created_at))
    conn.commit()
    conn.close()

    return JSONResponse({"token": token})


# ── API: geheim onthullen ─────────────────────────────────────────────────────

@app.post("/api/secret/{token}/reveal")
async def reveal_secret(token: str, request: Request):
    data             = await request.json()
    passphrase_input = data.get("passphrase", "").strip()

    conn = get_conn()
    cur  = get_cur(conn)
    cur.execute("SELECT * FROM otp_secrets WHERE token = %s", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(404, "Link bestaat niet of is verlopen")

    if row["expire_at"] and datetime.now() > datetime.fromisoformat(row["expire_at"]):
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(410, "Link is verlopen")

    if row["views_left"] is not None and row["views_left"] <= 0:
        cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(410, "Link is al het maximale aantal keren bekeken")

    if row["passphrase"]:
        if hash_passphrase(passphrase_input) != row["passphrase"]:
            conn.close()
            raise HTTPException(403, "Onjuiste wachtwoordzin")

    try:
        plaintext = ontsleutel(row["ciphertext"], token)
    except Exception:
        conn.close()
        raise HTTPException(500, "Ontsleuteling mislukt")

    # Weergaven verlagen of verwijderen
    if row["views_left"] is not None:
        new_views = row["views_left"] - 1
        if new_views <= 0:
            cur.execute("DELETE FROM otp_secrets WHERE token = %s", (token,))
        else:
            cur.execute("UPDATE otp_secrets SET views_left = %s WHERE token = %s",
                        (new_views, token))
    conn.commit()
    conn.close()

    return JSONResponse({"plaintext": plaintext})


# ── API: geheim verwijderen ───────────────────────────────────────────────────

@app.delete("/api/secret/{token}")
async def delete_secret(token: str):
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
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})


# ── API: wachtwoord genereren ─────────────────────────────────────────────────

@app.get("/api/password/generate")
async def generate_password(length: int = 20, upper: bool = True,
                             numbers: bool = True, symbols: bool = False):
    chars = string.ascii_lowercase
    if upper:   chars += string.ascii_uppercase
    if numbers: chars += string.digits
    if symbols: chars += "!@#$%^&*"
    length   = max(8, min(64, length))
    password = "".join(secrets.choice(chars) for _ in range(length))
    return JSONResponse({"password": password})
