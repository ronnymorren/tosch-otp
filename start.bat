@echo off
echo ============================================
echo   Tosch OTP starten...
echo ============================================
echo.

cd /d "%~dp0"

echo Pakketten installeren...
python -m pip install -r requirements.txt --quiet

echo.
echo Server starten op http://localhost:8000
echo Druk op Ctrl+C om te stoppen.
echo.

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

pause
