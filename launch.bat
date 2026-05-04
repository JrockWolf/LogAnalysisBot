@echo off
:: Launch LogAnalysisBot — desktop mode preferred, web mode fallback
SET SCRIPT_DIR=%~dp0

:: ── 1. Try the .venv312 desktop venv first (Python 3.12, all features) ──────
SET VENV312=%SCRIPT_DIR%.venv312\Scripts\python.exe
IF EXIST "%VENV312%" (
    echo [launch] Using .venv312 (Python 3.12 desktop venv)
    "%VENV312%" "%SCRIPT_DIR%run_desktop.py" %*
    exit /b %ERRORLEVEL%
)

:: ── 2. Search py launcher for any supported version (3.14 down to 3.9) ──────────
FOR %%V IN (3.14 3.13 3.12 3.11 3.10 3.9) DO (
    py -%%V --version >nul 2>&1
    IF NOT ERRORLEVEL 1 (
        echo [launch] Found Python %%V via py launcher
        IF NOT EXIST "%SCRIPT_DIR%.venv\Scripts\python.exe" (
            echo [launch] Creating virtualenv with Python %%V ...
            py -%%V -m venv "%SCRIPT_DIR%.venv"
            "%SCRIPT_DIR%.venv\Scripts\pip" install --quiet -r "%SCRIPT_DIR%requirements-desktop.txt"
        )
        "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%run_desktop.py" %*
        exit /b %ERRORLEVEL%
    )
)

:: ── 3. Fall back to any Python on PATH (web-only, no desktop window) ─────────
python --version >nul 2>&1
IF NOT ERRORLEVEL 1 (
    echo [launch] WARNING: Desktop deps unavailable in this environment.
    echo [launch] Falling back to web mode on http://localhost:8000
    IF NOT EXIST "%SCRIPT_DIR%.venv\Scripts\python.exe" (
        python -m venv "%SCRIPT_DIR%.venv"
        "%SCRIPT_DIR%.venv\Scripts\pip" install --quiet -r "%SCRIPT_DIR%requirements.txt"
    )
    "%SCRIPT_DIR%.venv\Scripts\python.exe" -m uvicorn src.webapp:app --host 127.0.0.1 --port 8000
    exit /b %ERRORLEVEL%
)

echo ERROR: No Python installation found.
echo Install Python from https://www.python.org/downloads/
pause
exit /b 1

