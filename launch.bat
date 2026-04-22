@echo off
:: Launch LogWatcher desktop app using the project virtualenv (Windows)
SET SCRIPT_DIR=%~dp0
SET VENV_PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe

IF NOT EXIST "%VENV_PYTHON%" (
    echo ERROR: virtualenv not found at %VENV_PYTHON%
    echo Run: python -m venv .venv ^&^& pip install -r requirements.txt
    pause
    exit /b 1
)

"%VENV_PYTHON%" "%SCRIPT_DIR%run_desktop.py" %*
