@echo off
:: ============================================================
:: AI SOC Assistant — CLI Launcher (Windows)
:: ============================================================
:: Usage:
::   run_cli.bat analyse data\samples\ssh_bruteforce.log
::   run_cli.bat analyse data\samples\sql_injection.log --type web
::   run_cli.bat analyse data\samples\ssh_bruteforce.log --no-ai
::   run_cli.bat status
::
:: All additional arguments are forwarded to the CLI.
:: ============================================================

setlocal

:: Resolve the directory this script lives in so it works regardless
:: of where you call it from.
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Prefer a venv if one exists, otherwise fall back to system Python.
if exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    set "PYTHON=%SCRIPT_DIR%venv\Scripts\python.exe"
) else if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    set "PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

:: Verify Python is available.
"%PYTHON%" --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

:: Create outputs directory if it doesn't exist.
if not exist "outputs\reports" mkdir "outputs\reports"

:: Forward all arguments to the CLI module.
"%PYTHON%" -m app.cli %*

endlocal
