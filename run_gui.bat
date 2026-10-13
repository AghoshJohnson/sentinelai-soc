@echo off
:: ============================================================
:: AI SOC Assistant — Streamlit GUI Launcher (Windows)
:: ============================================================
:: Opens the Streamlit web interface in your default browser.
:: Leave this terminal window open while using the app.
:: ============================================================

setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Prefer a venv if one exists.
if exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    set "PYTHON=%SCRIPT_DIR%venv\Scripts\python.exe"
    set "STREAMLIT=%SCRIPT_DIR%venv\Scripts\streamlit.exe"
) else if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    set "PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"
    set "STREAMLIT=%SCRIPT_DIR%.venv\Scripts\streamlit.exe"
) else (
    set "PYTHON=python"
    set "STREAMLIT=streamlit"
)

:: Verify Streamlit is installed.
"%STREAMLIT%" --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Streamlit not found.
    echo         Install dependencies with:  pip install -r requirements.txt
    pause
    exit /b 1
)

:: Create outputs directory if it doesn't exist.
if not exist "outputs\reports" mkdir "outputs\reports"

echo.
echo  ============================================================
echo   AI SOC Assistant — Starting Streamlit GUI
echo   Opening at: http://localhost:8501
echo   Press Ctrl+C in this window to stop.
echo  ============================================================
echo.

"%STREAMLIT%" run app/gui.py ^
    --server.port 8501 ^
    --server.headless false ^
    --browser.gatherUsageStats false ^
    --theme.base dark

endlocal
