@echo off
setlocal
title NRIS Launcher

echo ===================================================
echo      NIPT RESULT INTERPRETATION SYSTEM (NRIS)
echo ===================================================
echo.

:: 0. CHECK FOR PROGRAM FILE
if not exist "NRIS.py" (
    echo [ERROR] NRIS.py not found!
    echo Please make sure this file is in the same folder as NRIS.py
    pause
    exit /b
)

:: 1. CHECK FOR PYTHON
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed.
    echo Please download it from python.org and check "Add to PATH".
    pause
    exit /b
)

:: 2. CREATE ISOLATED ENVIRONMENT (venv_NRIS)
:: This creates a folder specifically for this app, ignoring others.
if not exist "venv_NRIS" (
    echo [INFO] Creating isolated environment 'venv_NRIS'...
    python -m venv venv_NRIS
)

:: 3. ACTIVATE & INSTALL SPECIFIC REQUIREMENTS
call venv_NRIS\Scripts\activate

:: Check if the specific requirements file exists
if exist "requirements_NRIS.txt" (
    echo [INFO] Checking NRIS dependencies...
    pip install -r requirements_NRIS.txt >nul 2>&1
) else (
    echo [ERROR] requirements_NRIS.txt not found!
    pause
    exit /b
)

:: 4. LAUNCH NRIS
echo.
echo [SUCCESS] Launching NRIS Dashboard...
echo Close this window to stop the application.
echo.

streamlit run NRIS.py

pause
