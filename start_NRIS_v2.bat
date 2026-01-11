@echo off
setlocal
title NRIS v2.0 Enhanced Launcher

echo ===================================================
echo   NIPT RESULT INTERPRETATION SYSTEM v2.0
echo   Enhanced Edition with Authentication ^& Analytics
echo ===================================================
echo.

:: 0. CHECK FOR PROGRAM FILE
if not exist "NRIS_Enhanced.py" (
    echo [ERROR] NRIS_Enhanced.py not found!
    echo Please make sure this file is in the same folder as NRIS_Enhanced.py
    pause
    exit /b
)

:: 1. CHECK FOR PYTHON
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please download Python 3.8+ from python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b
)

echo [OK] Python detected
python --version

:: 2. CREATE ISOLATED ENVIRONMENT (venv_NRIS_v2)
if not exist "venv_NRIS_v2" (
    echo.
    echo [INFO] Creating isolated virtual environment 'venv_NRIS_v2'...
    echo This only happens once and may take a minute...
    python -m venv venv_NRIS_v2
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b
    )
    echo [OK] Virtual environment created
)

:: 3. ACTIVATE ENVIRONMENT
echo.
echo [INFO] Activating virtual environment...
call venv_NRIS_v2\Scripts\activate
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b
)

:: 4. INSTALL/UPDATE DEPENDENCIES
if exist "requirements_NRIS_v2.txt" (
    echo.
    echo [INFO] Checking and installing dependencies...
    echo This may take a minute on first run...
    pip install --upgrade pip --quiet
    pip install -r requirements_NRIS_v2.txt --quiet
    if %errorlevel% neq 0 (
        echo [WARN] Some dependencies may have failed to install
        echo Trying individual installation...
        pip install streamlit pandas plotly reportlab openpyxl xlsxwriter
    )
    echo [OK] Dependencies ready
) else (
    echo.
    echo [WARN] requirements_NRIS_v2.txt not found!
    echo Installing core dependencies manually...
    pip install streamlit pandas plotly reportlab openpyxl xlsxwriter
)

:: 5. LAUNCH NRIS v2.0
echo.
echo ===================================================
echo [SUCCESS] Launching NRIS v2.0 Enhanced Edition...
echo ===================================================
echo.
echo Default Login Credentials:
echo   Username: admin
echo   Password: admin123
echo.
echo IMPORTANT: Change default password after first login!
echo.
echo The application will open in your default web browser.
echo Close this window to stop the application.
echo.
echo ===================================================
echo.

streamlit run NRIS_Enhanced.py --server.headless true --server.port 8501

:: Keep window open if error occurs
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application failed to start
    echo Check the error messages above
    pause
)
