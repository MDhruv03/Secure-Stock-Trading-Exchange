@echo off
REM Secure Trading Platform Startup Script for Windows

echo === Secure Trading Platform ===
echo Starting information security laboratory environment
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Check if pip is available
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not installed or not in PATH
    echo Please install pip and try again
    pause
    exit /b 1
)

echo [INFO] Installing/updating Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [INFO] Initializing database...
python -c "import sys; sys.path.append('.'); from backend.app.database import get_db_manager; db = get_db_manager(); print('[INFO] Database initialized successfully')"

echo.
echo === Platform Ready ===
echo Navigate to: http://localhost:8000
echo Press Ctrl+C to stop the server
echo.

REM Start the server
python backend/app/main.py

pause