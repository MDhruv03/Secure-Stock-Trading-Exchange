#!/bin/bash

# Secure Trading Platform Startup Script

echo "=== Secure Trading Platform ==="
echo "Starting information security laboratory environment"
echo ""

# Check if running on Windows
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "[INFO] Running on Windows environment"
    
    # Check if Python is available
    if ! command -v python &> /dev/null; then
        echo "[ERROR] Python is not installed or not in PATH"
        echo "Please install Python 3.8+ and try again"
        exit 1
    fi
    
    # Check if pip is available
    if ! command -v pip &> /dev/null; then
        echo "[ERROR] pip is not installed or not in PATH"
        echo "Please install pip and try again"
        exit 1
    fi
    
    echo "[INFO] Installing/updating Python dependencies..."
    pip install -r requirements.txt
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
    
    echo "[INFO] Initializing database..."
    python -c "
import sys
sys.path.append('.')
from backend.app.database import get_db_manager
db = get_db_manager()
print('[INFO] Database initialized successfully')
"
    
    echo ""
    echo "=== Platform Ready ==="
    echo "Navigate to: http://localhost:8000"
    echo "Press Ctrl+C to stop the server"
    echo ""
    
    # Start the server
    python backend/app/main.py
    
elif [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[INFO] Running on Linux/macOS environment"
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        echo "[ERROR] Python 3 is not installed or not in PATH"
        echo "Please install Python 3.8+ and try again"
        exit 1
    fi
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        echo "[ERROR] pip3 is not installed or not in PATH"
        echo "Please install pip3 and try again"
        exit 1
    fi
    
    echo "[INFO] Installing/updating Python dependencies..."
    pip3 install -r requirements.txt
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
    
    echo "[INFO] Initializing database..."
    python3 -c "
import sys
sys.path.append('.')
from backend.app.database import get_db_manager
db = get_db_manager()
print('[INFO] Database initialized successfully')
"
    
    echo ""
    echo "=== Platform Ready ==="
    echo "Navigate to: http://localhost:8000"
    echo "Press Ctrl+C to stop the server"
    echo ""
    
    # Start the server
    python3 backend/app/main.py
    
else
    echo "[ERROR] Unsupported operating system: $OSTYPE"
    echo "This script supports Windows, Linux, and macOS"
    exit 1
fi