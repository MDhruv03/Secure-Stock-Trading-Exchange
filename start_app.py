#!/usr/bin/env python3
"""
Start script for Secure Trading Platform
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

if __name__ == "__main__":
    try:
        from backend.app.main import app
        import uvicorn
        
        print("Starting Secure Trading Platform...")
        print("Access the application at: http://localhost:8000")
        print("Press Ctrl+C to stop the server")
        
        uvicorn.run(app, host="127.0.0.1", port=8000)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)