# Installation Guide

## Prerequisites

Before installing the Secure Trading Platform, ensure you have the following:

1. **Python 3.8 or higher**
2. **pip package manager**
3. **Git** (optional, for cloning the repository)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/secure-trading-platform.git
cd secure-trading-platform
```

Or download and extract the ZIP file.

### 2. Create a Virtual Environment (Recommended)

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install all required packages:
- FastAPI
- Uvicorn
- SQLite3
- Cryptography libraries
- Pydantic
- Jinja2
- And others listed in requirements.txt

### 4. Initialize the Database

```bash
python -c "
import sys
sys.path.append('.')
from backend.app.database import DatabaseManager
db = DatabaseManager()
print('Database initialized successfully!')
"
```

### 5. Start the Application

#### Method 1: Using the startup script
```bash
# On Windows
start.bat

# On macOS/Linux
chmod +x start.sh
./start.sh
```

#### Method 2: Manual start
```bash
# On Windows
python backend\app\main.py

# On macOS/Linux
python3 backend/app/main.py
```

### 6. Access the Application

Open your web browser and navigate to:
```
http://localhost:8000
```

## System Requirements

### Minimum Requirements
- **CPU**: 1 GHz processor or faster
- **RAM**: 1 GB RAM
- **Disk Space**: 100 MB available space
- **Operating System**: Windows 7+/macOS 10.12+/Linux

### Recommended Requirements
- **CPU**: 2 GHz dual-core processor
- **RAM**: 4 GB RAM
- **Disk Space**: 1 GB available space
- **Operating System**: Windows 10+/macOS 10.15+/Linux (Ubuntu 20.04+)

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Secret key for JWT tokens (change in production)
SECRET_KEY=your-secret-key-here-change-in-production

# Database configuration
DATABASE_URL=sqlite:///./trading_platform.db

# Cryptographic settings
AES_KEY=your-aes-key-here-must-be-32-bytes
RSA_KEY_SIZE=2048

# Security settings
MAX_LOGIN_ATTEMPTS=5
BLOCK_DURATION_MINUTES=30

# Development settings
DEBUG=True
```

### Customization Options

1. **Change Port**: Modify the port in `backend/app/main.py`
2. **Database Location**: Change the database path in `backend/app/database.py`
3. **Security Thresholds**: Adjust settings in the `.env` file

## Troubleshooting

### Common Issues

#### 1. "Module not found" errors
```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

#### 2. Database initialization fails
```bash
# Solution: Delete existing database and reinitialize
rm trading_platform.db  # On Windows: del trading_platform.db
python -c "
import sys
sys.path.append('.')
from backend.app.database import DatabaseManager
db = DatabaseManager()
print('Database reinitialized successfully!')
"
```

#### 3. Port already in use
```bash
# Solution: Change port in backend/app/main.py
# Or stop the existing process:
# On Windows: taskkill /PID <pid> /F
# On macOS/Linux: kill -9 <pid>
```

#### 4. Slow performance
```bash
# Solution: Ensure you have sufficient system resources
# Consider upgrading to recommended requirements
```

### Performance Optimization

1. **Use Production Server**: For production, use Gunicorn or similar
2. **Enable Caching**: Implement Redis for session caching
3. **Database Optimization**: Use connection pooling for SQLite
4. **Static Files**: Serve static files through a CDN or Nginx

## Testing

Run the test suite to verify installation:

```bash
python -m pytest tests/
```

Or run individual test modules:

```bash
python tests/test_suite.py
```

## Updates

To update the application:

1. **Pull Latest Changes** (if using Git):
   ```bash
   git pull origin main
   ```

2. **Update Dependencies**:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **Restart the Application**:
   ```bash
   # Stop current process (Ctrl+C)
   # Then restart
   python backend/app/main.py
   ```

## Support

For support, please:

1. **Check the FAQ section** in this document
2. **Review error messages carefully**
3. **Consult the project documentation**
4. **Open an issue** on the GitHub repository (if available)

## Next Steps

After successful installation, explore:

1. **The Web Interface**: http://localhost:8000
2. **API Documentation**: http://localhost:8000/docs
3. **Laboratory Exercises**: Follow the exercises in the documentation
4. **Security Simulations**: Test the red/blue team features

Congratulations! You have successfully installed the Secure Trading Platform for your information security laboratory.