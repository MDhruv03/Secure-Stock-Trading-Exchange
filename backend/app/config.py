"""
Configuration for the Secure Trading Platform
"""
import os

# Application configuration
APP_TITLE = "Secure Trading Platform - Information Security Lab"
APP_DESCRIPTION = "A secure trading platform demonstrating cryptographic security and red/blue team simulations"
APP_VERSION = "2.0.0"

# Security configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback_secret_key_for_demo")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "trading_platform.db")

# Security settings
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION_HOURS = 24
RATE_LIMIT_REQUESTS = 200
RATE_LIMIT_WINDOW = 60  # seconds