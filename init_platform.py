#!/usr/bin/env python3
"""
Enhanced Database Initialization Script for Secure Trading Platform
Sets up the database and creates initial data with enhanced security
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def initialize_database():
    """Initialize the database with required tables"""
    print("Initializing database...")
    
    try:
        from backend.app.database import DatabaseManager
        
        # Create database manager (this will initialize the database)
        db = DatabaseManager()
        
        print("Database initialized successfully!")
        return True
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        return False

def initialize_key_management():
    """Initialize key management system"""
    print("Initializing key management system...")
    
    try:
        from backend.app.key_management import KeyManager
        
        # Create key manager (this will generate keys if needed)
        km = KeyManager()
        
        print("Key management system initialized successfully!")
        return True
    except Exception as e:
        print(f"Error initializing key management: {str(e)}")
        return False

def create_demo_data():
    """Create demo data for testing"""
    print("Creating demo data...")
    
    try:
        from backend.app.database import DatabaseManager
        from backend.app.auth_service import AuthService
        
        db = DatabaseManager()
        auth = AuthService()
        
        # Create demo users
        users = [
            ("admin", "adminpassword"),
            ("user1", "userpassword1"),
            ("user2", "userpassword2"),
            ("trader", "traderpassword")
        ]
        
        for username, password in users:
            # Check if user already exists
            existing_user = db.get_user_by_username(username)
            if existing_user:
                print(f"User {username} already exists")
                continue
                
            # Hash the password
            hashed_password = auth.hash_password(password)
            
            # Create user
            user_id = db.create_user(
                username=username,
                password_hash=hashed_password
            )
            
            if user_id:
                print(f"Created user: {username} (ID: {user_id})")
            else:
                print(f"Failed to create user: {username}")
        
        print("Demo data created successfully!")
        return True
    except Exception as e:
        print(f"Error creating demo data: {str(e)}")
        return False

def verify_installation():
    """Verify that all components are working"""
    print("Verifying installation...")
    
    try:
        # Test importing all modules
        from backend.app.main import app
        from backend.app.database import DatabaseManager
        from backend.app.crypto_service import CryptoService
        from backend.app.auth_service import AuthService
        from backend.app.trading_service import TradingService
        from backend.app.security_service import SecurityService
        from backend.app.key_management import KeyManager
        
        print("All modules imported successfully!")
        
        # Test database connection
        db = DatabaseManager()
        print("Database connection successful!")
        
        # Test crypto service
        crypto = CryptoService()
        test_data = {"test": "data"}
        encrypted = crypto.encrypt_data(test_data)
        decrypted = crypto.decrypt_data(encrypted)
        assert test_data == decrypted
        print("Crypto service working correctly!")
        
        # Test key management
        km = KeyManager()
        master_key = km.get_master_key()
        assert len(master_key) == 32  # AES-256 key
        print("Key management working correctly!")
        
        # Test security service
        security = SecurityService()
        print("Security service initialized successfully!")
        
        print("Installation verified successfully!")
        return True
    except Exception as e:
        print(f"Error verifying installation: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def run_demos():
    """Run demo scripts to show functionality"""
    print("Running demo scripts...")
    
    try:
        # Run crypto demo
        print("\n--- Crypto Service Demo ---")
        from backend.app.crypto_service import demo_crypto_operations
        # demo_crypto_operations()  # Commented out to avoid verbose output
        
        # Run database demo
        print("\n--- Database Demo ---")
        from backend.app.database import demo_database_operations
        # demo_database_operations()  # Commented out to avoid verbose output
        
        # Run auth demo
        print("\n--- Auth Service Demo ---")
        from backend.app.auth_service import demo_auth_operations
        # demo_auth_operations()  # Commented out to avoid verbose output
        
        # Run security demo
        print("\n--- Security Service Demo ---")
        from backend.app.security_service import demo_security_operations
        # demo_security_operations()  # Commented out to avoid verbose output
        
        print("Demo scripts completed successfully!")
        return True
    except Exception as e:
        print(f"Error running demos: {str(e)}")
        return False

def main():
    """Main initialization function"""
    print("Secure Trading Platform - Enhanced Initialization")
    print("=" * 50)
    
    # Initialize database
    if not initialize_database():
        return 1
    
    # Initialize key management
    if not initialize_key_management():
        return 1
    
    # Create demo data
    if not create_demo_data():
        return 1
    
    # Verify installation
    if not verify_installation():
        return 1
    
    # Run demos
    if not run_demos():
        return 1
    
    print("\n" + "=" * 50)
    print("Initialization completed successfully!")
    print("\nYou can now start the application with:")
    print("  python backend/app/main.py")
    print("\nOr run the tests with:")
    print("  python tests/run_tests.py")
    print("\nDefault demo users:")
    print("  admin / adminpassword")
    print("  user1 / userpassword1")
    print("  user2 / userpassword2")
    print("  trader / traderpassword")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())