"""
Authentication Service for the Secure Trading Platform
"""
import bcrypt
import jwt
import time
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service
import sqlite3


class AuthService:
    """
    Authentication Service for the Secure Trading Platform
    Handles user registration, login, and session management with security features
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
        self.secret_key = "development-secret-key-12345"  # In production, use environment variable
        self.max_login_attempts = 5
        self.lockout_duration_hours = 24
        self.token_expiry = 24  # Token expiry in hours
        
    def create_access_token(self, user_id: int, username: str) -> str:
        """Create a JWT token for the user"""
        expires = datetime.now() + timedelta(hours=self.token_expiry)
        to_encode = {
            "sub": str(user_id),
            "username": username,
            "exp": expires
        }
        return jwt.encode(to_encode, self.secret_key, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a JWT token and return the user data"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            user_id = int(payload.get("sub"))
            user = self.db.get_user_by_id(user_id)
            if not user:
                return None
            return {
                "id": user_id,
                "username": payload.get("username"),
                "role": user.get("role", "trader")
            }
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None
        except Exception:
            return None

    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def register_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Register a new user with secure password hashing
        """
        try:
            # Check if user already exists
            existing_user = self.db.get_user_by_username(username)
            if existing_user:
                return {
                    "success": False,
                    "message": "Username already exists"
                }
            
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user in database
            user_id = self.db.create_user(username, hashed_password)
            if user_id:
                # Log security event
                self.db.log_security_event(
                    "USER_REGISTERED",
                    f"New user registered: {username}",
                    severity="INFO"
                )
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "message": "User registered successfully"
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to register user"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Registration failed: {str(e)}"
            }
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None, 
                         user_agent: str = None) -> Dict[str, Any]:
        """
        Authenticate user and create session
        """
        try:
            # Check if user account is locked
            if self.db.is_user_locked(username):
                self.db.log_security_event(
                    "LOGIN_ATTEMPT_BLOCKED",
                    f"Login attempt blocked for locked user: {username}",
                    ip_address,
                    "MEDIUM",
                    {"username": username}
                )
                return {
                    "success": False,
                    "message": "Account is locked due to multiple failed attempts"
                }
            
            # Get user from database
            user = self.db.get_user_by_username(username)
            if not user:
                # Log the failed attempt
                self.db.log_security_event(
                    "FAILED_LOGIN",
                    f"Failed login attempt: user {username} does not exist",
                    ip_address,
                    "MEDIUM",
                    {"username": username}
                )
                return {
                    "success": False,
                    "message": "Invalid credentials"
                }
            
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                # Update last login time
                self.db.update_user_last_login(user["id"])
                
                # Reset failed login attempts
                self.db.reset_failed_login_attempts(username)
                
                # Log successful login
                self.db.log_security_event(
                    "USER_LOGIN",
                    f"Successful login for user: {username}",
                    ip_address,
                    "INFO",
                    {"user_id": user["id"]}
                )
                
                # Create JWT access token
                access_token = self.create_access_token(user["id"], username)
                
                # Store session info in database for tracking
                expires_at = datetime.now() + timedelta(hours=self.token_expiry)
                self.db.create_session(
                    user_id=user["id"],
                    session_token=access_token,
                    expires_at=expires_at,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return {
                    "success": True,
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "user_id": user["id"],
                    "username": user["username"],
                    "role": user.get("role", "trader"),
                    "balance": user.get("balance", 10000.00),
                    "message": "Login successful"
                }
            else:
                # Increment failed login attempts
                self.db.increment_failed_login_attempts(username)
                
                # Log failed login attempt
                self.db.log_security_event(
                    "FAILED_LOGIN",
                    f"Failed login attempt for user: {username}",
                    ip_address,
                    "MEDIUM",
                    {"username": username}
                )
                
                # Check if account should be locked
                current_user = self.db.get_user_by_username(username)
                if current_user and current_user["failed_login_attempts"] >= self.max_login_attempts:
                    self.db.lock_user_account(username, self.lockout_duration_hours)
                    
                    self.db.log_security_event(
                        "ACCOUNT_LOCKED",
                        f"Account locked due to multiple failed attempts: {username}",
                        ip_address,
                        "HIGH",
                        {"username": username}
                    )
                
                return {
                    "success": False,
                    "message": "Invalid credentials"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Authentication failed: {str(e)}"
            }
    
    def logout_user(self, user_id: int, session_token: str) -> bool:
        """
        Logout user and invalidate session
        """
        try:
            # Invalidate the session in database
            success = self.db.invalidate_session(session_token)
            
            if success:
                self.db.log_security_event(
                    "USER_LOGOUT",
                    f"User logged out: {user_id}",
                    severity="INFO",
                    user_id=user_id
                )
            
            return success
        except Exception:
            return False
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Change user password after verifying old password
        """
        try:
            # Get user from database using user_id
            user = self.db.get_user_by_id(user_id)
            if not user:
                return {
                    "success": False,
                    "message": "User not found"
                }
            
            # Verify old password
            if not bcrypt.checkpw(old_password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                return {
                    "success": False,
                    "message": "Current password is incorrect"
                }
            
            # Hash new password
            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Update password in database
            # We need to add this method to the database utility
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            """, (new_hashed_password, user_id))
            
            conn.commit()
            conn.close()
            
            # Log the password change
            self.db.log_security_event(
                "PASSWORD_CHANGED",
                f"Password changed for user: {user['username']}",
                severity="INFO",
                user_id=user_id
            )
            
            return {
                "success": True,
                "message": "Password changed successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Password change failed: {str(e)}"
            }


# Global auth service instance
auth_service = AuthService()


def get_auth_service():
    """
    Get the global auth service instance
    """
    return auth_service


def demo_auth_operations():
    """
    Demonstrate authentication operations
    """
    print("=== Authentication Service Demo ===")
    
    # Get auth service
    auth = get_auth_service()
    
    print("\n1. User Registration:")
    
    # Try to register a new user
    result = auth.register_user("demo_user", "secure_password_123")
    print(f"   Registration result: {result['message']}")
    print(f"   Success: {result['success']}")
    
    # Try to register the same user again
    result = auth.register_user("demo_user", "another_password")
    print(f"   Duplicate registration: {result['message']}")
    
    print("\n2. User Authentication:")
    
    # Try to login with correct credentials
    result = auth.authenticate_user("demo_user", "secure_password_123", "192.168.1.100")
    print(f"   Login with correct password: {result['message']}")
    if result['success']:
        print(f"   Token: {result['token'][:20]}...")
    
    # Try to login with incorrect credentials
    result = auth.authenticate_user("demo_user", "wrong_password", "192.168.1.100")
    print(f"   Login with wrong password: {result['message']}")
    
    print("\n3. Simulating Failed Login Attempts:")
    
    # Simulate multiple failed login attempts to trigger account lock
    for i in range(5):
        result = auth.authenticate_user("demo_user", "wrong_password", "192.168.1.100")
        print(f"   Failed attempt #{i+1}: {result['message']}")
    
    # Try to login after account should be locked
    result = auth.authenticate_user("demo_user", "secure_password_123", "192.168.1.100")
    print(f"   Login after lock: {result['message']}")
    
    print("\n=== Auth Demo Completed ===")


if __name__ == "__main__":
    demo_auth_operations()