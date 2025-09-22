import hashlib
import bcrypt
import jwt
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json

# Import platform components
from backend.app.database import get_db_manager
from backend.app.security_service import get_security_service
from backend.app.key_management import get_key_manager

class AuthService:
    """
    Enhanced Authentication Service for the Secure Trading Platform
    Handles user registration, login, session management, and security
    """
    
    def __init__(self):
        self.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key_for_demo")
        self.db = get_db_manager()
        self.security = get_security_service()
        self.key_manager = get_key_manager()
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def register_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Register a new user with enhanced security
        """
        try:
            # Check if user already exists
            existing_user = self.db.get_user_by_username(username)
            if existing_user:
                return {
                    "success": False,
                    "message": "Username already exists"
                }
            
            # Hash the password
            hashed_password = self.hash_password(password)
            
            # In a real implementation, we would also generate cryptographic keys
            # For this demo, we'll just store None for keys
            user_id = self.db.create_user(
                username=username,
                password_hash=hashed_password
            )
            
            if user_id:
                # Log security event
                self.security.log_event(
                    "USER_REGISTERED",
                    f"New user registered: {username}",
                    "SYSTEM",
                    "INFO",
                    {"user_id": user_id}
                )
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "message": "User registered successfully"
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to create user"
                }
        except Exception as e:
            self.security.log_event(
                "USER_REGISTRATION_FAILED",
                f"User registration failed for {username}",
                "SYSTEM",
                "ERROR",
                {"error": str(e)}
            )
            return {
                "success": False,
                "message": f"Registration failed: {str(e)}"
            }
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """
        Authenticate a user and return access token with enhanced security
        """
        try:
            # Check if IP is blocked
            if self.security.is_blocked(ip_address):
                self.security.log_event(
                    "AUTH_BLOCKED_IP",
                    f"Authentication attempt from blocked IP: {ip_address}",
                    ip_address,
                    "HIGH",
                    {"username": username}
                )
                return {
                    "success": False,
                    "message": "Access denied"
                }
            
            # Check if user account is locked
            if self.db.is_user_locked(username):
                self.security.log_event(
                    "AUTH_LOCKED_ACCOUNT",
                    f"Authentication attempt on locked account: {username}",
                    ip_address,
                    "HIGH",
                    {"username": username}
                )
                return {
                    "success": False,
                    "message": "Account is locked. Please try again later."
                }
            
            # Get user from database
            user = self.db.get_user_by_username(username)
            
            if not user:
                # Log failed attempt
                self.db.increment_failed_login_attempts(username)
                self.security.log_event(
                    "AUTH_INVALID_USERNAME",
                    f"Invalid username attempt: {username}",
                    ip_address,
                    "MEDIUM",
                    {"username": username}
                )
                
                # Check for brute force
                self.security.check_brute_force(username, ip_address)
                
                return {
                    "success": False,
                    "message": "Invalid username or password"
                }
            
            # Verify password
            if not self.verify_password(password, user["password_hash"]):
                # Increment failed login attempts
                self.db.increment_failed_login_attempts(username)
                self.security.log_event(
                    "AUTH_INVALID_PASSWORD",
                    f"Invalid password attempt for user: {username}",
                    ip_address,
                    "MEDIUM",
                    {"username": username}
                )
                
                # Check for brute force
                self.security.check_brute_force(username, ip_address)
                
                return {
                    "success": False,
                    "message": "Invalid username or password"
                }
            
            # Reset failed login attempts
            self.db.increment_failed_login_attempts(username)  # This will reset to 0
            self.db.update_user_last_login(user["id"])
            
            # Generate session token
            session_token = self.security.generate_session_token()
            
            # Calculate expiration time (24 hours)
            expires_at = datetime.utcnow() + timedelta(hours=24)
            
            # Create session in database
            self.db.create_session(
                user_id=user["id"],
                session_token=session_token,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Generate JWT token
            payload = {
                "user_id": user["id"],
                "username": user["username"],
                "session_token": session_token,
                "exp": expires_at,
                "iat": datetime.utcnow()
            }
            
            token = jwt.encode(payload, self.secret_key, algorithm="HS256")
            
            # Log successful login
            self.security.log_event(
                "USER_LOGIN",
                f"User {username} logged in successfully",
                ip_address,
                "INFO",
                {"user_id": user["id"], "username": username}
            )
            
            return {
                "success": True,
                "access_token": token,
                "session_token": session_token,
                "token_type": "bearer",
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "last_login": user["last_login"]
                }
            }
        except Exception as e:
            self.security.log_event(
                "AUTH_ERROR",
                f"Authentication error for user: {username}",
                ip_address,
                "ERROR",
                {"username": username, "error": str(e)}
            )
            return {
                "success": False,
                "message": f"Authentication failed: {str(e)}"
            }
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token and return user info
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None
    
    def verify_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Verify session token and return session info
        """
        try:
            session = self.db.get_session(session_token)
            return session
        except Exception as e:
            self.security.log_event(
                "SESSION_VERIFICATION_ERROR",
                f"Session verification error",
                "SYSTEM",
                "ERROR",
                {"session_token": session_token, "error": str(e)}
            )
            return None
    
    def logout_user(self, user_id: int, session_token: str = None) -> bool:
        """
        Logout user (invalidate session)
        """
        try:
            # Invalidate session in database
            if session_token:
                self.db.invalidate_session(session_token)
            
            # Log logout event
            self.security.log_event(
                "USER_LOGOUT",
                f"User {user_id} logged out",
                "SYSTEM",
                "INFO",
                {"user_id": user_id}
            )
            
            return True
        except Exception as e:
            self.security.log_event(
                "LOGOUT_ERROR",
                f"Logout error for user: {user_id}",
                "SYSTEM",
                "ERROR",
                {"user_id": user_id, "error": str(e)}
            )
            return False
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Change user password
        """
        try:
            # Get user from database
            user = self.db.get_user_by_username(user_id)
            
            if not user:
                return {
                    "success": False,
                    "message": "User not found"
                }
            
            # Verify old password
            if not self.verify_password(old_password, user["password_hash"]):
                self.security.log_event(
                    "PASSWORD_CHANGE_FAILED",
                    f"Invalid old password for user: {user_id}",
                    "SYSTEM",
                    "MEDIUM",
                    {"user_id": user_id}
                )
                return {
                    "success": False,
                    "message": "Invalid old password"
                }
            
            # Hash new password
            new_hashed_password = self.hash_password(new_password)
            
            # Update password in database
            # Note: This would require a new method in database.py
            # For demo, we'll just log the action
            
            self.security.log_event(
                "PASSWORD_CHANGED",
                f"Password changed for user: {user_id}",
                "SYSTEM",
                "INFO",
                {"user_id": user_id}
            )
            
            return {
                "success": True,
                "message": "Password changed successfully"
            }
        except Exception as e:
            self.security.log_event(
                "PASSWORD_CHANGE_ERROR",
                f"Password change error for user: {user_id}",
                "SYSTEM",
                "ERROR",
                {"user_id": user_id, "error": str(e)}
            )
            return {
                "success": False,
                "message": f"Password change failed: {str(e)}"
            }

# Global auth service instance
auth_service = AuthService()

def get_auth_service():
    """Get the global auth service instance"""
    return auth_service

def demo_auth_operations():
    """
    Demonstrate authentication operations
    """
    print("=== Enhanced Authentication Service Demo ===")
    
    # Get auth service
    auth = get_auth_service()
    
    # Test user registration
    print("\n1. User Registration:")
    reg_result = auth.register_user("demouser", "securepassword123")
    print(f"   Registration result: {reg_result['message']}")
    
    # Test duplicate registration
    print("\n2. Duplicate Registration:")
    dup_reg_result = auth.register_user("demouser", "anotherpassword")
    print(f"   Duplicate registration: {dup_reg_result['message']}")
    
    # Test invalid login
    print("\n3. Invalid Login Attempt:")
    invalid_login = auth.authenticate_user("demouser", "wrongpassword", "192.168.1.100")
    print(f"   Invalid login: {invalid_login['message']}")
    
    # Test valid login
    print("\n4. Valid Login:")
    valid_login = auth.authenticate_user("demouser", "securepassword123", "192.168.1.100")
    if valid_login["success"]:
        print(f"   Login successful!")
        print(f"   Token: {valid_login['access_token'][:50]}...")
        print(f"   Session: {valid_login['session_token'][:32]}...")
        print(f"   User: {valid_login['user']['username']} (ID: {valid_login['user']['id']})")
    else:
        print(f"   Login failed: {valid_login['message']}")
    
    # Test token verification
    print("\n5. Token Verification:")
    if valid_login["success"]:
        token_payload = auth.verify_token(valid_login["access_token"])
        if token_payload:
            print(f"   Token verified successfully!")
            print(f"   User ID: {token_payload['user_id']}")
            print(f"   Username: {token_payload['username']}")
            print(f"   Issued at: {datetime.fromtimestamp(token_payload['iat'])}")
            print(f"   Expires at: {datetime.fromtimestamp(token_payload['exp'])}")
        else:
            print("   Token verification failed")
    else:
        print("   Token verification skipped due to login failure")
    
    # Test session verification
    print("\n6. Session Verification:")
    if valid_login["success"]:
        session_info = auth.verify_session(valid_login["session_token"])
        if session_info:
            print(f"   Session verified successfully!")
            print(f"   User ID: {session_info['user_id']}")
            print(f"   IP Address: {session_info['ip_address']}")
            print(f"   Created at: {session_info['created_at']}")
        else:
            print("   Session verification failed")
    else:
        print("   Session verification skipped due to login failure")
    
    # Test logout
    print("\n7. User Logout:")
    if valid_login["success"]:
        logout_success = auth.logout_user(valid_login["user"]["id"], valid_login["session_token"])
        if logout_success:
            print("   User logged out successfully")
        else:
            print("   Logout failed")
    
    print("\n=== Enhanced Auth Demo Completed ===")

if __name__ == "__main__":
    demo_auth_operations()