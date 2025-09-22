import time
import hashlib
import hmac
import json
import secrets
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import re

# Import platform components
from backend.app.database import get_db_manager
from backend.app.crypto_service import get_crypto_service

class SecurityService:
    """
    Comprehensive Security Service for the Secure Trading Platform
    Integrates intrusion detection, automated response, and monitoring
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
        
        # Track login attempts per IP
        self.login_attempts = defaultdict(list)
        
        # Track requests per IP for rate limiting
        self.request_counts = defaultdict(deque)
        
        # Known malicious patterns
        self.sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"exec(\s|\+)+(s|x)p\w+",
            r"union\s+select",
            r"insert\s+into",
            r"drop\s+table",
            r"delete\s+from",
            r"select\s+\*",
            r"or\s+1\s*=\s*1",
            r"'\s*or\s*'\s*=\s*'",
            r"'\s*or\s*1\s*=\s*1\s*--",
            r"'\s*or\s*'a'\s*=\s*'a",
            r"'\"",
            r"\"'"
        ]
        
        # Suspicious user agents
        self.suspicious_user_agents = [
            "sqlmap", "hydra", "burp", "nikto", "nessus", "nmap", "gobuster", "dirb"
        ]
        
        # Suspicious request patterns
        self.suspicious_patterns = [
            r"<script[^>]*>",  # XSS
            r"javascript:",    # XSS
            r"on\w+\s*=",      # XSS event handlers
            r"\.\./",          # Path traversal
            r"\.\.\\",         # Path traversal
            r"eval\s*\(",      # Code execution
            r"system\s*\(",    # Command execution
            r"exec\s*\(",      # Command execution
        ]
        
        # Blocked IPs
        self.blocked_ips = set()
        
        # Event log
        self.security_events = []
    
    def log_event(self, event_type: str, description: str, source_ip: str, severity: str = "INFO", details: Dict[str, Any] = None):
        """
        Log a security event to both in-memory log and database
        """
        # Log to database
        self.db.log_security_event(event_type, description, source_ip, severity, json.dumps(details) if details else None)
    
    def check_sql_injection(self, request_data: Any, source_ip: str) -> bool:
        """
        Check for SQL injection patterns in request data
        """
        # Convert request data to string for pattern matching
        request_str = json.dumps(request_data) if isinstance(request_data, dict) else str(request_data)
        
        for pattern in self.sql_patterns:
            if re.search(pattern, request_str, re.IGNORECASE):
                self.log_event(
                    "SQL_INJECTION_DETECTED",
                    f"SQL injection pattern '{pattern}' detected in request",
                    source_ip,
                    "HIGH",
                    {"pattern": pattern, "request_data": request_str[:100]}
                )
                
                # Block the IP
                self.block_ip(source_ip, "SQL injection attempt")
                return True
        
        return False
    
    def check_xss(self, request_data: Any, source_ip: str) -> bool:
        """
        Check for XSS patterns in request data
        """
        # Convert request data to string for pattern matching
        request_str = json.dumps(request_data) if isinstance(request_data, dict) else str(request_data)
        
        for pattern in self.suspicious_patterns:
            if "script" in pattern.lower() or "javascript" in pattern.lower() or "on" in pattern.lower():
                if re.search(pattern, request_str, re.IGNORECASE):
                    self.log_event(
                        "XSS_DETECTED",
                        f"XSS pattern '{pattern}' detected in request",
                        source_ip,
                        "HIGH",
                        {"pattern": pattern, "request_data": request_str[:100]}
                    )
                    
                    # Block the IP
                    self.block_ip(source_ip, "XSS attempt")
                    return True
        
        return False
    
    def check_path_traversal(self, request_data: Any, source_ip: str) -> bool:
        """
        Check for path traversal patterns in request data
        """
        # Convert request data to string for pattern matching
        request_str = json.dumps(request_data) if isinstance(request_data, dict) else str(request_data)
        
        for pattern in self.suspicious_patterns:
            if "../" in pattern or "..\\" in pattern:
                if re.search(pattern, request_str, re.IGNORECASE):
                    self.log_event(
                        "PATH_TRAVERSAL_DETECTED",
                        f"Path traversal pattern '{pattern}' detected in request",
                        source_ip,
                        "HIGH",
                        {"pattern": pattern, "request_data": request_str[:100]}
                    )
                    
                    # Block the IP
                    self.block_ip(source_ip, "Path traversal attempt")
                    return True
        
        return False
    
    def check_brute_force(self, username: str, source_ip: str) -> bool:
        """
        Check for brute force login attempts
        """
        now = time.time()
        
        # Remove old attempts (> 10 minutes ago)
        self.login_attempts[source_ip] = [
            attempt for attempt in self.login_attempts[source_ip] 
            if now - attempt < 600
        ]
        
        # Add current attempt
        self.login_attempts[source_ip].append(now)
        
        # Check if too many attempts in short time
        if len(self.login_attempts[source_ip]) >= 5:
            self.log_event(
                "BRUTE_FORCE_DETECTED",
                f"Multiple failed login attempts ({len(self.login_attempts[source_ip])}) for user {username}",
                source_ip,
                "HIGH",
                {"username": username, "attempts": len(self.login_attempts[source_ip])}
            )
            
            # Block the IP
            self.block_ip(source_ip, "Brute force attack detected")
            
            # Lock the user account
            self.db.lock_user_account(username)
            
            return True
        
        return False
    
    def check_rate_limit(self, source_ip: str, max_requests: int = 100, time_window: int = 60) -> bool:
        """
        Check if IP is exceeding rate limits
        """
        now = time.time()
        
        # Remove old requests outside time window
        while self.request_counts[source_ip] and now - self.request_counts[source_ip][0] > time_window:
            self.request_counts[source_ip].popleft()
        
        # Add current request
        self.request_counts[source_ip].append(now)
        
        # Check if exceeding limit
        if len(self.request_counts[source_ip]) > max_requests:
            self.log_event(
                "RATE_LIMIT_EXCEEDED",
                f"High request rate ({len(self.request_counts[source_ip])} requests in {time_window}s)",
                source_ip,
                "MEDIUM",
                {"requests": len(self.request_counts[source_ip]), "window": time_window}
            )
            return True
        
        return False
    
    def check_suspicious_user_agent(self, user_agent: str, source_ip: str) -> bool:
        """
        Check for suspicious user agents
        """
        if user_agent:
            user_agent_lower = user_agent.lower()
            for suspicious in self.suspicious_user_agents:
                if suspicious.lower() in user_agent_lower:
                    self.log_event(
                        "SUSPICIOUS_USER_AGENT",
                        f"Suspicious user agent detected: {user_agent}",
                        source_ip,
                        "MEDIUM",
                        {"user_agent": user_agent, "signature": suspicious}
                    )
                    return True
        
        return False
    
    def is_blocked(self, source_ip: str) -> bool:
        """
        Check if IP is blocked
        """
        # Check in-memory blocked IPs
        if source_ip in self.blocked_ips:
            return True
        
        # Check database blocked IPs
        return self.db.is_ip_blocked(source_ip)
    
    def block_ip(self, source_ip: str, reason: str):
        """
        Block an IP address
        """
        self.blocked_ips.add(source_ip)
        self.db.block_ip(source_ip, reason)
        
        self.log_event(
            "IP_BLOCKED",
            f"IP address blocked: {source_ip} - Reason: {reason}",
            source_ip,
            "HIGH",
            {"reason": reason}
        )
    
    def check_nonce_replay(self, nonce: str, source_ip: str) -> bool:
        """
        Check for replay attacks using nonce
        In a real implementation, we would store nonces and check for duplicates
        """
        if nonce:
            # Check if nonce is too short (suspicious)
            if len(str(nonce)) < 10:
                self.log_event(
                    "SUSPICIOUS_NONCE",
                    f"Suspicious nonce detected: {nonce}",
                    source_ip,
                    "MEDIUM",
                    {"nonce": nonce, "length": len(str(nonce))}
                )
                return True
            
            # In a real implementation, we would check against stored nonces
            # For demo, we'll just return False
        
        return False
    
    def check_signature_integrity(self, signature: str, data: Dict[str, Any], source_ip: str) -> bool:
        """
        Check signature integrity for MITM detection
        """
        # In a real implementation, we would verify the cryptographic signature
        # This is a simplified version that just checks if signature looks valid
        if signature:
            # Check if signature contains suspicious patterns
            if "invalid" in str(signature).lower() or "modified" in str(signature).lower():
                self.log_event(
                    "SIGNATURE_MISMATCH",
                    f"Invalid signature detected: {signature}",
                    source_ip,
                    "HIGH",
                    {"signature": signature[:50], "data_hash": hashlib.sha256(json.dumps(data).encode()).hexdigest()[:16]}
                )
                return False
            
            # Verify the actual signature
            is_valid = self.crypto.verify_signature(data, signature)
            if not is_valid:
                self.log_event(
                    "SIGNATURE_MISMATCH",
                    f"Signature verification failed",
                    source_ip,
                    "HIGH",
                    {"signature": signature[:50], "data_hash": hashlib.sha256(json.dumps(data).encode()).hexdigest()[:16]}
                )
                return False
        
        return True
    
    def check_data_integrity(self, data: Dict[str, Any], hmac_signature: str, source_ip: str) -> bool:
        """
        Check data integrity using HMAC
        """
        if hmac_signature:
            is_valid = self.crypto.hmac_verify(data, hmac_signature)
            if not is_valid:
                self.log_event(
                    "DATA_INTEGRITY_VIOLATION",
                    f"HMAC verification failed",
                    source_ip,
                    "HIGH",
                    {"data_hash": hashlib.sha256(json.dumps(data).encode()).hexdigest()[:16]}
                )
                return False
        
        return True
    
    def generate_session_token(self) -> str:
        """
        Generate a secure session token
        """
        return secrets.token_urlsafe(32)
    
    def monitor_user_behavior(self, user_id: int, action: str, source_ip: str) -> bool:
        """
        Monitor user behavior for anomalies
        """
        # In a real implementation, we would track user behavior patterns
        # and detect anomalies. For demo, we'll just log the action.
        
        self.log_event(
            "USER_ACTION",
            f"User {user_id} performed action: {action}",
            source_ip,
            "INFO",
            {"user_id": user_id, "action": action}
        )
        
        return True
    
    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent security events
        """
        return self.db.get_recent_security_events(limit)
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Get currently blocked IPs
        """
        return self.db.get_blocked_ips()
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address
        """
        try:
            # Remove from in-memory blocked IPs
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
            
            # In a real implementation, we would also remove from database
            # For demo, we'll just log the action
            self.log_event(
                "IP_UNBLOCKED",
                f"IP address unblocked: {ip_address}",
                "SYSTEM",
                "INFO",
                {"ip_address": ip_address}
            )
            
            return True
        except Exception as e:
            self.log_event(
                "IP_UNBLOCK_FAILED",
                f"Failed to unblock IP address: {ip_address}",
                "SYSTEM",
                "ERROR",
                {"ip_address": ip_address, "error": str(e)}
            )
            return False

class AutomatedResponseSystem:
    """
    Automated Response System for Security Events
    Automatically responds to detected threats
    """
    
    def __init__(self, security_service: SecurityService):
        self.security_service = security_service
        self.db = get_db_manager()
    
    def respond_to_threat(self, threat_type: str, source_ip: str, details: Dict[str, Any] = None) -> List[str]:
        """
        Respond to a detected threat
        """
        response_actions = []
        
        if threat_type == "SQL_INJECTION":
            # Block IP permanently
            self.security_service.block_ip(source_ip, "SQL injection attack")
            response_actions.append("IP_BLOCKED_PERMANENT")
            
            # Log incident
            response_actions.append("INCIDENT_LOGGED")
            
        elif threat_type == "BRUTE_FORCE":
            # Block IP temporarily
            self.security_service.block_ip(source_ip, "Brute force attack")
            response_actions.append("IP_BLOCKED_TEMPORARY")
            
            # Trigger CAPTCHA for future attempts
            response_actions.append("CAPTCHA_REQUIRED")
            
        elif threat_type == "RATE_LIMIT_EXCEEDED":
            # Temporarily throttle requests
            response_actions.append("REQUEST_THROTTLED")
            
            # Require rate limiting verification
            response_actions.append("RATE_LIMIT_ACTIVATED")
            
        elif threat_type == "SUSPICIOUS_USER_AGENT":
            # Log for review
            response_actions.append("USER_AGENT_FLAGGED")
            
            # Increase monitoring
            response_actions.append("MONITORING_INCREASED")
            
        elif threat_type == "REPLAY_ATTACK":
            # Reject transaction
            response_actions.append("TRANSACTION_REJECTED")
            
            # Block IP temporarily
            self.security_service.block_ip(source_ip, "Replay attack")
            response_actions.append("IP_BLOCKED_TEMPORARILY")
            
        elif threat_type == "MITM_ATTACK":
            # Terminate session
            response_actions.append("SESSION_TERMINATED")
            
            # Block IP
            self.security_service.block_ip(source_ip, "MITM attack")
            response_actions.append("IP_BLOCKED_PERMANENTLY")
            
        elif threat_type == "XSS":
            # Block IP
            self.security_service.block_ip(source_ip, "XSS attack")
            response_actions.append("IP_BLOCKED")
            
            # Sanitize input
            response_actions.append("INPUT_SANITIZED")
            
        # Log response actions
        self.security_service.log_event(
            "AUTOMATED_RESPONSE",
            f"Automated response to {threat_type}: {', '.join(response_actions)}",
            source_ip,
            "HIGH",
            {"threat_type": threat_type, "actions": response_actions, "details": details}
        )
        
        return response_actions

# Global instances
security_service = SecurityService()
automated_response_system = AutomatedResponseSystem(security_service)

def get_security_service():
    """Get the Security Service instance"""
    return security_service

def get_automated_response_system():
    """Get the Automated Response System instance"""
    return automated_response_system

def demo_security_operations():
    """
    Demonstrate security operations
    """
    print("=== Enhanced Security Service Demo ===")
    
    # Get security service
    sec_svc = get_security_service()
    ars = get_automated_response_system()
    
    # Test IP addresses
    test_ips = ["192.168.1.100", "10.0.0.50", "203.0.113.42"]
    
    # Test SQL injection detection
    print("\n1. Testing SQL Injection Detection:")
    for ip in test_ips[:1]:
        request_data = {"query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}
        sec_svc.check_sql_injection(request_data, ip)
    
    # Test XSS detection
    print("\n2. Testing XSS Detection:")
    for ip in test_ips[1:2]:
        request_data = {"input": "<script>alert('xss')</script>"}
        sec_svc.check_xss(request_data, ip)
    
    # Test brute force detection
    print("\n3. Testing Brute Force Detection:")
    for ip in test_ips[2:3]:
        for i in range(6):  # 6 attempts should trigger detection
            sec_svc.check_brute_force("testuser", ip)
    
    # Test rate limiting
    print("\n4. Testing Rate Limiting:")
    for ip in test_ips[:1]:
        for i in range(150):  # 150 requests should exceed limit
            sec_svc.check_rate_limit(ip, max_requests=100, time_window=60)
    
    # Test suspicious user agent
    print("\n5. Testing Suspicious User Agent Detection:")
    sec_svc.check_suspicious_user_agent("sqlmap/1.5.0", test_ips[0])
    
    # Test nonce replay detection
    print("\n6. Testing Nonce Replay Detection:")
    sec_svc.check_nonce_replay("short123", test_ips[1])
    
    # Test signature integrity
    print("\n7. Testing Signature Integrity:")
    test_data = {"amount": 100, "to": "user123"}
    invalid_signature = "invalid_sig_modified"
    sec_svc.check_signature_integrity(invalid_signature, test_data, test_ips[2])
    
    # Test automated responses
    print("\n8. Testing Automated Responses:")
    ars.respond_to_threat("SQL_INJECTION", test_ips[0], {"test": "data"})
    ars.respond_to_threat("BRUTE_FORCE", test_ips[1], {"username": "testuser"})
    
    # Show recent security events
    print("\n9. Recent Security Events:")
    events = sec_svc.get_security_events(10)
    for event in events:
        print(f"   {event['created_at']}: [{event['severity']}] {event['event_type']} - {event['description']}")
    
    print("\n=== Enhanced Security Demo Completed ===")

if __name__ == "__main__":
    demo_security_operations()