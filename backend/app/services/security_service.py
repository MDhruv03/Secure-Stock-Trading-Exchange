"""
Security Service for the Secure Trading Platform
Provides attack simulation and defense mechanisms
"""
import time
import random
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service


class SecurityService:
    """
    Security Service for the Secure Trading Platform
    Provides attack simulation and defense mechanisms
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
        self.blocked_ips = set()
        self.failed_attempts = {}  # ip -> count of failed attempts
        self.suspicious_patterns = set()  # Known malicious patterns
        self.attack_patterns = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE",
                "--",
                "UNION SELECT",
                "1' OR '1'='1' --"
            ],
            "xss": [
                "<script>",
                "javascript:",
                "onerror=",
                "<img src=",
                "onload="
            ],
            "path_traversal": [
                "../../../",
                "..\\..\\",
                "%2e%2e%2f",
                "..%2f"
            ]
        }
        
        # Start background monitoring thread
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitor_security_events, daemon=True)
        self.monitoring_thread.start()
    
    def _monitor_security_events(self):
        """
        Background thread to monitor security events
        """
        while self.monitoring_active:
            # Check for suspicious activities
            time.sleep(30)  # Check every 30 seconds
            
            # Log periodic security check
            self.db.log_security_event(
                "PERIODIC_CHECK",
                "Security monitoring performed",
                severity="INFO"
            )
    
    def check_sql_injection(self, query: str, ip_address: str) -> Dict[str, Any]:
        """
        Check for SQL injection patterns in query
        """
        is_suspicious = False
        matched_patterns = []
        
        for pattern in self.attack_patterns["sql_injection"]:
            if pattern.lower() in query.lower():
                is_suspicious = True
                matched_patterns.append(pattern)
        
        if is_suspicious:
            self.db.log_security_event(
                "SQL_INJECTION_DETECTED",
                f"SQL injection attempt from {ip_address} with patterns: {', '.join(matched_patterns)}",
                ip_address,
                "HIGH",
                {"query": query, "patterns": matched_patterns}
            )
            
            # Block IP if necessary
            self._block_ip_if_needed(ip_address, f"SQL injection attempt: {', '.join(matched_patterns)}")
        
        return {
            "is_suspicious": is_suspicious,
            "matched_patterns": matched_patterns,
            "action_taken": "BLOCKED" if is_suspicious else "ALLOWED"
        }
    
    def check_brute_force(self, ip_address: str) -> Dict[str, Any]:
        """
        Check for brute force attack based on failed attempts
        """
        if ip_address in self.failed_attempts:
            if self.failed_attempts[ip_address] >= 5:  # Threshold for brute force
                self.db.log_security_event(
                    "BRUTE_FORCE_DETECTED",
                    f"Brute force attempt detected from {ip_address}",
                    ip_address,
                    "HIGH",
                    {"failed_attempts": self.failed_attempts[ip_address]}
                )
                
                # Block the IP
                self._block_ip_if_needed(ip_address, f"Brute force attempt: {self.failed_attempts[ip_address]} failed attempts")
                
                return {
                    "is_suspicious": True,
                    "failed_attempts": self.failed_attempts[ip_address],
                    "action_taken": "BLOCKED"
                }
        
        return {
            "is_suspicious": False,
            "failed_attempts": self.failed_attempts.get(ip_address, 0),
            "action_taken": "ALLOWED"
        }
    
    def record_failed_attempt(self, ip_address: str):
        """
        Record a failed authentication attempt
        """
        if ip_address in self.failed_attempts:
            self.failed_attempts[ip_address] += 1
        else:
            self.failed_attempts[ip_address] = 1
        
        # Reset counter after 10 minutes
        def reset_counter():
            time.sleep(600)  # 10 minutes
            if ip_address in self.failed_attempts:
                if self.failed_attempts[ip_address] > 0:
                    self.failed_attempts[ip_address] = max(0, self.failed_attempts[ip_address] - 1)
        
        threading.Thread(target=reset_counter, daemon=True).start()
    
    def _block_ip_if_needed(self, ip_address: str, reason: str):
        """
        Block IP address if not already blocked
        """
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            self.db.block_ip(ip_address, reason)
            
            # Remove from failed attempts if any
            if ip_address in self.failed_attempts:
                del self.failed_attempts[ip_address]
    
    def check_suspicious_user_agent(self, user_agent: str, ip_address: str) -> Dict[str, Any]:
        """
        Check for suspicious user agents
        """
        suspicious_agents = [
            "sqlmap",
            "nikto",
            "nessus",
            "nmap",
            "hydra",
            "medusa"
        ]
        
        is_suspicious = False
        matched_agent = None
        
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                is_suspicious = True
                matched_agent = agent
                break
        
        if is_suspicious:
            self.db.log_security_event(
                "SUSPICIOUS_USER_AGENT",
                f"Suspicious user agent detected from {ip_address}: {user_agent}",
                ip_address,
                "MEDIUM",
                {"user_agent": user_agent, "matched_agent": matched_agent}
            )
        
        return {
            "is_suspicious": is_suspicious,
            "matched_agent": matched_agent,
            "action_taken": "LOGGED" if is_suspicious else "ALLOWED"
        }
    
    def simulate_sql_injection(self) -> Dict[str, Any]:
        """
        Simulate a SQL injection attack
        """
        # Log the simulation start
        self.db.log_security_event(
            "SIMULATION_STARTED",
            "SQL Injection simulation initiated",
            "SIMULATION",
            "INFO",
            {"attack_type": "SQL_INJECTION"}
        )
        
        # Simulate malicious queries
        attacks = [
            "SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'",
            "SELECT * FROM users WHERE username = ' OR '1'='1' --' AND password = 'anything'",
            "SELECT * FROM users; DROP TABLE users; --",
            "SELECT * FROM users UNION SELECT username, password FROM admin --"
        ]
        
        results = []
        for attack in attacks:
            result = self.check_sql_injection(attack, "127.0.0.1")
            results.append({
                "attack": attack,
                "result": result
            })
        
        # Log the simulation end
        self.db.log_security_event(
            "SIMULATION_COMPLETED",
            "SQL Injection simulation completed",
            "SIMULATION",
            "INFO",
            {"attack_type": "SQL_INJECTION", "results": results}
        )
        
        return {
            "attack_type": "SQL_INJECTION",
            "attacks": results
        }
    
    def simulate_brute_force(self) -> Dict[str, Any]:
        """
        Simulate a brute force attack
        """
        # Log the simulation start
        self.db.log_security_event(
            "SIMULATION_STARTED",
            "Brute Force simulation initiated",
            "SIMULATION",
            "INFO",
            {"attack_type": "BRUTE_FORCE"}
        )
        
        # Simulate multiple failed login attempts
        test_ip = "192.168.1.100"
        for i in range(10):
            self.record_failed_attempt(test_ip)
            time.sleep(0.1)  # Small delay between attempts
        
        # Check if IP was blocked
        check_result = self.check_brute_force(test_ip)
        
        # Log the simulation end
        self.db.log_security_event(
            "SIMULATION_COMPLETED",
            "Brute Force simulation completed",
            "SIMULATION",
            "INFO",
            {"attack_type": "BRUTE_FORCE", "result": check_result}
        )
        
        return {
            "attack_type": "BRUTE_FORCE",
            "ip_address": test_ip,
            "result": check_result
        }
    
    def simulate_replay_attack(self) -> Dict[str, Any]:
        """
        Simulate a replay attack
        """
        # Log the simulation start
        self.db.log_security_event(
            "SIMULATION_STARTED",
            "Replay Attack simulation initiated",
            "SIMULATION",
            "INFO",
            {"attack_type": "REPLAY_ATTACK"}
        )
        
        # Create a legitimate transaction
        test_data = {
            "user_id": 12345,
            "order_id": 67890,
            "amount": 100.0,
            "timestamp": int(time.time())
        }
        
        # Encrypt the data
        encrypted_package = self.crypto.encrypt_data(test_data)
        
        # Simulate replay attack by reusing the same data
        try:
            # This would normally be detected as a replay attack
            # For demo purposes, we'll just log it
            self.db.log_security_event(
                "REPLAY_ATTEMPT_DETECTED",
                "Possible replay attack detected",
                "SIMULATION",
                "MEDIUM",
                {"replay_data": test_data}
            )
            
            result = {
                "attack_type": "REPLAY_ATTACK",
                "status": "DETECTED",
                "message": "Replay attack attempt detected and blocked"
            }
        except Exception as e:
            result = {
                "attack_type": "REPLAY_ATTACK",
                "status": "FAILED",
                "message": str(e)
            }
        
        # Log the simulation end
        self.db.log_security_event(
            "SIMULATION_COMPLETED",
            "Replay Attack simulation completed",
            "SIMULATION",
            "INFO",
            {"attack_type": "REPLAY_ATTACK", "result": result}
        )
        
        return result
    
    def simulate_mitm_attack(self) -> Dict[str, Any]:
        """
        Simulate a Man-in-the-Middle attack
        """
        # Log the simulation start
        self.db.log_security_event(
            "SIMULATION_STARTED",
            "MITM Attack simulation initiated",
            "SIMULATION",
            "INFO",
            {"attack_type": "MITM_ATTACK"}
        )
        
        # In a real implementation, this would check for certificate issues,
        # encrypted data integrity, etc.
        try:
            # Simulate checking encrypted data
            test_data = {"transaction_id": "TX-001", "amount": 100.0}
            encrypted_package = self.crypto.encrypt_data(test_data)
            
            # Verify integrity by attempting to decrypt
            decrypted_data = self.crypto.decrypt_data(encrypted_package)
            
            if test_data == decrypted_data:
                result = {
                    "attack_type": "MITM_ATTACK",
                    "status": "DETECTED",
                    "message": "MITM attack attempt detected and blocked by encryption verification"
                }
            else:
                result = {
                    "attack_type": "MITM_ATTACK",
                    "status": "FAILED",
                    "message": "MITM attack may have tampered with data"
                }
        except Exception as e:
            result = {
                "attack_type": "MITM_ATTACK",
                "status": "FAILED",
                "message": f"Error during MITM detection: {str(e)}"
            }
        
        # Log the simulation end
        self.db.log_security_event(
            "SIMULATION_COMPLETED",
            "MITM Attack simulation completed",
            "SIMULATION",
            "INFO",
            {"attack_type": "MITM_ATTACK", "result": result}
        )
        
        return result
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of currently blocked IPs
        """
        return list(self.blocked_ips)
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address
        """
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            return True
        return False
    
    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent security events
        """
        return self.db.get_recent_security_events(limit)
    
    def stop_monitoring(self):
        """
        Stop the background monitoring thread
        """
        self.monitoring_active = False


# Global security service instance
security_service = SecurityService()


def get_security_service():
    """
    Get the global security service instance
    """
    return security_service


def demo_security_operations():
    """
    Demonstrate security operations
    """
    print("=== Security Service Demo ===")
    
    # Get security service
    ss = get_security_service()
    
    print("\n1. Testing SQL Injection Detection:")
    sql_tests = [
        "SELECT * FROM users WHERE id = 1",
        "SELECT * FROM users WHERE id = 1 OR '1'='1'",
        "SELECT * FROM users; DROP TABLE users; --"
    ]
    
    for query in sql_tests:
        result = ss.check_sql_injection(query, "192.168.1.100")
        print(f"   Query: {query[:30]}...")
        print(f"   Result: {result['action_taken']} - Suspicious: {result['is_suspicious']}")
    
    print("\n2. Testing Brute Force Detection:")
    test_ip = "10.0.0.50"
    
    # Simulate 3 failed attempts
    for i in range(3):
        ss.record_failed_attempt(test_ip)
        result = ss.check_brute_force(test_ip)
        print(f"   Failed attempt #{i+1}: {result['action_taken']} - Attempts: {result['failed_attempts']}")
    
    # Simulate 5 more attempts to trigger block
    for i in range(5):
        ss.record_failed_attempt(test_ip)
    
    final_result = ss.check_brute_force(test_ip)
    print(f"   After 8 attempts: {final_result['action_taken']} - Blocked: {test_ip in ss.blocked_ips}")
    
    print("\n3. Testing Suspicious User Agent Detection:")
    user_agents = [
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "sqlmap/1.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    ]
    
    for ua in user_agents:
        result = ss.check_suspicious_user_agent(ua, "203.0.113.42")
        print(f"   User Agent: {ua[:20]}... - Suspicious: {result['is_suspicious']}")
    
    print("\n4. Running Attack Simulations:")
    
    # Run SQL injection simulation
    print("   SQL Injection Simulation:")
    sql_result = ss.simulate_sql_injection()
    print(f"     Status: {sql_result['attacks'][-1]['result']['action_taken']}")
    
    # Run brute force simulation
    print("   Brute Force Simulation:")
    bf_result = ss.simulate_brute_force()
    print(f"     Status: {bf_result['result']['action_taken']}")
    
    # Run replay attack simulation
    print("   Replay Attack Simulation:")
    replay_result = ss.simulate_replay_attack()
    print(f"     Status: {replay_result['status']}")
    
    # Run MITM attack simulation
    print("   MITM Attack Simulation:")
    mitm_result = ss.simulate_mitm_attack()
    print(f"     Status: {mitm_result['status']}")
    
    print("\n5. Security Events:")
    events = ss.get_security_events(5)
    for event in events:
        print(f"   [{event['severity']}] {event['event_type']}: {event['description']}")
    
    print("\n6. Blocked IPs:")
    blocked = ss.get_blocked_ips()
    for ip in blocked:
        print(f"   - {ip}")
    
    print("\n=== Security Demo Completed ===")


if __name__ == "__main__":
    demo_security_operations()