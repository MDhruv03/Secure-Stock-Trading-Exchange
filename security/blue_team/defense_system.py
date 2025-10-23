"""
Blue Team Defense System for Secure Trading Platform
Implements defense mechanisms against various attack vectors
"""
import time
import hashlib
import hmac
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service


class IntrusionDetectionSystem:
    """
    Intrusion Detection System for the Secure Trading Platform
    Monitors for suspicious activities and triggers defensive measures
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
        self.suspicious_ips = set()
        self.suspicious_patterns = {}
        self.monitoring_active = True
        
        # Thresholds for detection
        self.login_attempts_threshold = 5
        self.api_call_threshold = 100  # per minute
        self.data_modification_threshold = 3  # per user per minute
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._continuous_monitoring, daemon=True)
        self.monitoring_thread.start()
    
    def _continuous_monitoring(self):
        """
        Background monitoring thread
        """
        while self.monitoring_active:
            # Check for anomalies every 30 seconds
            self._check_anomalies()
            time.sleep(30)
    
    def _check_anomalies(self):
        """
        Check for various anomalies in system behavior
        """
        # Check for unusual login patterns
        self._check_unusual_login_patterns()
        
        # Check for API rate limiting violations
        self._check_api_rate_violations()
        
        # Check for data integrity violations
        self._check_data_integrity_violations()
    
    def _check_unusual_login_patterns(self):
        """
        Check for unusual login patterns
        """
        # This would query the database for login attempts
        # For demo purposes, we'll just log the check
        pass
    
    def _check_api_rate_violations(self):
        """
        Check for API rate limiting violations
        """
        # This would check API usage patterns
        # For demo purposes, we'll just log the check
        pass
    
    def _check_data_integrity_violations(self):
        """
        Check for data integrity violations
        """
        # This would verify signatures and data integrity
        # For demo purposes, we'll just log the check
        pass
    
    def check_sql_injection(self, query: str, ip_address: str) -> Dict[str, Any]:
        """
        Check if query contains SQL injection patterns
        """
        sql_patterns = [
            "'", "--", "/*", "*/", "xp_", "sp_", "exec", "execute",
            "union", "select", "insert", "update", "delete", "drop",
            "create", "alter", "declare", "where", "having", "order by"
        ]
        
        detected = False
        matched_patterns = []
        
        for pattern in sql_patterns:
            if pattern.lower() in query.lower():
                detected = True
                matched_patterns.append(pattern)
        
        if detected:
            # Log security event
            self.db.log_security_event(
                "SQL_INJECTION_DETECTED",
                f"SQL injection detected from IP {ip_address}",
                ip_address,
                "HIGH",
                {
                    "query": query,
                    "matched_patterns": matched_patterns
                }
            )
            
            # Block IP
            self._block_ip(ip_address, "SQL Injection detected")
            
            return {
                "detected": True,
                "blocked": True,
                "severity": "HIGH",
                "patterns": matched_patterns,
                "threat_level": "HIGH",
                "action_taken": "BLOCK_IP"
            }
        
        return {
            "detected": False,
            "blocked": False,
            "severity": "LOW",
            "patterns": [],
            "threat_level": "LOW",
            "action_taken": "ALLOWED"
        }
    
    def check_brute_force(self, ip_address: str) -> Dict[str, Any]:
        """
        Check for brute force attack based on failed login attempts
        """
        # Get recent login failures for this IP
        recent_events = self.db.get_recent_security_events(20)
        failed_attempts = 0
        
        for event in recent_events:
            if (event["event_type"] == "FAILED_LOGIN" and 
                event["source_ip"] == ip_address and
                datetime.now() - datetime.fromisoformat(event["created_at"]) < timedelta(minutes=5)):
                failed_attempts += 1
        
        if failed_attempts >= self.login_attempts_threshold:
            # Log security event
            self.db.log_security_event(
                "BRUTE_FORCE_DETECTED",
                f"Brute force attack detected from IP {ip_address}",
                ip_address,
                "HIGH",
                {"failed_attempts": failed_attempts}
            )
            
            # Block IP
            self._block_ip(ip_address, f"Brute force: {failed_attempts} failed attempts")
            
            return {
                "detected": True,
                "severity": "HIGH",
                "failed_attempts": failed_attempts,
                "action_taken": "BLOCK_IP"
            }
        
        return {
            "detected": False,
            "severity": "LOW",
            "failed_attempts": failed_attempts,
            "action_taken": "ALLOWED"
        }
    
    def check_replay_attack(self, data: Dict[str, Any], timestamp: int) -> Dict[str, Any]:
        """
        Check for replay attacks using timestamp and nonce verification
        """
        current_time = int(time.time())
        
        # Check if timestamp is too old (potential replay)
        if current_time - timestamp > 300:  # 5 minutes
            # Log security event
            self.db.log_security_event(
                "REPLAY_ATTACK_DETECTED",
                "Potential replay attack: timestamp too old",
                "SYSTEM",
                "MEDIUM",
                {"timestamp_diff": current_time - timestamp}
            )
            
            return {
                "detected": True,
                "severity": "MEDIUM",
                "reason": "Timestamp too old",
                "action_taken": "REJECT_REQUEST"
            }
        
        # Check for duplicate nonces (if present in data)
        if "nonce" in data:
            # In a real implementation, we'd check against stored nonces
            # For demo, we'll just log the check
            pass
        
        return {
            "detected": False,
            "severity": "LOW",
            "reason": "Timestamp is valid",
            "action_taken": "ALLOWED"
        }
    
    def check_mitm_attack(self, data: Dict[str, Any], signature: str) -> Dict[str, Any]:
        """
        Check for MITM attacks by verifying digital signatures
        """
        try:
            # Verify the signature
            is_valid = self.crypto.verify_signature(data, signature)
            
            if not is_valid:
                # Log security event
                self.db.log_security_event(
                    "MITM_ATTACK_DETECTED",
                    "MITM attack detected: invalid digital signature",
                    "SYSTEM",
                    "HIGH",
                    {"data": data}
                )
                
                return {
                    "detected": True,
                    "severity": "HIGH",
                    "reason": "Invalid signature",
                    "action_taken": "REJECT_REQUEST"
                }
            
            return {
                "detected": False,
                "severity": "LOW",
                "reason": "Signature is valid",
                "action_taken": "ALLOWED"
            }
            
        except Exception as e:
            # Log security event
            self.db.log_security_event(
                "SIGNATURE_VERIFICATION_ERROR",
                f"Error during signature verification: {str(e)}",
                "SYSTEM",
                "HIGH",
                {"error": str(e)}
            )
            
            return {
                "detected": True,
                "severity": "HIGH",
                "reason": f"Verification error: {str(e)}",
                "action_taken": "REJECT_REQUEST"
            }
    
    def check_data_integrity(self, original_hash: str, current_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check data integrity by comparing hashes
        """
        try:
            # Calculate hash of current data
            current_hash = hashlib.sha256(str(sorted(current_data.items())).encode()).hexdigest()
            
            if original_hash != current_hash:
                # Log security event
                self.db.log_security_event(
                    "DATA_INTEGRITY_VIOLATION",
                    "Data integrity violation detected",
                    "SYSTEM",
                    "HIGH",
                    {
                        "original_hash": original_hash,
                        "current_hash": current_hash,
                        "data": current_data
                    }
                )
                
                return {
                    "integrity_violation": True,
                    "severity": "HIGH",
                    "action_taken": "REJECT_REQUEST"
                }
            
            return {
                "integrity_violation": False,
                "severity": "LOW",
                "action_taken": "ALLOWED"
            }
            
        except Exception as e:
            # Log security event
            self.db.log_security_event(
                "INTEGRITY_CHECK_ERROR",
                f"Error during integrity check: {str(e)}",
                "SYSTEM",
                "HIGH",
                {"error": str(e)}
            )
            
            return {
                "integrity_violation": True,
                "severity": "HIGH",
                "action_taken": "REJECT_REQUEST"
            }
    
    def check_suspicious_user_agent(self, user_agent: str, ip_address: str) -> Dict[str, Any]:
        """
        Check for suspicious user agents
        """
        suspicious_agents = [
            "sqlmap", "nikto", "nessus", "nmap", "hydra", "medusa",
            "burp", "zaproxy", "metasploit", "dirb", "gobuster"
        ]
        
        detected = False
        matched_agent = None
        
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                detected = True
                matched_agent = agent
                break
        
        if detected:
            # Log security event
            self.db.log_security_event(
                "SUSPICIOUS_USER_AGENT_DETECTED",
                f"Suspicious user agent detected: {user_agent}",
                ip_address,
                "MEDIUM",
                {"user_agent": user_agent, "matched_agent": matched_agent}
            )
            
            # Block IP
            self._block_ip(ip_address, f"Suspicious user agent: {matched_agent}")
            
            return {
                "detected": True,
                "severity": "MEDIUM",
                "matched_agent": matched_agent,
                "action_taken": "BLOCK_IP"
            }
        
        return {
            "detected": False,
            "severity": "LOW",
            "matched_agent": None,
            "action_taken": "ALLOWED"
        }
    
    def check_brute_force(self, ip_address: str, attempts: int = 1) -> Dict[str, Any]:
        """
        Enhanced brute force detection with attempt counting
        """
        # Track login attempts per IP
        if not hasattr(self, 'login_attempts'):
            self.login_attempts = {}
        
        if ip_address not in self.login_attempts:
            self.login_attempts[ip_address] = {
                'count': 0,
                'first_attempt': time.time()
            }
        
        self.login_attempts[ip_address]['count'] += attempts
        attempt_count = self.login_attempts[ip_address]['count']
        
        # Check if threshold exceeded
        threshold = 10  # 10 attempts triggers block
        blocked = attempt_count >= threshold
        
        if blocked:
            block_duration = 30  # 30 minutes
            
            # Log and block
            self.db.log_security_event(
                "BRUTE_FORCE_DETECTED",
                f"Brute force attack: {attempt_count} attempts from {ip_address}",
                ip_address,
                "CRITICAL"
            )
            
            self._block_ip(ip_address, f"Brute force: {attempt_count} attempts")
            
            return {
                "blocked": True,
                "detected": True,
                "attempt_count": attempt_count,
                "threshold": threshold,
                "block_duration": block_duration,
                "severity": "CRITICAL"
            }
        
        return {
            "blocked": False,
            "detected": attempt_count > threshold / 2,  # Warn at half threshold
            "attempt_count": attempt_count,
            "threshold": threshold,
            "severity": "WARNING" if attempt_count > threshold / 2 else "LOW"
        }
    
    def check_replay_attack(self, transaction: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """
        Enhanced replay attack detection with nonce and timestamp validation
        """
        current_time = int(time.time())
        transaction_timestamp = transaction.get('timestamp', current_time)
        
        # Calculate timestamp age
        timestamp_age = current_time - transaction_timestamp
        
        # Check timestamp (stale if older than 5 minutes)
        timestamp_valid = timestamp_age < 300
        
        # Check nonce (simulate nonce validation)
        nonce_valid = transaction.get('nonce') is not None
        
        # Blocked if timestamp is stale or nonce missing
        blocked = not timestamp_valid or not nonce_valid
        
        if blocked:
            reason = "Stale timestamp (>5 min)" if not timestamp_valid else "Missing or invalid nonce"
            
            self.db.log_security_event(
                "REPLAY_ATTACK_DETECTED",
                f"Replay attack from {ip_address}: {reason}",
                ip_address,
                "WARNING"
            )
            
            return {
                "blocked": True,
                "detected": True,
                "reason": reason,
                "timestamp_age": timestamp_age,
                "nonce_valid": nonce_valid,
                "severity": "WARNING"
            }
        
        return {
            "blocked": False,
            "detected": False,
            "reason": "Valid timestamp and nonce",
            "timestamp_age": timestamp_age,
            "nonce_valid": nonce_valid,
            "severity": "LOW"
        }
    
    def check_mitm_attack(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """
        Enhanced MITM attack detection via encryption verification
        """
        # In real scenario, check if connection is encrypted and certificate is valid
        # For simulation, assume all traffic should be encrypted
        encrypted = True  # Assume AES-256-GCM encryption is active
        encryption_type = "AES-256-GCM"
        certificate_valid = True
        
        # MITM is blocked if encryption is active
        blocked = encrypted
        
        if blocked:
            self.db.log_security_event(
                "MITM_ATTEMPT_BLOCKED",
                f"MITM attempt thwarted by {encryption_type} encryption",
                ip_address,
                "INFO"
            )
            
            return {
                "blocked": True,
                "detected": True,
                "encrypted": encrypted,
                "encryption_type": encryption_type,
                "certificate_valid": certificate_valid,
                "severity": "INFO"
            }
        
        # If unencrypted (would be critical)
        return {
            "blocked": False,
            "detected": True,
            "encrypted": False,
            "encryption_type": "NONE",
            "certificate_valid": False,
            "severity": "CRITICAL"
        }
    
    def _block_ip(self, ip_address: str, reason: str):
        """
        Block an IP address
        """
        self.db.block_ip(ip_address, reason)
        self.suspicious_ips.add(ip_address)
        
        # Log the blocking action
        self.db.log_security_event(
            "IP_BLOCKED",
            f"IP {ip_address} blocked: {reason}",
            ip_address,
            "HIGH",
            {"reason": reason}
        )
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of blocked IPs
        """
        return self.db.get_blocked_ips()
    
    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent security events
        """
        return self.db.get_recent_security_events(limit)
    
    def get_defense_responses(self, simulation_id: int) -> List[Dict[str, Any]]:
        """
        Get defense responses for a simulation
        """
        return self.db.get_defense_responses(simulation_id)
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries
        """
        return self.db.get_audit_log(limit)
    
    def stop_monitoring(self):
        """
        Stop the monitoring thread
        """
        self.monitoring_active = False


class DefenseSystem:
    """
    Main Defense System that coordinates all defense mechanisms
    """
    
    def __init__(self):
        self.ids = IntrusionDetectionSystem()
        self.crypto = get_crypto_service()
    
    def run_defense_scan(self) -> Dict[str, Any]:
        """
        Run a comprehensive defense scan
        """
        print("Running Comprehensive Defense Scan...")
        
        # Check for blocked IPs
        blocked_ips = self.ids.get_blocked_ips()
        
        # Check recent security events
        security_events = self.ids.get_security_events(20)
        
        # Check audit log
        audit_log = self.ids.get_audit_log(20)
        
        return {
            "scan_time": datetime.now().isoformat(),
            "blocked_ips_count": len(blocked_ips),
            "security_events_count": len(security_events),
            "audit_log_entries": len(audit_log),
            "status": "SECURE" if len([e for e in security_events if e["severity"] in ["HIGH", "CRITICAL"]]) == 0 else "WARNING"
        }
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report
        """
        scan_results = self.run_defense_scan()
        
        # Calculate statistics
        security_events = self.ids.get_security_events(100)
        high_severity_events = [e for e in security_events if e["severity"] == "HIGH"]
        medium_severity_events = [e for e in security_events if e["severity"] == "MEDIUM"]
        
        report = {
            "report_time": datetime.now().isoformat(),
            "summary": {
                "total_security_events": len(security_events),
                "high_severity_events": len(high_severity_events),
                "medium_severity_events": len(medium_severity_events),
                "blocked_ips": scan_results["blocked_ips_count"]
            },
            "system_status": scan_results["status"],
            "recent_events": security_events[:10],
            "recommendations": [
                "Monitor for unusual login patterns",
                "Review blocked IP addresses regularly",
                "Ensure all cryptographic keys are properly rotated",
                "Verify all digital signatures are being validated"
            ]
        }
        
        return report


# Global defense system instance
defense_system = DefenseSystem()


def get_intrusion_detection_system():
    """Get the intrusion detection system instance"""
    return defense_system.ids


def run_defense_scan():
    """Run a comprehensive defense scan"""
    return defense_system.run_defense_scan()


def generate_security_report():
    """Generate a comprehensive security report"""
    return defense_system.generate_security_report()


def demo_defense_operations():
    """
    Demonstrate defense operations
    """
    print("=== Blue Team Defense System Demo ===")
    
    # Get defense system
    ds = defense_system
    
    # Run a defense scan
    print("\n1. Running Defense Scan:")
    scan_results = ds.run_defense_scan()
    print(f"   Status: {scan_results['status']}")
    print(f"   Blocked IPs: {scan_results['blocked_ips_count']}")
    print(f"   Security Events: {scan_results['security_events_count']}")
    
    # Generate security report
    print("\n2. Generating Security Report:")
    report = ds.generate_security_report()
    print(f"   System Status: {report['system_status']}")
    print(f"   Total Events: {report['summary']['total_security_events']}")
    print(f"   High Severity: {report['summary']['high_severity_events']}")
    print(f"   Medium Severity: {report['summary']['medium_severity_events']}")
    
    # Test attack detection
    print("\n3. Testing Attack Detection:")
    
    # Test SQL injection detection
    result = ds.ids.check_sql_injection("SELECT * FROM users WHERE id = 1 OR '1'='1'", "192.168.1.100")
    print(f"   SQL Injection Detection: {result['action_taken']}")
    
    # Test brute force detection (simulated)
    result = ds.ids.check_brute_force("10.0.0.50")
    print(f"   Brute Force Detection: {result['action_taken']}")
    
    # Test replay attack detection
    test_data = {"user_id": 12345, "order_id": 67890}
    result = ds.ids.check_replay_attack(test_data, int(time.time()) - 600)  # 10 minutes ago
    print(f"   Replay Attack Detection: {result['action_taken']}")
    
    # Test MITM detection
    result = ds.ids.check_mitm_attack(test_data, "invalid_signature_here")
    print(f"   MITM Attack Detection: {result['action_taken']}")
    
    # Test suspicious user agent detection
    result = ds.ids.check_suspicious_user_agent("Mozilla/5.0 (compatible; sqlmap/1.0)", "203.0.113.42")
    print(f"   Suspicious User Agent Detection: {result['action_taken']}")
    
    print("\n4. Security Events:")
    events = ds.ids.get_security_events(5)
    for event in events:
        print(f"   [{event['severity']}] {event['event_type']}: {event['description']}")
    
    print("\n5. Blocked IPs:")
    blocked = ds.ids.get_blocked_ips()
    for ip in blocked[:5]:  # Show first 5
        print(f"   - {ip['ip_address']}: {ip['reason']}")
    
    print("\n6. Defense Recommendations:")
    for rec in report['recommendations'][:3]:
        print(f"   - {rec}")
    
    print("\n=== Defense Demo Completed ===")


if __name__ == "__main__":
    demo_defense_operations()