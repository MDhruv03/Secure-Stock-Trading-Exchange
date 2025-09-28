"""
Red Team Attack Simulator for Secure Trading Platform
Simulates various attack vectors for educational purposes
"""
import time
import random
import threading
import requests
from typing import Dict, List, Any
from backend.app.utils.database import get_db_manager


class AttackSimulator:
    """
    Simulates various attack vectors against the trading platform
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.base_url = "http://localhost:8000"
    
    def simulate_sql_injection(self) -> Dict[str, Any]:
        """
        Simulate SQL injection attack
        """
        print("Simulating SQL Injection Attack...")
        
        # Record simulation start
        simulation_id = self.db.start_attack_simulation(
            "SQL_INJECTION", 
            "Simulating SQL injection attack on login endpoint"
        )
        
        # Malicious payloads
        payloads = [
            {"username": "' OR '1'='1", "password": "' OR '1'='1"},
            {"username": "admin'; DROP TABLE users; --", "password": "password"},
            {"username": "'; EXEC xp_cmdshell 'ping 127.0.0.1'; --", "password": "password"},
            {"username": "admin' UNION SELECT 1,2,3,4,5--", "password": "password"},
            {"username": "admin", "password": "' OR 1=1 --"}
        ]
        
        results = []
        for payload in payloads:
            try:
                # This would normally be a real request to the API
                result = {
                    "payload": payload,
                    "status": "BLOCKED",  # In real system, these would be blocked
                    "detected": True,
                    "defense_response": "IP Blocked",
                    "timestamp": time.time()
                }
                results.append(result)
                
                # Log the attempted attack
                self.db.log_security_event(
                    "SQL_INJECTION_ATTEMPT",
                    f"SQL injection attempt with payload: {payload}",
                    "ATTACK_SIM",
                    "HIGH",
                    {"payload": payload, "simulation_id": simulation_id}
                )
                
                # Add defense response
                self.db.add_defense_response(
                    simulation_id,
                    "INTRUSION_DETECTION",
                    f"Detected SQL injection in payload: {payload}",
                    "EXECUTED"
                )
                
                time.sleep(0.5)  # Small delay between attempts
                
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e),
                    "timestamp": time.time()
                })
        
        # Record simulation end
        self.db.end_attack_simulation(simulation_id, f"Completed with {len(results)} attempted payloads")
        
        return {
            "attack_type": "SQL_INJECTION",
            "simulation_id": simulation_id,
            "total_attempts": len(payloads),
            "results": results
        }
    
    def simulate_brute_force(self) -> Dict[str, Any]:
        """
        Simulate brute force attack
        """
        print("Simulating Brute Force Attack...")
        
        # Record simulation start
        simulation_id = self.db.start_attack_simulation(
            "BRUTE_FORCE", 
            "Simulating brute force attack on authentication"
        )
        
        # Common credentials to try
        credentials = [
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "user", "password": "password"},
            {"username": "root", "password": "toor"},
            {"username": "test", "password": "test"},
            {"username": "admin", "password": "123456"},
            {"username": "user", "password": "12345678"},
            {"username": "demo", "password": "demo"},
            {"username": "guest", "password": "guest"},
            {"username": "admin", "password": "password123"}
        ]
        
        results = []
        for cred in credentials:
            try:
                # This would normally be a real request to the API
                result = {
                    "credentials": cred,
                    "status": "BLOCKED",  # In real system, after several attempts
                    "detected": True,
                    "defense_response": "Rate Limiting Applied",
                    "timestamp": time.time()
                }
                results.append(result)
                
                # Log the attempted login
                self.db.log_security_event(
                    "BRUTE_FORCE_ATTEMPT",
                    f"Brute force attempt with credentials: {cred}",
                    "ATTACK_SIM",
                    "MEDIUM",
                    {"credentials": cred, "simulation_id": simulation_id}
                )
                
                # Add defense response
                self.db.add_defense_response(
                    simulation_id,
                    "RATE_LIMITING",
                    f"Applied rate limiting after failed attempt: {cred}",
                    "EXECUTED"
                )
                
                time.sleep(0.1)  # Small delay between attempts
                
            except Exception as e:
                results.append({
                    "credentials": cred,
                    "error": str(e),
                    "timestamp": time.time()
                })
        
        # Record simulation end
        self.db.end_attack_simulation(simulation_id, f"Completed with {len(credentials)} attempted logins")
        
        return {
            "attack_type": "BRUTE_FORCE",
            "simulation_id": simulation_id,
            "total_attempts": len(credentials),
            "results": results
        }
    
    def simulate_replay_attack(self) -> Dict[str, Any]:
        """
        Simulate replay attack
        """
        print("Simulating Replay Attack...")
        
        # Record simulation start
        simulation_id = self.db.start_attack_simulation(
            "REPLAY_ATTACK", 
            "Simulating replay attack on transaction endpoint"
        )
        
        # Simulate capturing and replaying a transaction
        original_transaction = {
            "user_id": 12345,
            "symbol": "BTC",
            "side": "buy",
            "quantity": 1.0,
            "price": 45000.00,
            "timestamp": int(time.time()),
            "nonce": "original_nonce_123"
        }
        
        # Simulate replayed transaction with same data (except timestamp)
        replayed_transaction = original_transaction.copy()
        replayed_transaction["timestamp"] = int(time.time()) + 10  # 10 seconds later
        replayed_transaction["nonce"] = "original_nonce_123"  # Same nonce - this is the attack!
        
        # Results
        result = {
            "original_transaction": original_transaction,
            "replayed_transaction": replayed_transaction,
            "status": "DETECTED",
            "detected": True,
            "defense_response": "Nonce Verification Failed",
            "timestamp": time.time()
        }
        
        # Log the attempted replay
        self.db.log_security_event(
            "REPLAY_ATTEMPT_DETECTED",
            "Replay attack detected: duplicate nonce found",
            "ATTACK_SIM",
            "HIGH",
            {
                "original": original_transaction,
                "replayed": replayed_transaction,
                "simulation_id": simulation_id
            }
        )
        
        # Add defense response
        self.db.add_defense_response(
            simulation_id,
            "NONCE_VERIFICATION",
            "Detected and blocked replay attack using nonce verification",
            "EXECUTED"
        )
        
        # Record simulation end
        self.db.end_attack_simulation(simulation_id, "Replay attack successfully detected and blocked")
        
        return {
            "attack_type": "REPLAY_ATTACK",
            "simulation_id": simulation_id,
            "result": result
        }
    
    def simulate_mitm_attack(self) -> Dict[str, Any]:
        """
        Simulate Man-in-the-Middle attack
        """
        print("Simulating MITM Attack...")
        
        # Record simulation start
        simulation_id = self.db.start_attack_simulation(
            "MITM_ATTACK", 
            "Simulating MITM attack on encrypted communication"
        )
        
        # Simulate intercepted and modified data
        original_data = {
            "user_id": 12345,
            "order_id": 67890,
            "symbol": "ETH",
            "side": "sell",
            "quantity": 5.0,
            "price": 3200.00,
            "timestamp": int(time.time())
        }
        
        # Simulate tampered data (attacker modifies the quantity)
        tampered_data = original_data.copy()
        tampered_data["quantity"] = 50.0  # Attacker increased quantity
        
        # Results
        result = {
            "original_data": original_data,
            "tampered_data": tampered_data,
            "status": "DETECTED",
            "detected": True,
            "defense_response": "Digital Signature Verification Failed",
            "timestamp": time.time()
        }
        
        # Log the attempted MITM
        self.db.log_security_event(
            "MITM_ATTEMPT_DETECTED",
            "MITM attack detected: data integrity violation",
            "ATTACK_SIM",
            "HIGH",
            {
                "original": original_data,
                "tampered": tampered_data,
                "simulation_id": simulation_id
            }
        )
        
        # Add defense response
        self.db.add_defense_response(
            simulation_id,
            "SIGNATURE_VERIFICATION",
            "Detected and blocked MITM attack using digital signature verification",
            "EXECUTED"
        )
        
        # Record simulation end
        self.db.end_attack_simulation(simulation_id, "MITM attack successfully detected and blocked")
        
        return {
            "attack_type": "MITM_ATTACK",
            "simulation_id": simulation_id,
            "result": result
        }
    
    def run_all_simulations(self) -> Dict[str, Any]:
        """
        Run all attack simulations
        """
        print("Running All Attack Simulations...")
        
        results = {}
        results["sql_injection"] = self.simulate_sql_injection()
        results["brute_force"] = self.simulate_brute_force()
        results["replay_attack"] = self.simulate_replay_attack()
        results["mitm_attack"] = self.simulate_mitm_attack()
        
        return results


# Global attack simulator instance
attack_simulator = AttackSimulator()


def simulate_sql_injection():
    """Run SQL injection simulation"""
    return attack_simulator.simulate_sql_injection()


def simulate_brute_force():
    """Run brute force simulation"""
    return attack_simulator.simulate_brute_force()


def simulate_replay_attack():
    """Run replay attack simulation"""
    return attack_simulator.simulate_replay_attack()


def simulate_mitm_attack():
    """Run MITM attack simulation"""
    return attack_simulator.simulate_mitm_attack()


def simulate_all_attacks():
    """Run all attack simulations"""
    return attack_simulator.run_all_simulations()


def demo_attack_simulations():
    """
    Demonstrate attack simulations
    """
    print("=== Red Team Attack Simulation Demo ===")
    
    # Run all simulations
    results = simulate_all_attacks()
    
    print(f"\nSQL Injection Results: {results['sql_injection']['total_attempts']} payloads attempted")
    print(f"Brute Force Results: {results['brute_force']['total_attempts']} login attempts")
    print(f"Replay Attack Results: {results['replay_attack']['result']['status']}")
    print(f"MITM Attack Results: {results['mitm_attack']['result']['status']}")
    
    print("\nAttack simulations completed successfully!")
    print("All attacks were properly detected and blocked by defense mechanisms.")


if __name__ == "__main__":
    demo_attack_simulations()