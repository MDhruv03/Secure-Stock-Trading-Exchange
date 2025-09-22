#!/usr/bin/env python3
"""
Security Simulation Runner for Secure Trading Platform
Runs various attack simulations to test the defense system
"""

import sys
import os
import time

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def run_sql_injection_simulation():
    """Run SQL injection attack simulation"""
    print("Running SQL Injection Attack Simulation...")
    
    try:
        from security.red_team.attack_simulator import simulate_sql_injection
        simulate_sql_injection()
        print("SQL Injection Simulation completed.\n")
        return True
    except Exception as e:
        print(f"Error in SQL Injection Simulation: {str(e)}\n")
        return False

def run_brute_force_simulation():
    """Run brute force attack simulation"""
    print("Running Brute Force Attack Simulation...")
    
    try:
        from security.red_team.attack_simulator import simulate_brute_force
        simulate_brute_force()
        print("Brute Force Simulation completed.\n")
        return True
    except Exception as e:
        print(f"Error in Brute Force Simulation: {str(e)}\n")
        return False

def run_replay_attack_simulation():
    """Run replay attack simulation"""
    print("Running Replay Attack Simulation...")
    
    try:
        from security.red_team.attack_simulator import simulate_replay_attack
        simulate_replay_attack()
        print("Replay Attack Simulation completed.\n")
        return True
    except Exception as e:
        print(f"Error in Replay Attack Simulation: {str(e)}\n")
        return False

def run_mitm_attack_simulation():
    """Run MITM attack simulation"""
    print("Running MITM Attack Simulation...")
    
    try:
        from security.red_team.attack_simulator import simulate_mitm_attack
        simulate_mitm_attack()
        print("MITM Attack Simulation completed.\n")
        return True
    except Exception as e:
        print(f"Error in MITM Attack Simulation: {str(e)}\n")
        return False

def run_blue_team_monitoring():
    """Run blue team monitoring to detect attacks"""
    print("Running Blue Team Monitoring...")
    
    try:
        from security.blue_team.defense_system import IntrusionDetectionSystem
        
        ids = IntrusionDetectionSystem()
        
        # Simulate some suspicious activities
        ids.check_sql_injection({"query": "SELECT * FROM users"}, "192.168.1.100")
        ids.check_brute_force("10.0.0.50")
        ids.check_suspicious_user_agent("sqlmap/1.0", "203.0.113.42")
        
        # Show recent events
        events = ids.get_security_events(10)
        print(f"Recent security events ({len(events)}):")
        for event in events:
            print(f"  [{event['severity']}] {event['event_type']}: {event['description']}")
        
        print("Blue Team Monitoring completed.\n")
        return True
    except Exception as e:
        print(f"Error in Blue Team Monitoring: {str(e)}\n")
        return False

def main():
    """Main simulation runner"""
    print("Secure Trading Platform - Security Simulation Runner")
    print("=" * 50)
    
    # Run all simulations
    simulations = [
        ("SQL Injection", run_sql_injection_simulation),
        ("Brute Force", run_brute_force_simulation),
        ("Replay Attack", run_replay_attack_simulation),
        ("MITM Attack", run_mitm_attack_simulation),
        ("Blue Team Monitoring", run_blue_team_monitoring)
    ]
    
    results = []
    for name, func in simulations:
        print(f"[{len(results)+1}/{len(simulations)}] {name}")
        success = func()
        results.append((name, success))
        time.sleep(1)  # Small delay between simulations
    
    # Print summary
    print("=" * 50)
    print("SIMULATION SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"{name}: {status}")
        if not success:
            all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("ALL SIMULATIONS COMPLETED SUCCESSFULLY!")
        return 0
    else:
        print("SOME SIMULATIONS FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(main())