
import requests
import json
import time

def simulate_replay_attack():
    """Simulates a replay attack on the /order endpoint."""
    url = "http://localhost:8000/order"
    headers = {'Content-Type': 'application/json'}
    
    # Legitimate payload
    legitimate_payload = {
        "order": {
            "id": "replay_order",
            "trader_id": "trader3",
            "asset": "ETH-USD",
            "type": "sell",
            "amount": 5.0,
            "price": 3000.0
        },
        "signature": "dummy_signature",
        "public_key": "dummy_public_key"
    }

    print("Sending a legitimate request...")
    try:
        response = requests.post(url, headers=headers, data=json.dumps(legitimate_payload))
        print(f"Server response: {response.status_code} - {response.text}")

        # Replay the same request multiple times
        print("\nReplaying the request...")
        for i in range(3):
            print(f"Replay attempt {i+1}")
            response = requests.post(url, headers=headers, data=json.dumps(legitimate_payload))
            print(f"Server response: {response.status_code} - {response.text}")
            time.sleep(1)

    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")

if __name__ == '__main__':
    simulate_replay_attack()
