import hashlib
import secrets
import string

def hash_data(data: str) -> str:
    """Hashes a string using SHA256."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_random_string(length: int) -> str:
    """Generates a random string of a given length."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))
