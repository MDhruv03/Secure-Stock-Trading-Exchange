from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign(data_bytes: bytes, priv_pem: str) -> bytes:
    """Signs data using RSA."""
    key = RSA.import_key(priv_pem)
    h = SHA256.new(data_bytes)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify(data_bytes: bytes, sig: bytes, pub_pem: str) -> bool:
    """Verifies a signature using RSA."""
    key = RSA.import_key(pub_pem)
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(key).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False