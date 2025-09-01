from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

def encrypt_order(plaintext: dict, key: bytes) -> tuple:
    """Encrypts plaintext using AES-GCM."""
    header = b"order_data"
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(plaintext).encode('utf-8'))
    return ciphertext, cipher.nonce, tag, header

def decrypt_order(ciphertext: bytes, nonce: bytes, tag: bytes, header: bytes, key: bytes) -> dict:
    """Decrypts ciphertext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode('utf-8'))