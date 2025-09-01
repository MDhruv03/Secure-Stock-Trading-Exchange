from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def encrypt_aes_gcm(key, plaintext):
    """Encrypts plaintext using AES-GCM."""
    header = b"header"
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, header, ciphertext, tag

def decrypt_aes_gcm(key, nonce, header, ciphertext, tag):
    """Decrypts ciphertext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext