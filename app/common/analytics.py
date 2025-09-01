
from phe import paillier

def generate_paillier_keypair(n_length=1024):
    """Generates a Paillier key pair."""
    public_key, private_key = paillier.generate_paillier_keypair(n_length=n_length)
    return public_key, private_key

def encrypt_value(public_key, value):
    """Encrypts a value using the Paillier public key."""
    return public_key.encrypt(value)

def decrypt_value(private_key, encrypted_value):
    """Decrypts a value using the Paillier private key."""
    return private_key.decrypt(encrypted_value)

def homomorphic_add(encrypted_values):
    """Performs homomorphic addition on a list of encrypted values."""
    if not encrypted_values:
        return None
    
    sum_encrypted = encrypted_values[0]
    for i in range(1, len(encrypted_values)):
        sum_encrypted += encrypted_values[i]
        
    return sum_encrypted
