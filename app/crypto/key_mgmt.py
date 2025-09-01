from Crypto.PublicKey import RSA

def generate_keypair() -> tuple:
    """Generates a new RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key