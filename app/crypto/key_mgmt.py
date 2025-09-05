from Crypto.PublicKey import RSA

def generate_keypair() -> tuple:
    """Generates a new RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key

def save_key(key: str, filename: str):
    """Saves a key to a file."""
    with open(filename, 'w') as f:
        f.write(key)

def load_key(filename: str) -> str:
    """Loads a key from a file."""
    with open(filename, 'r') as f:
        return f.read()

def generate_and_save_keypair(public_filename: str, private_filename: str):
    """Generates a new RSA key pair and saves it to files."""
    public_key, private_key = generate_keypair()
    save_key(public_key, public_filename)
    save_key(private_key, private_filename)
