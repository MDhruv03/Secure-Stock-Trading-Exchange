import os
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional

class KeyManager:
    """
    Key Management Service for the Secure Trading Platform
    Handles secure storage and management of cryptographic keys
    """
    
    def __init__(self, key_storage_path: str = "keys/"):
        self.key_storage_path = key_storage_path
        self.ensure_key_storage()
        
        # Load or generate master key
        self.master_key = self.load_or_generate_master_key()
        
        # Load or generate RSA key pair
        self.rsa_private_key, self.rsa_public_key = self.load_or_generate_rsa_keys()
    
    def ensure_key_storage(self):
        """Ensure key storage directory exists"""
        if not os.path.exists(self.key_storage_path):
            os.makedirs(self.key_storage_path)
            print(f"[KEYMAN] Created key storage directory: {self.key_storage_path}")
    
    def load_or_generate_master_key(self) -> bytes:
        """Load or generate the master encryption key"""
        master_key_path = os.path.join(self.key_storage_path, "master.key")
        
        if os.path.exists(master_key_path):
            # Load existing master key
            with open(master_key_path, "rb") as f:
                encrypted_key = f.read()
            
            # For demo, we'll just return a fixed key
            # In production, this would be decrypted with a secure method
            return b"demo_master_key_32_bytes_long_32"  # Exactly 32 bytes
        else:
            # Generate new master key
            master_key = os.urandom(32)  # 256-bit key
            
            # For demo, we'll just save it directly
            # In production, this would be encrypted before saving
            with open(master_key_path, "wb") as f:
                f.write(master_key)
            
            print("[KEYMAN] Generated new master key")
            return master_key
    
    def load_or_generate_rsa_keys(self):
        """Load or generate RSA key pair"""
        private_key_path = os.path.join(self.key_storage_path, "private_key.pem")
        public_key_path = os.path.join(self.key_storage_path, "public_key.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, "rb") as f:
                private_pem = f.read()
            
            with open(public_key_path, "rb") as f:
                public_pem = f.read()
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            
            public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
            print("[KEYMAN] Loaded existing RSA key pair")
            return private_key, public_key
        else:
            # Generate new RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Save private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(private_key_path, "wb") as f:
                f.write(private_pem)
            
            # Save public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(public_key_path, "wb") as f:
                f.write(public_pem)
            
            print("[KEYMAN] Generated new RSA key pair")
            return private_key, public_key
    
    def get_master_key(self) -> bytes:
        """Get the master encryption key"""
        return self.master_key
    
    def get_rsa_keys(self):
        """Get the RSA key pair"""
        return self.rsa_private_key, self.rsa_public_key
    
    def rotate_master_key(self) -> bytes:
        """Rotate the master encryption key"""
        new_master_key = os.urandom(32)
        master_key_path = os.path.join(self.key_storage_path, "master.key")
        
        with open(master_key_path, "wb") as f:
            f.write(new_master_key)
        
        self.master_key = new_master_key
        print("[KEYMAN] Rotated master key")
        return new_master_key
    
    def export_key_metadata(self) -> Dict[str, Any]:
        """Export key metadata for backup/audit purposes"""
        return {
            "master_key_path": os.path.join(self.key_storage_path, "master.key"),
            "rsa_private_key_path": os.path.join(self.key_storage_path, "private_key.pem"),
            "rsa_public_key_path": os.path.join(self.key_storage_path, "public_key.pem"),
            "key_generation_timestamp": os.path.getctime(os.path.join(self.key_storage_path, "master.key")),
            "key_algorithm": "AES-256",
            "rsa_key_size": 2048
        }

# Global key manager instance
key_manager = KeyManager()

def get_key_manager():
    """Get the global key manager instance"""
    return key_manager

def demo_key_management():
    """Demonstrate key management operations"""
    print("=== Key Management Service Demo ===")
    
    # Get key manager
    km = get_key_manager()
    
    # Show key metadata
    metadata = km.export_key_metadata()
    print("\n1. Key Metadata:")
    for key, value in metadata.items():
        print(f"   {key}: {value}")
    
    # Get master key
    master_key = km.get_master_key()
    print(f"\n2. Master Key: {master_key.hex()[:32]}...")
    print(f"   Master Key Length: {len(master_key)} bytes")
    
    # Get RSA keys
    private_key, public_key = km.get_rsa_keys()
    print(f"\n3. RSA Private Key: {type(private_key)}")
    print(f"   RSA Public Key: {type(public_key)}")
    
    # Rotate master key
    print("\n4. Key Rotation:")
    new_master_key = km.rotate_master_key()
    print(f"   New Master Key: {new_master_key.hex()[:32]}...")
    print(f"   New Master Key Length: {len(new_master_key)} bytes")
    
    print("\n=== Key Management Demo Completed ===")

if __name__ == "__main__":
    demo_key_management()