import os
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional

class KeyManager:
    """
    Key Management Service for Secure Trading Platform
    Handles generation, storage, and retrieval of cryptographic keys
    """
    
    def __init__(self, key_storage_path: str = "keys"):
        self.key_storage_path = key_storage_path
        self._ensure_key_storage()
    
    def _ensure_key_storage(self):
        """Ensure key storage directory exists"""
        if not os.path.exists(self.key_storage_path):
            os.makedirs(self.key_storage_path)
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict[str, str]:
        """
        Generate RSA key pair
        Returns dictionary with PEM-encoded private and public keys
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "private_key": private_pem.decode('utf-8'),
            "public_key": public_pem.decode('utf-8')
        }
    
    def store_key_pair(self, key_id: str, key_pair: Dict[str, str]) -> bool:
        """
        Store key pair securely
        In production, this should use secure storage mechanisms
        """
        try:
            key_file_path = os.path.join(self.key_storage_path, f"{key_id}.json")
            
            # In a real implementation, you would encrypt the key file
            with open(key_file_path, 'w') as f:
                json.dump(key_pair, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[KEY MANAGER] Error storing key pair: {str(e)}")
            return False
    
    def load_key_pair(self, key_id: str) -> Optional[Dict[str, str]]:
        """
        Load key pair from storage
        """
        try:
            key_file_path = os.path.join(self.key_storage_path, f"{key_id}.json")
            
            if not os.path.exists(key_file_path):
                return None
            
            with open(key_file_path, 'r') as f:
                key_pair = json.load(f)
            
            return key_pair
        except Exception as e:
            print(f"[KEY MANAGER] Error loading key pair: {str(e)}")
            return None
    
    def generate_aes_key(self, key_size: int = 256) -> str:
        """
        Generate AES key
        Returns base64-encoded key
        """
        key_bytes = os.urandom(key_size // 8)
        return base64.b64encode(key_bytes).decode('utf-8')
    
    def store_aes_key(self, key_id: str, aes_key: str) -> bool:
        """
        Store AES key securely
        """
        try:
            key_file_path = os.path.join(self.key_storage_path, f"{key_id}_aes.json")
            
            key_data = {
                "key": aes_key
            }
            
            # In a real implementation, you would encrypt the key file
            with open(key_file_path, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"[KEY MANAGER] Error storing AES key: {str(e)}")
            return False
    
    def load_aes_key(self, key_id: str) -> Optional[str]:
        """
        Load AES key from storage
        """
        try:
            key_file_path = os.path.join(self.key_storage_path, f"{key_id}_aes.json")
            
            if not os.path.exists(key_file_path):
                return None
            
            with open(key_file_path, 'r') as f:
                key_data = json.load(f)
            
            return key_data.get("key")
        except Exception as e:
            print(f"[KEY MANAGER] Error loading AES key: {str(e)}")
            return None
    
    def rotate_keys(self, key_id: str) -> bool:
        """
        Rotate keys for a given key ID
        """
        try:
            # Generate new key pair
            new_key_pair = self.generate_rsa_keypair()
            
            # Store new key pair
            if self.store_key_pair(key_id, new_key_pair):
                print(f"[KEY MANAGER] Keys rotated for {key_id}")
                return True
            else:
                print(f"[KEY MANAGER] Failed to store new keys for {key_id}")
                return False
        except Exception as e:
            print(f"[KEY MANAGER] Error rotating keys: {str(e)}")
            return False

# Global key manager instance
key_manager = KeyManager()

def get_key_manager():
    """Get the global key manager instance"""
    return key_manager

def demo_key_management():
    """
    Demonstrate key management operations
    """
    print("=== Key Management Service Demo ===")
    
    # Get key manager
    km = get_key_manager()
    
    # Generate RSA key pair
    print("\n1. Generating RSA Key Pair:")
    key_pair = km.generate_rsa_keypair()
    print(f"   Private Key Length: {len(key_pair['private_key'])} characters")
    print(f"   Public Key Length: {len(key_pair['public_key'])} characters")
    
    # Store key pair
    print("\n2. Storing Key Pair:")
    if km.store_key_pair("demo_key", key_pair):
        print("   Key pair stored successfully")
    else:
        print("   Failed to store key pair")
    
    # Load key pair
    print("\n3. Loading Key Pair:")
    loaded_key_pair = km.load_key_pair("demo_key")
    if loaded_key_pair:
        print("   Key pair loaded successfully")
        print(f"   Keys match: {key_pair == loaded_key_pair}")
    else:
        print("   Failed to load key pair")
    
    # Generate AES key
    print("\n4. Generating AES Key:")
    aes_key = km.generate_aes_key()
    print(f"   AES Key: {aes_key[:32]}...")
    print(f"   Key Length: {len(aes_key)} characters")
    
    # Store AES key
    print("\n5. Storing AES Key:")
    if km.store_aes_key("demo_aes", aes_key):
        print("   AES key stored successfully")
    else:
        print("   Failed to store AES key")
    
    # Load AES key
    print("\n6. Loading AES Key:")
    loaded_aes_key = km.load_aes_key("demo_aes")
    if loaded_aes_key:
        print("   AES key loaded successfully")
        print(f"   Keys match: {aes_key == loaded_aes_key}")
    else:
        print("   Failed to load AES key")
    
    print("\n=== Key Management Demo Completed ===")

if __name__ == "__main__":
    demo_key_management()