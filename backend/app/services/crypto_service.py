import os
import hashlib
import hmac
import secrets
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
import base64
import json
from typing import Dict, Any, Tuple, Optional
import time

class CryptoService:
    """
    Enhanced Cryptographic Service for the Secure Trading Platform
    Provides encryption, decryption, signing, verification, and key management services
    """
    
    def __init__(self):
        # Generate or load master encryption key
        self.master_key = self._generate_or_load_master_key()
        
        # Generate or load RSA key pair
        self.private_key, self.public_key = self._generate_or_load_rsa_keys()
        
        # Generate or load ECC key pair for key exchange
        self.ecc_private_key, self.ecc_public_key = self._generate_or_load_ecc_keys()
        
        # Key derivation salt
        self.salt = self._generate_or_load_salt()
        
        # HMAC key for message authentication
        self.hmac_key = self._generate_or_load_hmac_key()
    
    def _generate_or_load_master_key(self) -> bytes:
        """
        Generate or load the master AES key
        In production, this would be loaded from a secure key management system
        """
        # For demo purposes, generate a random 256-bit key
        return os.urandom(32)  # 256 bits = 32 bytes
    
    def _generate_or_load_rsa_keys(self) -> Tuple[Any, Any]:
        """
        Generate or load RSA key pair
        In production, private key would be stored securely
        """
        # Generate new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def _generate_or_load_ecc_keys(self) -> Tuple[Any, Any]:
        """
        Generate or load ECC key pair for key exchange
        """
        # Generate new ECC key pair
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def _generate_or_load_salt(self) -> bytes:
        """
        Generate or load salt for key derivation
        """
        return os.urandom(16)  # 128 bits = 16 bytes
    
    def _generate_or_load_hmac_key(self) -> bytes:
        """
        Generate or load HMAC key for message authentication
        """
        return os.urandom(32)  # 256 bits = 32 bytes
    
    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """
        Derive a key from a password using PBKDF2
        """
        if salt is None:
            salt = self.salt
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key
    
    def encrypt_data(self, data: Dict[str, Any], key: bytes = None) -> Dict[str, str]:
        """
        Encrypt data using AES-256-GCM
        Returns encrypted data with metadata needed for decryption
        """
        if key is None:
            key = self.master_key
            
        # Convert data to JSON string
        plaintext = json.dumps(data, separators=(',', ':'))
        
        # Generate a random 96-bit nonce (12 bytes)
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        # Encrypt the data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # Return encrypted data with metadata
        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def decrypt_data(self, encrypted_package: Dict[str, str], key: bytes = None) -> Dict[str, Any]:
        """
        Decrypt data using AES-256-GCM
        Takes encrypted package and returns decrypted data
        """
        if key is None:
            key = self.master_key
            
        # Decode base64 encoded data
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        # Decrypt the data
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Parse JSON and return
        return json.loads(plaintext.decode('utf-8'))
    
    def sign_data(self, data: Dict[str, Any]) -> str:
        """
        Sign data using RSA private key
        Returns base64 encoded signature
        """
        # Convert data to JSON string
        data_string = json.dumps(data, separators=(',', ':'), sort_keys=True)
        
        # Sign the data
        signature = self.private_key.sign(
            data_string.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, data: Dict[str, Any], signature: str) -> bool:
        """
        Verify signature using RSA public key
        Returns True if signature is valid, False otherwise
        """
        try:
            # Convert data to JSON string
            data_string = json.dumps(data, separators=(',', ':'), sort_keys=True)
            
            # Decode signature
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            # Verify signature
            self.public_key.verify(
                signature_bytes,
                data_string.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
        except Exception:
            return False
    
    def create_merkle_leaf(self, data: Dict[str, Any]) -> str:
        """
        Create a Merkle tree leaf hash from data
        """
        # Convert data to JSON string with sorted keys for consistency
        data_string = json.dumps(data, separators=(',', ':'), sort_keys=True)
        
        # Create SHA-256 hash
        leaf_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
        
        return leaf_hash
    
    def create_merkle_root(self, leaves: list) -> str:
        """
        Create a Merkle tree root from a list of leaf hashes
        """
        if not leaves:
            return hashlib.sha256(b"").hexdigest()
        
        # Work with a copy of leaves
        current_level = leaves[:]
        
        # Build tree level by level
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last one
                right = current_level[i+1] if i+1 < len(current_level) else left
                
                # Concatenate and hash
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode('utf-8')).hexdigest())
            
            current_level = next_level
        
        return current_level[0]
    
    def build_merkle_tree_with_structure(self, leaves: list) -> Dict[str, Any]:
        """
        Build complete Merkle tree with full structure for visualization
        Returns tree structure with all nodes and levels
        """
        if not leaves:
            empty_hash = hashlib.sha256(b"").hexdigest()
            return {
                "root": empty_hash,
                "levels": [[{"hash": empty_hash, "index": 0, "isLeaf": True}]],
                "total_levels": 1,
                "total_nodes": 1,
                "leaf_count": 0
            }
        
        # Initialize tree structure
        tree_levels = []
        current_level = []
        
        # Add leaf level
        for i, leaf in enumerate(leaves):
            current_level.append({
                "hash": leaf,
                "index": i,
                "isLeaf": True,
                "left_child": None,
                "right_child": None
            })
        
        tree_levels.append(current_level)
        
        # Build intermediate levels
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left_node = current_level[i]
                right_node = current_level[i+1] if i+1 < len(current_level) else current_level[i]
                
                # Create parent hash
                combined = left_node["hash"] + right_node["hash"]
                parent_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                
                parent_node = {
                    "hash": parent_hash,
                    "index": i // 2,
                    "isLeaf": False,
                    "left_child": left_node["hash"],
                    "right_child": right_node["hash"]
                }
                
                next_level.append(parent_node)
            
            tree_levels.append(next_level)
            current_level = next_level
        
        # Calculate total nodes
        total_nodes = sum(len(level) for level in tree_levels)
        
        return {
            "root": tree_levels[-1][0]["hash"],
            "levels": tree_levels,
            "total_levels": len(tree_levels),
            "total_nodes": total_nodes,
            "leaf_count": len(leaves)
        }
    
    def generate_merkle_proof(self, leaves: list, leaf_index: int) -> Dict[str, Any]:
        """
        Generate Merkle proof for a specific leaf
        Proof can be used to verify the leaf is part of the tree without revealing all leaves
        """
        if not leaves or leaf_index < 0 or leaf_index >= len(leaves):
            return {
                "valid": False,
                "error": "Invalid leaf index"
            }
        
        proof_path = []
        current_level = leaves[:]
        current_index = leaf_index
        
        # Build proof path from leaf to root
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                
                # If current index is at this pair, add sibling to proof
                if i == current_index or i+1 == current_index:
                    if i == current_index:
                        # Current is left, add right sibling
                        proof_path.append({
                            "hash": right,
                            "position": "right"
                        })
                    else:
                        # Current is right, add left sibling
                        proof_path.append({
                            "hash": left,
                            "position": "left"
                        })
                    
                    current_index = i // 2
                
                # Create parent hash
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode('utf-8')).hexdigest())
            
            current_level = next_level
        
        return {
            "valid": True,
            "leaf": leaves[leaf_index],
            "leaf_index": leaf_index,
            "root": current_level[0],
            "proof": proof_path,
            "proof_length": len(proof_path)
        }
    
    def verify_merkle_proof(self, leaf: str, proof: list, root: str) -> bool:
        """
        Verify a Merkle proof
        Returns True if the proof is valid, False otherwise
        """
        try:
            current_hash = leaf
            
            # Process proof path
            for step in proof:
                sibling_hash = step["hash"]
                position = step["position"]
                
                if position == "left":
                    combined = sibling_hash + current_hash
                else:  # right
                    combined = current_hash + sibling_hash
                
                current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
            
            # Check if computed root matches expected root
            return current_hash == root
        except Exception:
            return False
    
    def generate_homomorphic_keypair(self) -> Tuple[int, int]:
        """
        Generate a simple homomorphic encryption keypair (simplified for demo)
        In practice, this would use a proper homomorphic encryption library
        """
        # For demo purposes, we'll use a simple additive homomorphic scheme
        # This is NOT cryptographically secure - just for demonstration
        private_key = 12345  # In reality, this would be much more complex
        public_key = 67890    # And properly generated
        
        return private_key, public_key
    
    def homomorphic_encrypt(self, value: int, public_key: int) -> int:
        """
        Simple homomorphic encryption (NOT SECURE - for demo only)
        """
        # This is a simplified demonstration - NOT cryptographically secure
        return (value * public_key) + 42  # Simple multiplication with offset
    
    def homomorphic_add(self, encrypted_a: int, encrypted_b: int) -> int:
        """
        Perform homomorphic addition on encrypted values
        """
        # In a real homomorphic system, you could add encrypted values
        # and decrypt the result to get the sum of the plaintexts
        return encrypted_a + encrypted_b
    
    def homomorphic_decrypt(self, encrypted_value: int, private_key: int) -> int:
        """
        Decrypt homomorphically encrypted value (simplified demo)
        """
        # This is a simplified demonstration - NOT cryptographically secure
        return (encrypted_value - 42) // private_key
    
    def generate_diffie_hellman_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate Diffie-Hellman key pair for secure key exchange
        """
        # Generate private key (32 bytes)
        private_key = secrets.token_bytes(32)
        
        # Generate public key using ECC
        public_key = self.ecc_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_key, public_key
    
    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Derive shared secret using ECDH
        """
        import logging
        try:
            # Load peer's public key
            peer_public_key_obj = load_pem_public_key(peer_public_key, backend=default_backend())
            
            # Derive shared secret
            shared_secret = self.ecc_private_key.exchange(ec.ECDH(), peer_public_key_obj)
            
            # Derive key from shared secret
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(shared_secret)
            
            return key
        except Exception as e:
            logging.error(f"Crypto error deriving shared secret: {str(e)}")
            return None
    
    def create_certificate(self, subject_name: str) -> Tuple[bytes, bytes]:
        """
        Create a self-signed certificate (simplified for demo)
        In production, use a proper certificate authority
        """
        # This is a simplified implementation for demonstration purposes
        # In a real implementation, you would use a proper certificate generation library
        
        # Generate certificate data
        cert_data = {
            "subject": subject_name,
            "issuer": "Secure Trading Platform CA",
            "valid_from": time.time(),
            "valid_to": time.time() + 365*24*60*60,  # 1 year
            "public_key": base64.b64encode(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode('utf-8')
        }
        
        # Sign certificate data
        signature = self.sign_data(cert_data)
        
        # Return certificate and signature
        cert_pem = json.dumps(cert_data)
        return cert_pem.encode('utf-8'), signature.encode('utf-8')
    
    def verify_certificate(self, cert_pem: bytes, signature: bytes) -> bool:
        """
        Verify a certificate's signature
        """
        try:
            # Parse certificate
            cert_data = json.loads(cert_pem.decode('utf-8'))
            
            # Verify signature
            return self.verify_signature(cert_data, signature.decode('utf-8'))
        except Exception:
            return False
    
    def hmac_sign(self, data: Dict[str, Any]) -> str:
        """
        Create HMAC signature for message authentication
        """
        # Convert data to JSON string
        data_string = json.dumps(data, separators=(',', ':'), sort_keys=True)
        
        # Create HMAC
        hmac_obj = hmac.new(self.hmac_key, data_string.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(hmac_obj.digest()).decode('utf-8')
    
    def hmac_verify(self, data: Dict[str, Any], signature: str) -> bool:
        """
        Verify HMAC signature
        """
        try:
            # Create expected signature
            expected_signature = self.hmac_sign(data)
            
            # Compare signatures
            return hmac.compare_digest(expected_signature, signature)
        except Exception:
            return False

# Global crypto service instance
crypto_service = CryptoService()

def get_crypto_service():
    """Get the global crypto service instance"""
    return crypto_service

def demo_crypto_operations():
    """
    Demonstrate cryptographic operations
    """
    print("=== Enhanced Cryptographic Service Demo ===")
    
    # Get crypto service
    cs = get_crypto_service()
    
    # Test data
    test_data = {
        "order_id": "ORD-001",
        "symbol": "BTC",
        "quantity": 0.5,
        "price": 45000.00,
        "timestamp": "2023-01-01T12:00:00Z",
        "user_id": 12345
    }
    
    print("\n1. Original Data:")
    print(f"   {test_data}")
    
    # Test encryption/decryption
    print("\n2. AES-256-GCM Encryption:")
    encrypted_package = cs.encrypt_data(test_data)
    print(f"   Ciphertext: {encrypted_package['ciphertext'][:50]}...")
    print(f"   Nonce: {encrypted_package['nonce']}")
    print(f"   Tag: {encrypted_package['tag']}")
    
    print("\n3. AES-256-GCM Decryption:")
    decrypted_data = cs.decrypt_data(encrypted_package)
    print(f"   Decrypted: {decrypted_data}")
    print(f"   Match: {test_data == decrypted_data}")
    
    # Test digital signatures
    print("\n4. RSA Digital Signature:")
    signature = cs.sign_data(test_data)
    print(f"   Signature: {signature[:50]}...")
    
    print("\n5. Signature Verification:")
    is_valid = cs.verify_signature(test_data, signature)
    print(f"   Valid: {is_valid}")
    
    # Test Merkle tree
    print("\n6. Merkle Tree Operations:")
    
    # Create multiple leaves
    leaves = []
    for i in range(5):
        leaf_data = {"tx_id": f"TX-{i+1}", "amount": (i+1) * 100}
        leaf_hash = cs.create_merkle_leaf(leaf_data)
        leaves.append(leaf_hash)
        print(f"   Leaf {i+1}: {leaf_hash[:16]}...")
    
    # Create Merkle root
    merkle_root = cs.create_merkle_root(leaves)
    print(f"   Merkle Root: {merkle_root[:32]}...")
    
    # Test homomorphic encryption
    print("\n7. Homomorphic Encryption (Demo):")
    hom_priv_key, hom_pub_key = cs.generate_homomorphic_keypair()
    print(f"   Private Key: {hom_priv_key}")
    print(f"   Public Key: {hom_pub_key}")
    
    value1 = 100
    value2 = 200
    
    enc_value1 = cs.homomorphic_encrypt(value1, hom_pub_key)
    enc_value2 = cs.homomorphic_encrypt(value2, hom_pub_key)
    
    print(f"   Encrypted {value1}: {enc_value1}")
    print(f"   Encrypted {value2}: {enc_value2}")
    
    # Perform homomorphic addition
    enc_sum = cs.homomorphic_add(enc_value1, enc_value2)
    print(f"   Encrypted Sum: {enc_sum}")
    
    # Decrypt result
    dec_sum = cs.homomorphic_decrypt(enc_sum, hom_priv_key)
    print(f"   Decrypted Sum: {dec_sum}")
    print(f"   Correct: {dec_sum == (value1 + value2)}")
    
    # Test Diffie-Hellman key exchange
    print("\n8. Diffie-Hellman Key Exchange:")
    priv_key_a, pub_key_a = cs.generate_diffie_hellman_keys()
    priv_key_b, pub_key_b = cs.generate_diffie_hellman_keys()
    
    print(f"   Party A Private Key: {priv_key_a[:16].hex()}...")
    print(f"   Party A Public Key: {pub_key_a[:32].decode('utf-8', errors='ignore')}...")
    print(f"   Party B Private Key: {priv_key_b[:16].hex()}...")
    print(f"   Party B Public Key: {pub_key_b[:32].decode('utf-8', errors='ignore')}...")
    
    # Test HMAC
    print("\n9. HMAC Authentication:")
    hmac_signature = cs.hmac_sign(test_data)
    print(f"   HMAC Signature: {hmac_signature[:32]}...")
    
    is_hmac_valid = cs.hmac_verify(test_data, hmac_signature)
    print(f"   HMAC Valid: {is_hmac_valid}")
    
    print("\n=== Enhanced Crypto Demo Completed ===")

if __name__ == "__main__":
    demo_crypto_operations()