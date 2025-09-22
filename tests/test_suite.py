import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

class TestSecureTradingPlatform(unittest.TestCase):
    """Test suite for the Secure Trading Platform"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Use a temporary database for testing
        self.test_db_path = ":memory:"
    
    def test_imports(self):
        """Test that all modules can be imported"""
        # Test database module
        try:
            from backend.app.database import DatabaseManager
            db = DatabaseManager(self.test_db_path)  # Use in-memory database for testing
            self.assertIsNotNone(db)
        except Exception as e:
            self.fail(f"Database module import failed: {str(e)}")
        
        # Test crypto module
        try:
            from backend.app.crypto_service import CryptoService
            crypto = CryptoService()
            self.assertIsNotNone(crypto)
        except Exception as e:
            self.fail(f"Crypto module import failed: {str(e)}")
        
        # Test auth module
        try:
            from backend.app.auth_service import AuthService
            auth = AuthService()
            self.assertIsNotNone(auth)
        except Exception as e:
            self.fail(f"Auth module import failed: {str(e)}")
        
        # Test trading module
        try:
            from backend.app.trading_service import TradingService
            trading = TradingService()
            self.assertIsNotNone(trading)
        except Exception as e:
            self.fail(f"Trading module import failed: {str(e)}")
    
    def test_database_operations(self):
        """Test basic database operations"""
        from backend.app.database import DatabaseManager
        
        # Use in-memory database for testing
        db = DatabaseManager(self.test_db_path)
        
        # Test user creation
        user_id = db.create_user("testuser", "hashed_password")
        self.assertIsNotNone(user_id)
        self.assertGreater(user_id, 0)
        
        # Test getting user
        user = db.get_user_by_username("testuser")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "testuser")
        
        # Test order creation
        order_id = db.create_order(
            user_id=user_id,
            symbol="BTC",
            side="buy",
            quantity=0.5,
            price=45000.00,
            encrypted_data="encrypted_data_here",
            signature="digital_signature_here",
            merkle_leaf="merkle_leaf_hash",
            nonce="nonce_data",
            tag="tag_data"
        )
        self.assertIsNotNone(order_id)
        self.assertGreater(order_id, 0)
        
        # Test getting user orders
        orders = db.get_user_orders(user_id)
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0]["symbol"], "BTC")
        self.assertEqual(orders[0]["side"], "buy")
    
    def test_crypto_operations(self):
        """Test basic cryptographic operations"""
        from backend.app.crypto_service import CryptoService
        
        crypto = CryptoService()
        
        # Test data encryption/decryption
        test_data = {
            "order_id": "ORD-001",
            "symbol": "BTC",
            "quantity": 0.5,
            "price": 45000.00
        }
        
        # Encrypt data
        encrypted_package = crypto.encrypt_data(test_data)
        self.assertIn("ciphertext", encrypted_package)
        self.assertIn("nonce", encrypted_package)
        self.assertIn("tag", encrypted_package)
        
        # Decrypt data
        decrypted_data = crypto.decrypt_data(encrypted_package)
        self.assertEqual(test_data, decrypted_data)
        
        # Test digital signature
        signature = crypto.sign_data(test_data)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)
        
        # Verify signature
        is_valid = crypto.verify_signature(test_data, signature)
        self.assertTrue(is_valid)
        
        # Test Merkle tree operations
        leaf_hash = crypto.create_merkle_leaf(test_data)
        self.assertIsInstance(leaf_hash, str)
        self.assertTrue(len(leaf_hash) > 0)
        
        merkle_root = crypto.create_merkle_root([leaf_hash])
        self.assertIsInstance(merkle_root, str)
        self.assertTrue(len(merkle_root) > 0)
    
    def test_auth_operations(self):
        """Test basic authentication operations"""
        from backend.app.auth_service import AuthService
        
        auth = AuthService()
        
        # Test password hashing
        password = "testpassword123"
        hashed = auth.hash_password(password)
        self.assertIsInstance(hashed, str)
        self.assertTrue(len(hashed) > 0)
        
        # Test password verification
        is_valid = auth.verify_password(password, hashed)
        self.assertTrue(is_valid)
        
        # Test invalid password
        is_invalid = auth.verify_password("wrongpassword", hashed)
        self.assertFalse(is_invalid)
    
    def test_trading_operations(self):
        """Test basic trading operations"""
        from backend.app.trading_service import TradingService
        from backend.app.database import DatabaseManager
        from backend.app.crypto_service import CryptoService
        
        # Mock database and crypto services
        trading = TradingService()
        
        # Test order book retrieval
        order_book = trading.get_order_book("BTC")
        self.assertIn("symbol", order_book)
        self.assertIn("buy_orders", order_book)
        self.assertIn("sell_orders", order_book)
        self.assertEqual(order_book["symbol"], "BTC")
        
        # Test VWAP calculation
        vwap = trading.calculate_vwap("BTC")
        self.assertIsInstance(vwap, float)
        # Note: VWAP might be 0 if there are no orders, which is valid
        
        # Test trade search
        results = trading.search_trades("BTC")
        self.assertIsInstance(results, list)

if __name__ == "__main__":
    print("=== Secure Trading Platform Test Suite ===")
    print()
    
    # Run tests
    unittest.main(verbosity=2)