import unittest
import os
import sys

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.crypto.merkle import MerkleTree
from app.crypto.he import generate_paillier_keypair, paillier_encrypt, paillier_decrypt
from app.crypto.key_mgmt import generate_keypair, save_key, load_key
from app.common.crypto import hash_data, generate_random_string

class TestCrypto(unittest.TestCase):

    def test_merkle_tree(self):
        transactions = ['a', 'b', 'c', 'd']
        tree = MerkleTree(transactions)
        root = tree.get_root()
        self.assertIsNotNone(root)

        proof = tree.get_proof('a')
        self.assertIsNotNone(proof)

        self.assertTrue(tree.verify_transaction('a', proof, root))
        self.assertFalse(tree.verify_transaction('x', proof, root))

    def test_paillier(self):
        public_key, private_key = generate_paillier_keypair()
        m1 = 10
        m2 = 20

        c1 = paillier_encrypt(m1, public_key)
        c2 = paillier_encrypt(m2, public_key)

        # Homomorphic addition
        c_sum = (c1 * c2) % (public_key[0] ** 2)

        m_sum = paillier_decrypt(c_sum, public_key, private_key)

        self.assertEqual(m1 + m2, m_sum)

    def test_key_management(self):
        public_key, private_key = generate_keypair()

        pub_filename = 'test_pub.key'
        priv_filename = 'test_priv.key'

        save_key(public_key, pub_filename)
        save_key(private_key, priv_filename)

        loaded_pub_key = load_key(pub_filename)
        loaded_priv_key = load_key(priv_filename)

        self.assertEqual(public_key, loaded_pub_key)
        self.assertEqual(private_key, loaded_priv_key)

        os.remove(pub_filename)
        os.remove(priv_filename)

    def test_common_crypto(self):
        data = 'hello world'
        hashed_data = hash_data(data)
        self.assertEqual(hashed_data, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')

        random_string = generate_random_string(10)
        self.assertEqual(len(random_string), 10)

if __name__ == '__main__':
    unittest.main()
