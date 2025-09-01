
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from collections import defaultdict

class SearchableSymmetricEncryption:
    def __init__(self, key):
        self.key = key
        self.index = defaultdict(list)

    def _get_keyword_hash(self, keyword):
        """Hashes a keyword."""
        return SHA256.new(keyword.encode('utf-8')).digest()

    def add_document(self, doc_id, keywords):
        """Adds a document to the searchable index."""
        for keyword in keywords:
            keyword_hash = self._get_keyword_hash(keyword)
            self.index[keyword_hash].append(doc_id)

    def search(self, keyword):
        """Searches the index for a keyword."""
        keyword_hash = self._get_keyword_hash(keyword)
        return self.index.get(keyword_hash, [])

# Example Usage (for demonstration)
if __name__ == '__main__':
    # Generate a secret key
    secret_key = os.urandom(16)

    # Create an SSE instance
    sse = SearchableSymmetricEncryption(secret_key)

    # Add some documents (in our case, trade logs)
    sse.add_document("log1", ["buy", "BTC", "trader1"])
    sse.add_document("log2", ["sell", "ETH", "trader2"])
    sse.add_document("log3", ["buy", "ETH", "trader1"])

    # Search for a keyword
    results = sse.search("trader1")
    print(f"Search results for 'trader1': {results}")

    results = sse.search("BTC")
    print(f"Search results for 'BTC': {results}")

    results = sse.search("XRP")
    print(f"Search results for 'XRP': {results}")
