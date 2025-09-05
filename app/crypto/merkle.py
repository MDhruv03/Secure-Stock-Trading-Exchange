import hashlib
from app.database import database
from app.models import merkle_roots
from sqlalchemy.sql import func

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.tree = self._create_tree()

    def _create_tree(self):
        transactions = [self._hash(tx) for tx in self.transactions]
        tree = [transactions]
        while len(transactions) > 1:
            if len(transactions) % 2 != 0:
                transactions.append(transactions[-1])
            level = []
            for i in range(0, len(transactions), 2):
                level.append(self._hash(transactions[i] + transactions[i+1]))
            transactions = level
            tree.append(transactions)
        return tree

    def _hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def get_root(self):
        if not self.tree or not self.tree[-1]:
            return None
        return self.tree[-1][0]

    def add_transaction(self, transaction):
        self.transactions.append(transaction)
        self.tree = self._create_tree()

    def get_proof(self, transaction):
        tx_hash = self._hash(transaction)
        if tx_hash not in self.tree[0]:
            return None
        
        proof = []
        index = self.tree[0].index(tx_hash)
        
        for i in range(len(self.tree) - 1):
            level = self.tree[i]
            is_right_node = index % 2
            sibling_index = index - 1 if is_right_node else index + 1
            
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            
            index //= 2
            
        return proof

    def verify_transaction(self, transaction, proof, root):
        leaf = self._hash(transaction)
        
        for sibling in proof:
            leaf = self._hash(leaf + sibling)
            
        return leaf == root

    async def append_leaf(self, leaf_hash: str) -> str:
        """Appends a leaf hash to the Merkle tree and returns the new root."""
        self.add_transaction(leaf_hash)
        new_root = self.get_root()
        return new_root

    def leaf_for_order(self, order_id: int) -> str:
        """Generates a Merkle leaf hash for a given order ID."""
        # This is a placeholder. In a real scenario, the leaf would be a hash of the order's content.
        return self._hash(str(order_id))

    async def prove(self, order_id: int) -> dict:
        """Generates a Merkle proof for a given order ID."""
        leaf = self.leaf_for_order(order_id)
        proof = self.get_proof(leaf)
        root = self.get_root()
        return {"leaf": leaf, "path": proof, "root": root}

    async def checkpoint_every(self, n: int):
        """Stores the current Merkle root in the database every N appends."""
        if len(self.transactions) % n == 0:
            root_hash = self.get_root()
            total_leaves = len(self.transactions)
            query = merkle_roots.insert().values(root_hash=root_hash, total_leaves=total_leaves, created_at=func.now())
            await database.execute(query)
            print(f"Merkle tree checkpointed. Root: {root_hash}, Leaves: {total_leaves}")
