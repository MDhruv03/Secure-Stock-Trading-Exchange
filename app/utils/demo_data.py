from app.database import database
from app.models import users, orders
from app.security import get_password_hash
from app.crypto.encryption import encrypt_order
from app.crypto.signatures import sign
from app.crypto.merkle import MerkleTree
from app.crypto.key_mgmt import generate_keypair
import os
import json
from datetime import datetime

async def seed_demo_data():
    print("Seeding database with initial data...")
    async with database.transaction():
        # Create a default admin user
        admin_public_key, admin_private_key = generate_keypair()
        admin_password_hash = get_password_hash("adminpass")
        await database.execute(users.insert().values(
            username="admin", 
            password_hash=admin_password_hash, 
            public_key=admin_public_key, 
            private_key=admin_private_key, # For demo/lab only
            role="admin", 
            balance=999999.99
        ))
        print("Admin user created.")

        # Create a default customer user
        customer_public_key, customer_private_key = generate_keypair()
        customer_password_hash = get_password_hash("customerpass")
        await database.execute(users.insert().values(
            username="customer", 
            password_hash=customer_password_hash, 
            public_key=customer_public_key, 
            private_key=customer_private_key, # For demo/lab only
            role="customer", 
            balance=10000.00
        ))
        print("Customer user created.")

        # Add some sample orders (encrypted and signed)
        # This is a simplified example, in a real app, orders would come from clients
        sample_order_data = {
            "id": 1,
            "user_id": 2, # Assuming customer user has ID 2
            "stock": "BTC-USD",
            "side": "buy",
            "qty": 1,
            "price": 50000.0
        }
        
        aes_key = os.urandom(16)
        ciphertext, nonce, tag, header = encrypt_order(sample_order_data, aes_key)
        
        # Sign the order data (using customer's private key)
        order_json_str = json.dumps(sample_order_data)
        signature = sign(order_json_str.encode('utf-8'), customer_private_key)

        merkle_leaf_data = f"{sample_order_data['id']}-{sample_order_data['user_id']}-{sample_order_data['stock']}-{sample_order_data['side']}-{sample_order_data['qty']}-{sample_order_data['price']}"
        merkle_leaf = MerkleTree([merkle_leaf_data]).get_root()

        await database.execute(orders.insert().values(
            id=sample_order_data["id"],
            user_id=sample_order_data["user_id"],
            stock=sample_order_data["stock"],
            qty=sample_order_data["qty"],
            side=sample_order_data["side"],
            price=sample_order_data["price"],
            ciphertext=ciphertext.hex(),
            nonce=nonce.hex(),
            signature=signature.hex(),
            merkle_leaf=merkle_leaf,
            created_at=datetime.now()
        ))
        print("Sample order added.")

    print("Database seeded.")