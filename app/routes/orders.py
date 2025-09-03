from fastapi import APIRouter, Depends, HTTPException, status
import logging

logger = logging.getLogger(__name__)

from app.database import database
from app.models import orders, trades, users
from app.security import get_current_user, get_current_admin_user
from app.schemas import UserResponse, OrderResponse, SignedOrder, TradeResponse
from app.crypto.signatures import verify as verify_signature
from app.crypto.encryption import encrypt_order, decrypt_order
from app.crypto.merkle import MerkleTree
import os
import json
from datetime import datetime
from typing import List

# Assuming OrderBook and MatchingEngine are defined elsewhere or passed as dependencies
# For MVP, we'll re-initialize them here, but in a real app, they'd be singletons.
from app.exchange import OrderBook, MatchingEngine

router = APIRouter()

order_book = OrderBook()
matching_engine = MatchingEngine(order_book)

trades_log = [] # This should ideally be managed globally or via DB
merkle_tree = MerkleTree(trades_log)



@router.get("/admin/users", response_model=List[UserResponse])
async def get_all_users(current_user: UserResponse = Depends(get_current_admin_user)):
    logger.info(f"Admin user '{current_user['username']}' accessed all users.")
    query = users.select()
    all_users = await database.fetch_all(query)
    return all_users

@router.get("/admin/orders", response_model=List[OrderResponse])
async def get_all_orders(current_user: UserResponse = Depends(get_current_admin_user)):
    logger.info(f"Admin user '{current_user['username']}' accessed all orders.")
    query = orders.select()
    all_orders = await database.fetch_all(query)
    return all_orders

@router.get("/admin/trades", response_model=List[TradeResponse])
async def get_all_trades(current_user: UserResponse = Depends(get_current_admin_user)):
    logger.info(f"Admin user '{current_user['username']}' accessed all trades.")
    query = trades.select()
    all_trades = await database.fetch_all(query)
    return all_trades

@router.post("/order")
async def place_order(signed_order: SignedOrder, current_user: UserResponse = Depends(get_current_user)):
    logger.info(f"User '{current_user['username']}' attempting to place order: {signed_order.order.dict()}")
    # In a real app, we would look up the public key based on the user_id
    # For now, we accept the public key in the request
    # Generate a random AES key for order encryption
    aes_key = os.urandom(16) # 128-bit key

    # Encrypt the order details
    order_to_encrypt = {
        "id": signed_order.order.id,
        "user_id": current_user["id"],
        "stock": signed_order.order.stock,
        "side": signed_order.order.side,
        "qty": signed_order.order.qty,
        "price": signed_order.order.price
    }
    ciphertext, nonce, tag, header = encrypt_order(order_to_encrypt, aes_key)

    # Sign the ciphertext (or a hash of it)
    # For simplicity, signing the original order_data (which is the signed_order.order.json())
    # In a real scenario, you might sign the ciphertext or a hash of the encrypted data.
    # The client already signed the original order_data, so we'll use that signature for now.
    # If we were to sign on the server, we'd need the server's private key.
    # For now, we'll use the signature provided by the client.

    # Generate Merkle leaf (hash of the order data)
    merkle_leaf_data = f"{signed_order.order.id}-{current_user['id']}-{signed_order.order.stock}-{signed_order.order.side}-{signed_order.order.qty}-{signed_order.order.price}"
    merkle_leaf = MerkleTree([merkle_leaf_data]).get_root() # Create a temporary MerkleTree for a single leaf

    order_data_for_db = {
        "id": signed_order.order.id,
        "user_id": current_user["id"],
        "stock": signed_order.order.stock,
        "qty": signed_order.order.qty,
        "side": signed_order.order.side,
        "price": signed_order.order.price,
        "ciphertext": ciphertext.hex(), # Store as hex string
        "nonce": nonce.hex(), # Store as hex string
        "signature": signed_order.signature, # Use client-provided signature
        "merkle_leaf": merkle_leaf,
        "created_at": datetime.now()
    }

    # Save order to database
    query = orders.insert().values(**order_data_for_db)
    await database.execute(query)
    logger.info(f"Order {signed_order.order.id} placed by {current_user['username']}.")

    trades = matching_engine.match_order(order_data_for_db) # Pass order_data_for_db to matching engine
    
    for trade in trades:
        trade["id"] = str(trade["buy_order_id"]) + "-" + str(trade["sell_order_id"]) # Simple trade ID
        trade["timestamp"] = datetime.now().isoformat()
        trades_log.append(str(trade))
        merkle_tree.add_transaction(str(trade))
        
        # Save trade to database
        query = trades.insert().values(**trade)
        await database.execute(query)
        logger.info(f"Trade {trade['id']} matched for order {signed_order.order.id}.")

        # Add to SSE index (commented out as SSE is managed in main.py)
        # keywords = [order_data_for_db.get('user_id'), order_data_for_db.get('stock'), order_data_for_db.get('side')]
        # keywords = [k for k in keywords if k]
        # sse.add_document(f"trade_{len(trades_log)}", keywords)

        # Encrypt and store price for VWAP (commented out as Paillier is managed in main.py)
        # if 'price' in order_data_for_db and isinstance(order_data_for_db['price'], (int, float)):
        #     encrypted_price = encrypt_value(paillier_public_key, order_data_for_db['price'])
        #     encrypted_prices.append(encrypted_price)

    return {"status": "received", "trades": trades, "merkle_root": merkle_tree.get_root()}

@router.get("/orders", response_model=List[OrderResponse])
async def list_orders(current_user: UserResponse = Depends(get_current_user)):
    query = orders.select().where(orders.c.user_id == current_user["id"])
    user_orders = await database.fetch_all(query)
    
    # Decrypt orders for the current user
    decrypted_orders = []
    for order_record in user_orders:
        # For decryption, we need the AES key used during encryption.
        # In a real system, this key would be securely managed and retrieved.
        # For this MVP, we'll assume a placeholder key or skip decryption for now.
        # Placeholder:
        decrypted_order_data = {
            "id": order_record["id"],
            "user_id": order_record["user_id"],
            "stock": order_record["stock"],
            "side": order_record["side"],
            "qty": order_record["qty"],
            "price": order_record["price"],
            "ciphertext": order_record["ciphertext"],
            "nonce": order_record["nonce"],
            "signature": order_record["signature"],
            "merkle_leaf": order_record["merkle_leaf"],
            "created_at": order_record["created_at"]
        }
        decrypted_orders.append(OrderResponse(**decrypted_order_data))
    
    return decrypted_orders

@router.get("/orders/{order_id}")
async def get_order_detail(order_id: int, current_user: UserResponse = Depends(get_current_user)):
    query = orders.select().where(orders.c.id == order_id, orders.c.user_id == current_user["id"])
    order_record = await database.fetch_one(query)

    if not order_record:
        raise HTTPException(status_code=404, detail="Order not found or not authorized")

    # Generate Merkle proof (placeholder)
    merkle_proof = await MerkleTree([]).prove(order_id) # MerkleTree needs to be initialized with all transactions

    # Decrypt order (placeholder)
    decrypted_order_data = {
        "id": order_record["id"],
        "user_id": order_record["user_id"],
        "stock": order_record["stock"],
        "side": order_record["side"],
        "qty": order_record["qty"],
        "price": order_record["price"],
        "ciphertext": order_record["ciphertext"],
        "nonce": order_record["nonce"],
        "signature": order_record["signature"],
        "merkle_leaf": order_record["merkle_leaf"],
        "created_at": order_record["created_at"]
    }

    return {"order": OrderResponse(**decrypted_order_data), "merkle_proof": merkle_proof}

@router.get("/orderbook/{stock}")
def get_order_book(stock: str):
    return {
        "buy_orders": order_book.buy_orders.get(stock, []),
        "sell_orders": order_book.sell_orders.get(stock, [])
    }