from fastapi import APIRouter, Depends, HTTPException, status
import logging

logger = logging.getLogger(__name__)

from app.database import database
from app.models import orders, trades, users, merkle_trades, encrypted_vwap
from app.security import get_current_user, get_current_admin_user,used_nonces
from app.schemas import UserResponse, OrderResponse, SignedOrder, TradeResponse, MerkleProof,Order
from app.crypto.signatures import verify as verify_signature
from app.crypto.encryption import encrypt_order, decrypt_order
from app.crypto.merkle import MerkleTree
from app.crypto.he import generate_paillier_keypair, paillier_encrypt
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

# Initialize trades_log from the database
trades_log = []
merkle_tree = MerkleTree(trades_log)

# Generate Paillier key pair
paillier_public_key, paillier_private_key = generate_paillier_keypair()

@router.on_event("startup")
async def startup():
    query = merkle_trades.select()
    db_trades = await database.fetch_all(query)
    for trade in db_trades:
        trades_log.append(trade["trade_data"])
    global merkle_tree
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
        trade_str = str(trade)
        trades_log.append(trade_str)
        merkle_tree.add_transaction(trade_str)
        
        # Save trade to database
        query = trades.insert().values(**trade)
        await database.execute(query)
        # Save trade to merkle_trades table
        query = merkle_trades.insert().values(trade_data=trade_str)
        await database.execute(query)
        logger.info(f"Trade {trade['id']} matched for order {signed_order.order.id}.")

        # Encrypt and store price and quantity for VWAP
        encrypted_price = paillier_encrypt(int(trade["price"] * 100), paillier_public_key)
        encrypted_quantity = paillier_encrypt(trade["amount"], paillier_public_key)
        query = encrypted_vwap.insert().values(encrypted_price=str(encrypted_price), encrypted_quantity=str(encrypted_quantity))
        await database.execute(query)

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

    # Find the trade associated with this order
    trade_query = trades.select().where((trades.c.buy_order_id == str(order_id)) | (trades.c.sell_order_id == str(order_id)))
    trade_record = await database.fetch_one(trade_query)

    merkle_proof = None
    if trade_record:
        trade_str = str(dict(trade_record))
        merkle_proof = merkle_tree.get_proof(trade_str)

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
        "created_at": order_record["created_at"]
    }

    return {"order": OrderResponse(**decrypted_order_data), "merkle_proof": merkle_proof}

@router.post("/verify_trade")
async def verify_trade(proof: MerkleProof):
    is_valid = merkle_tree.verify_transaction(proof.transaction, proof.proof, proof.root)
    return {"is_valid": is_valid}

@router.get("/orderbook/{stock}")
def get_order_book(stock: str):
    return {
        "buy_orders": order_book.buy_orders.get(stock, []),
        "sell_orders": order_book.sell_orders.get(stock, [])
    }

@router.post("/orders/new_with_nonce")
async def place_order_with_nonce(order: Order, current_user: dict = Depends(get_current_user)):
    if order.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Replay attack detected")
    used_nonces.add(order.nonce)

    logger.info(f"User '{current_user['username']}' attempting to place order: {order.dict()}")
    # In a real app, we would look up the public key based on the user_id
    # For now, we accept the public key in the request
    # Generate a random AES key for order encryption
    aes_key = os.urandom(16) # 128-bit key

    # Encrypt the order details
    order_to_encrypt = {
        "id": order.id,
        "user_id": current_user["id"],
        "stock": order.stock,
        "side": order.side,
        "qty": order.qty,
        "price": order.price
    }
    ciphertext, nonce, tag, header = encrypt_order(order_to_encrypt, aes_key)

    order_data_for_db = {
        "id": order.id,
        "user_id": current_user["id"],
        "stock": order.stock,
        "qty": order.qty,
        "side": order.side,
        "price": order.price,
        "ciphertext": ciphertext.hex(), # Store as hex string
        "nonce": nonce.hex(), # Store as hex string
        "signature": "", # No signature for this endpoint
        "created_at": datetime.now()
    }

    # Save order to database
    query = orders.insert().values(**order_data_for_db)
    await database.execute(query)
    logger.info(f"Order {order.id} placed by {current_user['username']}.")

    order_for_matching_engine = order_data_for_db.copy()
    order_for_matching_engine["amount"] = order.qty
    order_for_matching_engine["type"] = order.side
    order_for_matching_engine["asset"] = order.stock

    trades = matching_engine.match_order(order_for_matching_engine) # Pass order_data_for_db to matching engine
    
    for trade in trades:
        trade["id"] = str(trade["buy_order_id"]) + "-" + str(trade["sell_order_id"]) # Simple trade ID
        trade["timestamp"] = datetime.now().isoformat()
        trade_str = str(trade)
        trades_log.append(trade_str)
        merkle_tree.add_transaction(trade_str)
        
        # Save trade to database
        query = trades.insert().values(**trade)
        await database.execute(query)
        # Save trade to merkle_trades table
        query = merkle_trades.insert().values(trade_data=trade_str)
        await database.execute(query)
        logger.info(f"Trade {trade['id']} matched for order {order.id}.")

        # Encrypt and store price and quantity for VWAP
        encrypted_price = paillier_encrypt(int(trade["price"] * 100), paillier_public_key)
        encrypted_quantity = paillier_encrypt(trade["amount"], paillier_public_key)
        query = encrypted_vwap.insert().values(encrypted_price=str(encrypted_price), encrypted_quantity=str(encrypted_quantity))
        await database.execute(query)

    return {"status": "received", "trades": trades, "merkle_root": merkle_tree.get_root()}
