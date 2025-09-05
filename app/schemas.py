from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from typing import Optional

class UserCreate(BaseModel):
    username: str
    password: str
    public_key: str
    private_key: Optional[str] = None
    role: Optional[str] = "customer"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    balance: float
    public_key: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Order(BaseModel): # Moved from main.py
    id: int # Changed to int
    user_id: int # Renamed from trader_id
    stock: str # Renamed from asset
    side: str # 'buy' or 'sell', renamed from type
    qty: int # Renamed from amount, changed to int
    price: float
    ciphertext: str # Added
    nonce: str # Added
    signature: str # Added
    created_at: datetime # Added

class SignedOrder(BaseModel): # Moved from main.py
    order: Order
    signature: str
    public_key: str

class OrderResponse(BaseModel):
    id: int # Changed to int
    user_id: int # Renamed from trader_id
    stock: str # Renamed from asset
    side: str # Renamed from type
    qty: int # Renamed from amount
    price: float
    ciphertext: str # Added
    nonce: str # Added
    signature: str # Added
    created_at: datetime # Added

    class Config:
        orm_mode = True

class TradeResponse(BaseModel):
    id: str
    buy_order_id: str
    sell_order_id: str
    price: float
    amount: float
    timestamp: str

    class Config:
        orm_mode = True

class MerkleProof(BaseModel):
    transaction: str
    proof: list
    root: str