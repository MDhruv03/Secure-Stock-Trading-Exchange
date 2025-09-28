"""
Order model for the Secure Trading Platform
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum


class OrderSide(str, Enum):
    BUY = "buy"
    SELL = "sell"


class OrderType(str, Enum):
    MARKET = "MARKET"
    LIMIT = "LIMIT"
    STOP = "STOP"


class OrderStatus(str, Enum):
    PENDING = "PENDING"
    FILLED = "FILLED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"


class OrderBase(BaseModel):
    symbol: str
    side: OrderSide
    order_type: OrderType = OrderType.MARKET
    quantity: float
    price: float


class OrderCreate(OrderBase):
    pass


class OrderUpdate(BaseModel):
    status: Optional[OrderStatus] = None
    filled_quantity: Optional[float] = None


class OrderInDB(OrderBase):
    id: int
    user_id: int
    status: OrderStatus = OrderStatus.PENDING
    filled_quantity: float = 0.0
    encrypted_data: str
    signature: str
    merkle_leaf: str
    nonce: str
    tag: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class OrderPublic(OrderBase):
    id: int
    status: OrderStatus
    filled_quantity: float
    created_at: Optional[datetime] = None