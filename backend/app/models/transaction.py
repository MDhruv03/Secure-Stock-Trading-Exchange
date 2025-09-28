"""
Transaction model for the Secure Trading Platform
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum
from .order import OrderSide


class TransactionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"


class TransactionBase(BaseModel):
    order_id: int
    user_id: int
    symbol: str
    side: OrderSide
    quantity: float
    price: float
    total_value: float
    status: TransactionStatus = TransactionStatus.SUCCESS


class TransactionCreate(TransactionBase):
    encrypted_data: str
    signature: str
    merkle_leaf: str


class TransactionInDB(TransactionBase):
    id: int
    encrypted_data: str
    signature: str
    merkle_leaf: str
    executed_at: Optional[datetime] = None


class TransactionPublic(TransactionBase):
    id: int
    executed_at: Optional[datetime] = None