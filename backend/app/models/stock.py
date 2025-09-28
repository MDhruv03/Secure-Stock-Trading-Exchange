"""
Stock model for the Secure Trading Platform
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class StockBase(BaseModel):
    symbol: str
    name: str
    current_price: float


class StockCreate(StockBase):
    pass


class StockUpdate(BaseModel):
    current_price: Optional[float] = None
    market_cap: Optional[float] = None


class StockInDB(StockBase):
    id: int
    market_cap: Optional[float] = None
    created_at: Optional[datetime] = None


class StockPublic(StockBase):
    id: int
    market_cap: Optional[float] = None