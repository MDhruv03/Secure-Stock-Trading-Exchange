"""
User model for the Secure Trading Platform
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    TRADER = "trader"
    ADMIN = "admin"
    MODERATOR = "moderator"


class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserChangePassword(BaseModel):
    old_password: str
    new_password: str


class UserInDB(UserBase):
    id: int
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    balance: float = 10000.00
    is_active: bool = True
    role: UserRole = UserRole.TRADER


class UserPublic(UserBase):
    id: int
    balance: float
    is_active: bool = True
    role: UserRole = UserRole.TRADER