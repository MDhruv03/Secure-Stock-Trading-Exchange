
from datetime import datetime, timedelta
from typing import Optional
import logging

logger = logging.getLogger(__name__)

from jose import JWTError, jwt
from passlib.context import CryptContext

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.database import database
from app.models import users
from dotenv import load_dotenv
load_dotenv()  # loads .env automatically



import os

# Configuration for JWT
SECRET_KEY = os.environ.get("SECRET_KEY")
logger.debug(f"SECRET_KEY loaded: {SECRET_KEY[:5]}...{SECRET_KEY[-5:]}") # Log partial key for security
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable not set.")
    raise ValueError("SECRET_KEY environment variable not set. This is required for JWT security.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.error(f"JWTError during token decoding: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# This will be used as a dependency to get the current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    logger.debug(f"Attempting to get current user. Token received: {token[:10]}...")
    payload = decode_access_token(token)
    logger.debug(f"Token decoded. Payload: {payload}")
    username: str = payload.get("sub")
    if username is None:
        logger.warning("Attempt to get current user with no username in token payload.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    if user is None:
        logger.warning(f"User '{username}' not found in database.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

async def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    logger.debug(f"Current user in get_current_admin_user: {current_user}")
    if current_user["role"] != "admin":
        logger.warning(f"User '{current_user['username']}' attempted to access admin resource without admin role.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user
