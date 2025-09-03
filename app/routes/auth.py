from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
import logging

from app.database import database
from app.models import users
from app.security import get_password_hash, verify_password, create_access_token, get_current_user
from app.schemas import UserCreate, UserResponse, Token

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate):
    try:
        hashed_password = get_password_hash(user.password)
        query = users.insert().values(username=user.username, password_hash=hashed_password, public_key=user.public_key, private_key=user.private_key, role=user.role)
        last_record_id = await database.execute(query)
        created_user = await database.fetch_one(users.select().where(users.c.id == last_record_id))
        logger.info(f"User '{user.username}' registered successfully with ID: {last_record_id}")
        return UserResponse(**created_user)
    except Exception as e:
        logger.error(f"Error during user registration for '{user.username}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed")

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    query = users.select().where(users.c.username == form_data.username)
    user = await database.fetch_one(query)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    logger.info(f"User '{form_data.username}' logged in successfully.")
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user