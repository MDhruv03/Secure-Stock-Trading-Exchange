
import sys
import os
import uvicorn
import json
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Depends, status, APIRouter
import logging

# Configure logging
logger = logging.getLogger(__name__)

from app.routes.auth import router as auth_router
from app.routes.orders import router as orders_router
from app.routes.analytics import router as analytics_router
from app.routes.logs import router as logs_router
from app.routes.redblue import router as redblue_router
from app.routes.utils import router as utils_router
from app.utils.vulns import router as vulns_router
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import asyncio

# Add the project root to the Python path


from app.exchange import OrderBook, MatchingEngine
from app.crypto.signatures import verify as verify_signature
from app.crypto.encryption import encrypt_order, decrypt_order
from app.crypto.merkle import MerkleTree
from app.common.analytics import generate_paillier_keypair, encrypt_value, decrypt_value, homomorphic_add
from app.utils.sse import SearchableSymmetricEncryption
from app.database import database, metadata, engine
from app.models import users, orders, trades
from app.security import get_password_hash, verify_password, create_access_token, get_current_user
from app.schemas import UserCreate, UserResponse, Token, OrderResponse, TradeResponse, Order, SignedOrder
from app.routes.orders import order_book # Import the order_book instance

app = FastAPI()
app.include_router(auth_router)
app.include_router(orders_router)
app.include_router(analytics_router)
app.include_router(logs_router)
app.include_router(redblue_router)
app.include_router(vulns_router)
app.include_router(utils_router)

# Mount static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

async def periodic_market_simulation():
    while True:
        order_book.simulate_market_activity()
        await asyncio.sleep(5) # Simulate market activity every 5 seconds

@app.on_event("startup")
async def startup():
    await database.connect()
    metadata.create_all(engine)
    asyncio.create_task(periodic_market_simulation())

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()









@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})









if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
