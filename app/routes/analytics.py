from fastapi import APIRouter, Depends, Request, Response
import logging

logger = logging.getLogger(__name__)

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import database
from app.models import encrypted_vwap, orders, trades, users
from app.security import get_current_user, get_current_admin_user
from app.crypto.he import paillier_decrypt
from app.routes.orders import paillier_public_key, paillier_private_key
import io
from collections import Counter
from datetime import datetime

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/analytics", response_class=HTMLResponse)
async def get_analytics_page(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.debug(f"Accessing analytics page. Current user: {current_user['username']}")
    return templates.TemplateResponse("analytics.html", {"request": request, "current_user": current_user})

@router.get("/analytics/vwap-data")
async def get_vwap_data(current_user: dict = Depends(get_current_admin_user)):
    query = encrypted_vwap.select()
    encrypted_data = await database.fetch_all(query)

    if not encrypted_data:
        return {"labels": [], "vwap": []}

    encrypted_prices = [int(row["encrypted_price"]) for row in encrypted_data]
    encrypted_quantities = [int(row["encrypted_quantity"]) for row in encrypted_data]

    # Homomorphically add the encrypted prices and quantities
    sum_encrypted_prices = encrypted_prices[0]
    for i in range(1, len(encrypted_prices)):
        sum_encrypted_prices = (sum_encrypted_prices * encrypted_prices[i]) % (paillier_public_key[0] ** 2)

    sum_encrypted_quantities = encrypted_quantities[0]
    for i in range(1, len(encrypted_quantities)):
        sum_encrypted_quantities = (sum_encrypted_quantities * encrypted_quantities[i]) % (paillier_public_key[0] ** 2)

    # Decrypt the sums
    total_price = paillier_decrypt(sum_encrypted_prices, paillier_public_key, paillier_private_key) / 100
    total_quantity = paillier_decrypt(sum_encrypted_quantities, paillier_public_key, paillier_private_key)

    # Calculate VWAP
    vwap = total_price / total_quantity if total_quantity else 0

    return {"labels": list(range(len(encrypted_data))), "vwap": [vwap] * len(encrypted_data)}

@router.get("/analytics/order-distribution")
async def get_order_distribution(current_user: dict = Depends(get_current_admin_user)):
    query = orders.select()
    all_orders = await database.fetch_all(query)
    stock_counts = Counter(order["stock"] for order in all_orders)
    return {"labels": list(stock_counts.keys()), "data": list(stock_counts.values())}

@router.get("/analytics/trade-volume")
async def get_trade_volume(current_user: dict = Depends(get_current_admin_user)):
    query = trades.select().order_by(trades.c.timestamp)
    all_trades = await database.fetch_all(query)
    trade_counts = Counter(datetime.fromisoformat(trade["timestamp"]).strftime('%Y-%m-%d') for trade in all_trades)
    return {"labels": list(trade_counts.keys()), "data": list(trade_counts.values())}

@router.get("/analytics/user-activity")
async def get_user_activity(current_user: dict = Depends(get_current_admin_user)):
    query = users.select().order_by(users.c.created_at)
    all_users = await database.fetch_all(query)
    user_counts = Counter(user["created_at"].strftime('%Y-%m-%d') for user in all_users)
    return {"labels": list(user_counts.keys()), "data": list(user_counts.values())}