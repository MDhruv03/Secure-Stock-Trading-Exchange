from fastapi import APIRouter, Depends, Request, Response
import logging

logger = logging.getLogger(__name__)

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import database
from app.models import orders
from app.security import get_current_user, get_current_admin_user
from app.common.analytics import decrypt_value, homomorphic_add, generate_paillier_keypair, encrypt_value
from app.services.charts import vwap_png
import io

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

paillier_public_key, paillier_private_key = generate_paillier_keypair()
encrypted_prices = []

@router.get("/analytics", response_class=HTMLResponse)
async def get_analytics_page(request: Request, current_user: dict = Depends(get_current_admin_user)):
    logger.debug(f"Accessing analytics page. Current user: {current_user['username']}")
    return templates.TemplateResponse("analytics.html", {"request": request, "current_user": current_user})

@router.get("/analytics/vwap-data")
async def get_vwap_data(current_user: dict = Depends(get_current_admin_user)):
    # Fetch all orders (for simplicity, in a real app, filter by user or time)
    query = orders.select()
    all_orders = await database.fetch_all(query)

    prices = [order["price"] for order in all_orders]
    quantities = [order["qty"] for order in all_orders]

    # Calculate VWAP
    vwap_values = []
    cumulative_price_x_quantity = 0
    cumulative_quantity = 0
    for price, quantity in zip(prices, quantities):
        cumulative_price_x_quantity += price * quantity
        cumulative_quantity += quantity
        vwap = cumulative_price_x_quantity / cumulative_quantity if cumulative_quantity else 0
        vwap_values.append(vwap)

    return {"labels": list(range(len(all_orders))), "vwap": vwap_values}

@router.get("/vwap")
def get_vwap():
    if not encrypted_prices:
        return {"average_price": 0}

    sum_of_prices_encrypted = homomorphic_add(encrypted_prices)
    sum_of_prices = decrypt_value(paillier_private_key, sum_of_prices_encrypted)
    average_price = sum_of_prices / len(encrypted_prices)

    return {"average_price": average_price}