from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import database
from app.models import orders
from app.security import get_current_user
from app.common.analytics import decrypt_value, homomorphic_add, generate_paillier_keypair, encrypt_value
from app.services.charts import vwap_png
import io

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

paillier_public_key, paillier_private_key = generate_paillier_keypair()
encrypted_prices = []

@router.get("/analytics", response_class=HTMLResponse)
async def get_analytics_page(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("analytics.html", {"request": request, "current_user": current_user})

@router.get("/analytics/vwap.png", response_class=Response)
async def get_vwap_chart(current_user: dict = Depends(get_current_user)):
    # Fetch all orders (for simplicity, in a real app, filter by user or time)
    query = orders.select()
    all_orders = await database.fetch_all(query)

    prices = [order["price"] for order in all_orders]
    quantities = [order["qty"] for order in all_orders]

    # Generate the PNG image
    png_image = vwap_png(prices, quantities)

    return Response(content=png_image, media_type="image/png")

@router.get("/vwap")
def get_vwap():
    if not encrypted_prices:
        return {"average_price": 0}

    sum_of_prices_encrypted = homomorphic_add(encrypted_prices)
    sum_of_prices = decrypt_value(paillier_private_key, sum_of_prices_encrypted)
    average_price = sum_of_prices / len(encrypted_prices)

    return {"average_price": average_price}