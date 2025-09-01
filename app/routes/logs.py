from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import database
from app.models import ids_alerts, incidents, merkle_roots
from app.security import get_current_user
from typing import Optional

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/logs", response_class=HTMLResponse)
async def get_logs_page(request: Request, current_user: dict = Depends(get_current_user)):
    # Fetch IDS alerts
    alerts_query = ids_alerts.select().order_by(ids_alerts.c.created_at.desc()).limit(100)
    alerts = await database.fetch_all(alerts_query)

    # Fetch incidents
    incidents_query = incidents.select().order_by(incidents.c.created_at.desc()).limit(100)
    incidents_data = await database.fetch_all(incidents_query)

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "current_user": current_user,
        "alerts": alerts,
        "incidents": incidents_data
    })

@router.get("/logs/merkle", response_class=HTMLResponse)
async def get_merkle_logs_page(request: Request, current_user: dict = Depends(get_current_user)):
    # Fetch Merkle roots
    merkle_roots_query = merkle_roots.select().order_by(merkle_roots.c.created_at.desc()).limit(100)
    roots = await database.fetch_all(merkle_roots_query)

    return templates.TemplateResponse("merkle_logs.html", {
        "request": request,
        "current_user": current_user,
        "merkle_roots": roots
    })