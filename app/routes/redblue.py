from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.security import get_current_user
from app.services.ids_service import raise_alert, scan_request_for_ioc, rate_limit_key
from app.services.incident import handle_alert, block_ip
import json
import asyncio

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/sim", response_class=HTMLResponse)
async def get_sim_page(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("redblue.html", {"request": request, "current_user": current_user})

@router.post("/sim/sqlmap")
async def run_sqlmap_sim(request: Request, current_user: dict = Depends(get_current_user)):
    # Simulate a SQLi attack
    attack_payload = "test' OR '1'='1"
    
    # Simulate IDS detection
    matches = await scan_request_for_ioc(attack_payload)
    if matches:
        alert_id = await raise_alert(
            alert_type="sqli",
            description=f"Simulated SQLi attack detected with payload: {attack_payload}",
            src_ip=request.client.host,
            raw=attack_payload
        )
        if alert_id:
            await handle_alert(alert_id)
        return {"status": "success", "message": "Simulated SQLi attack detected and handled."}
    return {"status": "failed", "message": "Simulated SQLi attack not detected."}

@router.post("/sim/bruteforce")
async def run_bruteforce_sim(request: Request, current_user: dict = Depends(get_current_user)):
    # Simulate multiple failed login attempts
    ip = request.client.host
    username = "test_user"
    
    # Simulate 6 failed attempts to trigger rate limit
    for i in range(6):
        await rate_limit_key(ip, username)
        await asyncio.sleep(0.1) # Small delay

    return {"status": "success", "message": "Simulated brute-force attack. Check logs for alerts."}

@router.post("/sim/replay")
async def run_replay_sim(request: Request, current_user: dict = Depends(get_current_user)):
    # Simulate a replay attack
    # In a real scenario, this would involve re-submitting a captured legitimate request
    # For MVP, we'll just raise an alert.
    alert_id = await raise_alert(
        alert_type="replay",
        description="Simulated replay attack detected.",
        src_ip=request.client.host,
        raw="Replayed request data"
    )
    if alert_id:
        await handle_alert(alert_id)
    return {"status": "success", "message": "Simulated replay attack detected and handled."}

@router.post("/sim/mitm")
async def run_mitm_sim(request: Request, current_user: dict = Depends(get_current_user)):
    # Simulate a MITM attack (e.g., tampering with data)
    # For MVP, we'll just raise an alert.
    alert_id = await raise_alert(
        alert_type="mitm",
        description="Simulated MITM attack detected (data tampering).",
        src_ip=request.client.host,
        raw="Tampered data"
    )
    if alert_id:
        await handle_alert(alert_id)
    return {"status": "success", "message": "Simulated MITM attack detected and handled."}