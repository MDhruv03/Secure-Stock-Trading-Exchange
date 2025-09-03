from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.security import get_current_user, get_current_admin_user
from app.services.ids_service import raise_alert, scan_request_for_ioc, rate_limit_key
from app.services.incident import handle_alert, block_ip
import json
import asyncio

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/sim", response_class=HTMLResponse)
async def get_sim_page(request: Request, current_user: dict = Depends(get_current_admin_user)):
    return templates.TemplateResponse("redblue.html", {"request": request, "current_user": current_user})

@router.post("/sim/sqlmap")
async def run_sqlmap_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    steps.append({"actor": "Red Team", "action": "Initiating simulated SQL injection attack..."})
    attack_payload = "test' OR '1'='1"
    steps.append({"actor": "Red Team", "action": f"Using payload: {attack_payload}"})

    steps.append({"actor": "Blue Team", "action": "Scanning request for Indicators of Compromise (IOCs)..."})
    matches = await scan_request_for_ioc(attack_payload)
    if matches:
        steps.append({"actor": "Blue Team", "action": f"IOCs detected: {matches}"})
        alert_id = await raise_alert(
            alert_type="sqli",
            description=f"Simulated SQLi attack detected with payload: {attack_payload}",
            src_ip=request.client.host,
            raw=attack_payload
        )
        steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}"})
        if alert_id:
            await handle_alert(alert_id)
            steps.append({"actor": "Blue Team", "action": "Incident response initiated."})
        return {"status": "success", "steps": steps}
    else:
        steps.append({"actor": "Blue Team", "action": "No IOCs detected."})
        return {"status": "failed", "steps": steps}

@router.post("/sim/bruteforce")
async def run_bruteforce_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    try:
        steps.append({"actor": "Red Team", "action": "Initiating simulated brute-force attack..."})
        ip = request.client.host
        username = "test_user"
        steps.append({"actor": "Red Team", "action": f"Simulating multiple failed login attempts for user: {username}"})

        steps.append({"actor": "Blue Team", "action": "Monitoring login attempts..."})
        for i in range(6):
            await rate_limit_key(ip, username)
            steps.append({"actor": "Blue Team", "action": f"Failed login attempt {i+1} detected."})
            await asyncio.sleep(0.1)

        steps.append({"actor": "Blue Team", "action": "Rate limit exceeded. Blocking IP."})
        alert_id = await raise_alert(
            alert_type="bruteforce",
            description=f"Simulated brute-force attack detected for user: {username}",
            src_ip=ip,
            raw=f"username={username}"
        )
        steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}"})
        if alert_id:
            await handle_alert(alert_id)
            steps.append({"actor": "Blue Team", "action": "Incident response initiated."})

        return {"status": "success", "steps": steps}
    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {e}"}

@router.post("/sim/replay")
async def run_replay_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    steps.append({"actor": "Red Team", "action": "Initiating simulated replay attack..."})
    steps.append({"actor": "Red Team", "action": "Replaying a captured request."})

    steps.append({"actor": "Blue Team", "action": "Detecting replayed request..."})
    alert_id = await raise_alert(
        alert_type="replay",
        description="Simulated replay attack detected.",
        src_ip=request.client.host,
        raw="Replayed request data"
    )
    steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}"})
    if alert_id:
        await handle_alert(alert_id)
        steps.append({"actor": "Blue Team", "action": "Incident response initiated."})

    return {"status": "success", "steps": steps}

@router.post("/sim/mitm")
async def run_mitm_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    steps.append({"actor": "Red Team", "action": "Initiating simulated MITM attack..."})
    steps.append({"actor": "Red Team", "action": "Tampering with data in transit."})

    steps.append({"actor": "Blue Team", "action": "Detecting data tampering..."})
    alert_id = await raise_alert(
        alert_type="mitm",
        description="Simulated MITM attack detected (data tampering).",
        src_ip=request.client.host,
        raw="Tampered data"
    )
    steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}"})
    if alert_id:
        await handle_alert(alert_id)
        steps.append({"actor": "Blue Team", "action": "Incident response initiated."})

    return {"status": "success", "steps": steps}