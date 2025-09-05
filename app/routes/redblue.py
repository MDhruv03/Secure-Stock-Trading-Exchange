from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.security import get_current_admin_user, try_login
from app.services.ids_service import raise_alert, scan_request_for_ioc
from app.blue_team.incident_response import create_incident_from_alert
from app.red_team.sqli_attack import get_sqli_payload
from app.red_team.brute_force_attack import get_brute_force_passwords
from app.red_team.replay_attack import get_replay_order_data
from app.routes.orders import place_order_with_nonce
from app.schemas import Order
import time
import uuid

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/sim", response_class=HTMLResponse)
async def get_sim_page(request: Request, current_user: dict = Depends(get_current_admin_user)):
    return templates.TemplateResponse("redblue.html", {"request": request, "current_user": current_user})

@router.post("/sim/sqlmap")
async def run_sqlmap_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    steps.append({"actor": "Red Team", "action": "Initiating simulated SQL injection attack...", "timestamp": time.time()})
    
    payload = get_sqli_payload()
    steps.append({"actor": "Red Team", "action": f"Using payload: {payload}", "timestamp": time.time()})

    steps.append({"actor": "Blue Team", "action": "Scanning request for Indicators of Compromise (IOCs)...", "timestamp": time.time()})
    matches = await scan_request_for_ioc(payload)
    if matches:
        steps.append({"actor": "Blue Team", "action": f"IOCs detected: {matches}", "timestamp": time.time()})
        alert_id = await raise_alert(
            alert_type="sqli",
            description=f"Simulated SQLi attack detected with payload: {payload}",
            src_ip=request.client.host,
            raw=payload
        )
        steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}", "timestamp": time.time()})
        if alert_id:
            await create_incident_from_alert(alert_id)
            steps.append({"actor": "Blue Team", "action": "Incident response initiated.", "timestamp": time.time()})
        return {"status": "success", "steps": steps}
    else:
        steps.append({"actor": "Blue Team", "action": "No IOCs detected.", "timestamp": time.time()})
        return {"status": "failed", "steps": steps}

@router.post("/sim/bruteforce")
async def run_bruteforce_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    steps.append({"actor": "Red Team", "action": "Initiating simulated brute-force attack...", "timestamp": time.time()})
    
    passwords = get_brute_force_passwords()
    username = "admin"

    for password in passwords:
        steps.append({"actor": "Red Team", "action": f"Attempting password: {password}", "timestamp": time.time()})
        if await try_login(username, password):
            steps.append({"actor": "Red Team", "action": f"Success! Password found: {password}", "timestamp": time.time()})
            steps.append({"actor": "Blue Team", "action": "Brute-force attack successful.", "timestamp": time.time()})
            return {"status": "success", "steps": steps}
        else:
            steps.append({"actor": "Blue Team", "action": "Login attempt failed.", "timestamp": time.time()})

    steps.append({"actor": "Blue Team", "action": "Brute-force attack failed.", "timestamp": time.time()})
    return {"status": "failed", "steps": steps}

from datetime import datetime

@router.post("/sim/replay")
async def run_replay_sim(request: Request, current_user: dict = Depends(get_current_admin_user)):
    steps = []
    try:
        steps.append({"actor": "Red Team", "action": "Initiating simulated replay attack...", "timestamp": time.time()})
        
        order_data = get_replay_order_data()
        order_data["id"] = int(time.time())
        order_data["user_id"] = current_user["id"]
        order_data["price"] = 100.0
        order_data["ciphertext"] = ""
        order_data["signature"] = ""
        order_data["nonce"] = str(uuid.uuid4())
        order_data["created_at"] = datetime.now()
        order = Order(**order_data)

        # First request
        steps.append({"actor": "Red Team", "action": "Sending original order...", "timestamp": time.time()})
        try:
            await place_order_with_nonce(order, current_user)
            steps.append({"actor": "Blue Team", "action": "Original order placed successfully.", "timestamp": time.time()})
        except HTTPException as e:
            steps.append({"actor": "Blue Team", "action": f"Original order failed: {e.detail}", "timestamp": time.time()})
            return {"status": "failed", "steps": steps}

        # Replay request
        steps.append({"actor": "Red Team", "action": "Replaying the same order...", "timestamp": time.time()})
        try:
            await place_order_with_nonce(order, current_user)
            steps.append({"actor": "Blue Team", "action": "Replay attack successful.", "timestamp": time.time()})
            return {"status": "failed", "steps": steps}
        except HTTPException as e:
            if e.status_code == 400 and "Replay attack detected" in e.detail:
                steps.append({"actor": "Blue Team", "action": "Replay attack detected and blocked.", "timestamp": time.time()})
                alert_id = await raise_alert(
                    alert_type="replay",
                    description="Simulated replay attack detected.",
                    src_ip=request.client.host,
                    raw=str(order_data)
                )
                steps.append({"actor": "Blue Team", "action": f"Alert raised with ID: {alert_id}", "timestamp": time.time()})
                if alert_id:
                    await create_incident_from_alert(alert_id)
                    steps.append({"actor": "Blue Team", "action": "Incident response initiated.", "timestamp": time.time()})
                return {"status": "success", "steps": steps}
            else:
                steps.append({"actor": "Blue Team", "action": f"Replay failed with unexpected error: {e.detail}", "timestamp": time.time()})
                return {"status": "failed", "steps": steps}
    except Exception as e:
        steps.append({"actor": "System", "action": f"An unexpected error occurred: {e}", "timestamp": time.time()})
        return {"status": "failed", "steps": steps, "error": str(e)}
