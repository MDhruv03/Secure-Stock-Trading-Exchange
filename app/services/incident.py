from app.database import database
from app.models import incidents, blocklist, ids_alerts
from sqlalchemy.sql import func
from fastapi import HTTPException

async def block_ip(ip: str, reason: str = 'IDS match') -> bool:
    """Blocks an IP address by adding it to the blocklist table."""
    try:
        query = blocklist.insert().values(ip=ip, reason=reason, created_at=func.now())
        await database.execute(query)
        print(f"IP {ip} blocked due to: {reason}")
        return True
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")
        return False

async def handle_alert(alert_id: int) -> dict:
    """Handles an IDS alert based on policy (e.g., block SQLi/replay sources)."""
    query = ids_alerts.select().where(ids_alerts.c.id == alert_id)
    alert = await database.fetch_one(query)

    if not alert:
        return {"status": "error", "detail": "Alert not found"}

    action = "ignore"
    result = "N/A"

    if alert["alert_type"] in ["sqli", "replay", "brute_force"] and alert["src_ip"]:
        if await block_ip(alert["src_ip"], f"Automated block for {alert['alert_type']}"):
            action = "block_ip"
            result = "success"
        else:
            result = "failed_to_block"

    query = incidents.insert().values(
        alert_id=alert_id,
        action=action,
        result=result,
        created_at=func.now()
    )
    incident_id = await database.execute(query)
    print(f"Incident recorded for alert {alert_id}: Action={action}, Result={result}")
    return {"status": "success", "incident_id": incident_id, "action": action, "result": result}

async def is_ip_blocked(ip: str) -> bool:
    """Checks if an IP address is in the blocklist."""
    query = blocklist.select().where(blocklist.c.ip == ip)
    blocked_entry = await database.fetch_one(query)
    return blocked_entry is not None

# This middleware would be integrated into FastAPI's middleware stack
# For MVP, we'll just provide the function.
async def blocked_middleware(request):
    """Middleware to deny requests from blocked IP addresses."""
    client_ip = request.client.host
    if await is_ip_blocked(client_ip):
        raise HTTPException(status_code=403, detail=f"IP address {client_ip} is blocked.")
    return True # Allow request to proceed