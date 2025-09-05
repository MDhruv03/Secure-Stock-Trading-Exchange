import re
from app.database import database
from app.models import ids_alerts, login_attempts
from sqlalchemy.sql import func
from datetime import datetime, timedelta

# Simple regex patterns for IDS-lite
SQLI_PATTERNS = [
    re.compile(r"'\s*OR\s*'1'='1"),
    re.compile(r"UNION SELECT"),
    re.compile(r"SLEEP\(\d+\)"),
]

BRUTE_FORCE_THRESHOLD = 5 # Max failed attempts
BRUTE_FORCE_WINDOW = 60 # Seconds

async def scan_request_for_ioc(request_data: str) -> list:
    """Scans request data for Indicators of Compromise (IoC) using regex."""
    matches = []
    for pattern in SQLI_PATTERNS:
        if pattern.search(request_data):
            matches.append(f"SQLi pattern detected: {pattern.pattern}")
    return matches

async def rate_limit_key(ip: str, username: str) -> bool:
    """Checks and updates failed login attempts for rate limiting using the database."""
    # Remove old attempts
    cutoff = datetime.utcnow() - timedelta(seconds=BRUTE_FORCE_WINDOW)
    query = login_attempts.delete().where(
        (login_attempts.c.ip_address == ip) &
        (login_attempts.c.username == username) &
        (login_attempts.c.timestamp < cutoff)
    )
    await database.execute(query)

    # Add new attempt
    query = login_attempts.insert().values(ip_address=ip, username=username)
    await database.execute(query)

    # Check attempt count
    query = login_attempts.select().where(
        (login_attempts.c.ip_address == ip) &
        (login_attempts.c.username == username)
    )
    attempts = await database.fetch_all(query)

    if len(attempts) >= BRUTE_FORCE_THRESHOLD:
        await raise_alert(
            alert_type="brute_force",
            description=f"Brute-force attempt detected for user {username} from IP {ip}",
            src_ip=ip,
            raw=f"Failed login attempts: {len(attempts)}"
        )
        return True # Rate limited
    return False # Not rate limited

async def raise_alert(alert_type: str, description: str, src_ip: str = None, dst_ip: str = None, raw: str = None):
    """Raises an IDS alert and stores it in the database."""
    query = ids_alerts.insert().values(
        alert_type=alert_type,
        description=description,
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw=raw,
        created_at=func.now()
    )
    await database.execute(query)
    print(f"IDS Alert: {alert_type} - {description} from {src_ip}")
