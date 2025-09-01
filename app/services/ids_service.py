import re
from app.database import database
from app.models import ids_alerts
from sqlalchemy.sql import func

# Simple regex patterns for IDS-lite
SQLI_PATTERNS = [
    re.compile(r"'\s*OR\s*'1'='1"),
    re.compile(r"UNION SELECT"),
    re.compile(r"SLEEP\(\d+\)"),
]

BRUTE_FORCE_THRESHOLD = 5 # Max failed attempts
BRUTE_FORCE_WINDOW = 60 # Seconds

# In-memory store for rate limiting (for simplicity in MVP)
failed_login_attempts = {}

async def scan_request_for_ioc(request_data: str) -> list:
    """Scans request data for Indicators of Compromise (IoC) using regex."""
    matches = []
    for pattern in SQLI_PATTERNS:
        if pattern.search(request_data):
            matches.append(f"SQLi pattern detected: {pattern.pattern}")
    return matches

async def rate_limit_key(ip: str, username: str) -> bool:
    """Checks and updates failed login attempts for rate limiting."""
    current_time = func.now()
    if username not in failed_login_attempts:
        failed_login_attempts[username] = []

    # Remove old attempts
    failed_login_attempts[username] = [
        t for t in failed_login_attempts[username] if (current_time - t).total_seconds() < BRUTE_FORCE_WINDOW
    ]

    failed_login_attempts[username].append(current_time)

    if len(failed_login_attempts[username]) >= BRUTE_FORCE_THRESHOLD:
        await raise_alert(
            alert_type="brute_force",
            description=f"Brute-force attempt detected for user {username} from IP {ip}",
            src_ip=ip,
            raw=f"Failed login attempts: {len(failed_login_attempts[username])}"
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