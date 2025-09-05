from app.database import database
from app.models import incidents, ids_alerts
from sqlalchemy.sql import func

async def create_incident_from_alert(alert_id: int):
    """Creates an incident from an alert and assigns it to an analyst."""
    query = ids_alerts.select().where(ids_alerts.c.id == alert_id)
    alert = await database.fetch_one(query)

    if not alert:
        return

    # In a real system, this would assign to a specific analyst
    # or a queue.
    action = f"Investigate {alert['alert_type']} alert for IP {alert['src_ip']}"

    query = incidents.insert().values(
        alert_id=alert_id,
        action=action,
        result="pending",
        created_at=func.now()
    )
    await database.execute(query)
    print(f"Incident created for alert {alert_id}")