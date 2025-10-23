import sqlite3
from typing import List, Dict, Any

def get_security_events_by_type(event_types: List[str], limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get security events filtered by event type(s)
    """
    try:
        conn = sqlite3.connect('trading_platform.db')
        cursor = conn.cursor()
        
        # Create placeholders for the IN clause
        placeholders = ','.join(['?' for _ in event_types])
        
        cursor.execute(f"""
            SELECT id, event_type, description, source_ip, severity, details, created_at
            FROM security_events
            WHERE event_type IN ({placeholders})
            ORDER BY created_at DESC
            LIMIT ?
        """, (*event_types, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            events.append({
                "id": row[0],
                "event_type": row[1],
                "description": row[2],
                "source_ip": row[3],
                "severity": row[4],
                "details": row[5],
                "created_at": row[6]
            })
        
        return events
    except Exception as e:
        print(f"[DB] Error getting security events by type: {str(e)}")
        return []

# Test the new method
event_types = ["USER_LOGIN", "USER_LOGOUT", "USER_REGISTERED"]
events = get_security_events_by_type(event_types, limit=100)

print(f"Found {len(events)} user activity events (out of 100 requested)")
print("\n" + "=" * 100)
print(f"{'Timestamp':<25} | {'Event Type':<20} | {'Description'}")
print("=" * 100)

# Show first 20 events
for event in events[:20]:
    print(f"{event['created_at']:<25} | {event['event_type']:<20} | {event['description']}")

print("\n" + "=" * 100)

# Show event type breakdown
from collections import Counter
event_counts = Counter([e['event_type'] for e in events])
print("\nEvent Type Breakdown:")
for event_type, count in event_counts.items():
    print(f"  {event_type}: {count}")
