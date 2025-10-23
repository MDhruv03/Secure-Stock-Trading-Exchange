import sqlite3
from datetime import datetime

conn = sqlite3.connect('trading_platform.db')
cursor = conn.cursor()

# Check recent user activity logs
cursor.execute("""
    SELECT event_type, description, created_at, details 
    FROM security_events 
    WHERE event_type IN ('USER_LOGIN', 'USER_LOGOUT', 'USER_REGISTERED') 
    ORDER BY created_at DESC 
    LIMIT 20
""")

results = cursor.fetchall()

print("Recent User Activity Logs:")
print("-" * 100)
print(f"{'Timestamp':<25} | {'Event Type':<20} | {'Description'}")
print("-" * 100)

for row in results:
    event_type, description, created_at, details = row
    print(f"{created_at:<25} | {event_type:<20} | {description}")

print("\n" + "=" * 100)

# Check all user activity counts
cursor.execute("""
    SELECT event_type, COUNT(*) as count 
    FROM security_events 
    WHERE event_type IN ('USER_LOGIN', 'USER_LOGOUT', 'USER_REGISTERED') 
    GROUP BY event_type
""")

print("\nUser Activity Summary:")
print("-" * 40)
for row in cursor.fetchall():
    print(f"{row[0]}: {row[1]}")

conn.close()
