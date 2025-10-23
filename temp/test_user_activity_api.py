import sqlite3

conn = sqlite3.connect('trading_platform.db')
cursor = conn.cursor()

# Get the 50 most recent events (what the API does)
cursor.execute("""
    SELECT id, event_type, description, created_at 
    FROM security_events 
    ORDER BY created_at DESC 
    LIMIT 50
""")

print("Last 50 Security Events:")
print("-" * 80)

user_activity_count = 0
for row in cursor.fetchall():
    event_id, event_type, description, created_at = row
    if event_type in ["USER_LOGIN", "USER_LOGOUT", "USER_REGISTER", "ORDER_PLACED", "ORDER_EXECUTED"]:
        user_activity_count += 1
        print(f"✓ {created_at} | {event_type:20} | {description[:50]}")
    else:
        print(f"  {created_at} | {event_type:20} | {description[:50]}")

print("\n" + "=" * 80)
print(f"User activity events in last 50: {user_activity_count}")

# Now get ALL user activity events
cursor.execute("""
    SELECT event_type, COUNT(*) as count 
    FROM security_events 
    WHERE event_type IN ('USER_LOGIN', 'USER_LOGOUT', 'USER_REGISTER')
    GROUP BY event_type
""")

print("\nTotal User Activity Events in Database:")
for row in cursor.fetchall():
    print(f"  {row[0]}: {row[1]}")

conn.close()
