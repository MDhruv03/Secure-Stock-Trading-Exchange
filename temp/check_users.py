import sqlite3

print("Checking users in the database...")

conn = sqlite3.connect('trading_platform.db')
cursor = conn.cursor()

# Get all users
cursor.execute("SELECT id, username, created_at, last_login FROM users ORDER BY created_at DESC")
rows = cursor.fetchall()

if len(rows) == 0:
    print("\n❌ No users found in database!")
    print("\nPossible issues:")
    print("1. Registration endpoint is not storing users")
    print("2. Users table might be empty")
else:
    print(f"\n✓ Found {len(rows)} users in database:")
    print("\nID | Username | Created At | Last Login")
    print("-" * 70)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]}")

# Check recent USER_REGISTERED events
cursor.execute("SELECT description, created_at FROM security_events WHERE event_type = 'USER_REGISTERED' ORDER BY created_at DESC LIMIT 5")
reg_events = cursor.fetchall()

if reg_events:
    print(f"\n\nRecent registration events ({len(reg_events)}):")
    for event in reg_events:
        print(f"  {event[0]} at {event[1]}")
else:
    print("\n\n❌ No USER_REGISTERED events found")

conn.close()
