import sqlite3

# First, delete existing check file
import os
if os.path.exists('check_logs.py'):
    os.remove('check_logs.py')

print("Testing logout logging fix...")
print("\nBefore fix - checking for logout events:")

conn = sqlite3.connect('trading_platform.db')
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'USER_LOGOUT'")
count = cursor.fetchone()[0]
print(f"USER_LOGOUT events in database: {count}")

if count == 0:
    print("\n❌ No logout events found. The issue confirmed.")
    print("\nTo test the fix:")
    print("1. Restart the backend server")
    print("2. Log in to the application")
    print("3. Click the logout button")
    print("4. Run this script again to verify logout events are being logged")
else:
    print(f"\n✓ Found {count} logout events")
    cursor.execute("SELECT description, created_at FROM security_events WHERE event_type = 'USER_LOGOUT' ORDER BY created_at DESC LIMIT 5")
    rows = cursor.fetchall()
    print("\nRecent logout events:")
    for row in rows:
        print(f"  {row[0]} at {row[1]}")

conn.close()
