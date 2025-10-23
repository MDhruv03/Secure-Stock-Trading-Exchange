import sqlite3

print("Checking orders and portfolio data...")

conn = sqlite3.connect('trading_platform.db')
cursor = conn.cursor()

# Check orders
cursor.execute("SELECT COUNT(*) FROM orders")
order_count = cursor.fetchone()[0]
print(f"\n✓ Total orders in database: {order_count}")

if order_count > 0:
    cursor.execute("""
        SELECT id, user_id, symbol, side, order_type, quantity, price, status, created_at 
        FROM orders 
        ORDER BY created_at DESC 
        LIMIT 10
    """)
    rows = cursor.fetchall()
    print("\nRecent orders:")
    print("ID | User | Symbol | Side | Type | Qty | Price | Status | Created")
    print("-" * 90)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} | {row[7]} | {row[8]}")
else:
    print("\n❌ No orders found! Orders are not being created.")

# Check portfolio
cursor.execute("SELECT COUNT(*) FROM portfolio")
portfolio_count = cursor.fetchone()[0]
print(f"\n✓ Total portfolio entries: {portfolio_count}")

if portfolio_count > 0:
    cursor.execute("""
        SELECT id, user_id, symbol, quantity, avg_buy_price, updated_at
        FROM portfolio
        ORDER BY updated_at DESC
        LIMIT 10
    """)
    rows = cursor.fetchall()
    print("\nRecent portfolio entries:")
    print("ID | User | Symbol | Quantity | Avg Price | Updated")
    print("-" * 70)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | {row[5]}")
else:
    print("\n❌ No portfolio entries found!")

# Check stocks table
cursor.execute("SELECT COUNT(*) FROM stocks")
stock_count = cursor.fetchone()[0]
print(f"\n✓ Total stocks in database: {stock_count}")

if stock_count > 0:
    cursor.execute("SELECT symbol, name, current_price FROM stocks LIMIT 5")
    rows = cursor.fetchall()
    print("\nAvailable stocks:")
    for row in rows:
        print(f"  {row[0]} - {row[1]} @ ${row[2]}")
else:
    print("\n❌ No stocks found! Need to populate stocks table.")

conn.close()
