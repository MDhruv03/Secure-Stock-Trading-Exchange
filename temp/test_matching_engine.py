"""
Test Order Matching Engine
"""
import sys
sys.path.append('.')

from backend.app.services.matching_engine import get_matching_engine
from backend.app.utils.database import get_db_manager

print("="*80)
print("ORDER MATCHING ENGINE TEST")
print("="*80)

# Get instances
engine = get_matching_engine()
db = get_db_manager()

# Get current statistics
print("\n1. Current System Statistics:")
stats = engine.get_matching_statistics()
print(f"   Pending Orders: {stats['pending_orders']}")
print(f"   Filled Orders: {stats['filled_orders']}")
print(f"   Total Transactions: {stats['total_transactions']}")
print(f"   Symbols with Pending Orders: {stats['symbols_with_pending']}")

# List symbols with pending orders
print("\n2. Symbols with Pending Orders:")
symbols = db.get_symbols_with_pending_orders()
for symbol in symbols:
    orders = db.get_pending_orders_by_symbol(symbol)
    buy_orders = [o for o in orders if o['side'] == 'BUY']
    sell_orders = [o for o in orders if o['side'] == 'SELL']
    print(f"   {symbol}: {len(buy_orders)} BUY, {len(sell_orders)} SELL")

# Try to match orders for first symbol
if symbols:
    test_symbol = symbols[0]
    print(f"\n3. Attempting to match orders for {test_symbol}:")
    
    # Show order book before matching
    orders = db.get_pending_orders_by_symbol(test_symbol)
    print(f"   Order Book (Before Matching):")
    for order in orders[:5]:
        print(f"      {order['side']:4} {order['quantity']:8.4f} @ ${order['price']:10.2f}")
    
    # Run matching
    executions = engine.match_orders(test_symbol)
    
    if executions:
        print(f"\n   ✓ Executed {len(executions)} trades:")
        for i, exec in enumerate(executions, 1):
            print(f"      Trade {i}: {exec['quantity']} @ ${exec['price']} = ${exec['total_value']:.2f}")
    else:
        print(f"\n   ✗ No matches found (prices don't overlap or insufficient orders)")
    
    # Show order book after matching
    orders_after = db.get_pending_orders_by_symbol(test_symbol)
    print(f"\n   Order Book (After Matching):")
    if orders_after:
        for order in orders_after[:5]:
            filled = order.get('filled_quantity', 0)
            remaining = order['quantity'] - filled
            print(f"      {order['side']:4} {remaining:8.4f} remaining @ ${order['price']:10.2f}")
    else:
        print(f"      (All orders filled!)")
else:
    print("\n✗ No pending orders found in system")

# Get updated statistics
print("\n4. Updated Statistics:")
stats_after = engine.get_matching_statistics()
print(f"   Pending Orders: {stats_after['pending_orders']} (was {stats['pending_orders']})")
print(f"   Filled Orders: {stats_after['filled_orders']} (was {stats['filled_orders']})")
print(f"   Total Transactions: {stats_after['total_transactions']} (was {stats['total_transactions']})")

print("\n" + "="*80)
print("TEST COMPLETE")
print("="*80)
