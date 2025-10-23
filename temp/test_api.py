import requests
import json

print("Testing order book API...")

# Test order book for BTC
try:
    response = requests.get('http://127.0.0.1:8000/api/trading/orderbook/BTC')
    if response.status_code == 200:
        data = response.json()
        print(f"\n✓ Order book API responded successfully")
        print(f"\nBTC Order Book:")
        print(f"  Buy orders: {len(data.get('buy_orders', []))}")
        print(f"  Sell orders: {len(data.get('sell_orders', []))}")
        
        if data.get('buy_orders'):
            print("\n  Top buy orders:")
            for order in data['buy_orders'][:5]:
                print(f"    ${order['price']:.2f} - {order['quantity']} ({order['count']} orders)")
        
        if data.get('sell_orders'):
            print("\n  Top sell orders:")
            for order in data['sell_orders'][:5]:
                print(f"    ${order['price']:.2f} - {order['quantity']} ({order['count']} orders)")
        
        if not data.get('buy_orders') and not data.get('sell_orders'):
            print("\n  ❌ Order book is empty!")
    else:
        print(f"\n❌ API returned status {response.status_code}: {response.text}")
except Exception as e:
    print(f"\n❌ Error calling API: {str(e)}")
    print("Make sure the backend server is running!")

# Test portfolio for user 15
try:
    response = requests.get('http://127.0.0.1:8000/api/data/portfolio/15', 
                           headers={'Authorization': 'Bearer test-token'})
    if response.status_code == 200:
        data = response.json()
        portfolio = data.get('portfolio', [])
        print(f"\n\n✓ Portfolio API responded")
        print(f"Portfolio entries: {len(portfolio)}")
        if portfolio:
            for item in portfolio:
                print(f"  {item}")
        else:
            print("  ❌ Portfolio is empty")
    else:
        print(f"\n❌ Portfolio API returned status {response.status_code}")
except Exception as e:
    print(f"\n❌ Error calling portfolio API: {str(e)}")
