
from collections import defaultdict
import random
import uuid

class OrderBook:
    def __init__(self):
        self.buy_orders = defaultdict(list)
        self.sell_orders = defaultdict(list)

    def add_order(self, order):
        if order['type'] == 'buy':
            self.buy_orders[order['asset']].append(order)
            self.buy_orders[order['asset']].sort(key=lambda x: x['price'], reverse=True)
        else:
            self.sell_orders[order['asset']].append(order)
            self.sell_orders[order['asset']].sort(key=lambda x: x['price'])

    def simulate_market_activity(self):
        assets = ["BTC", "ETH", "XRP"]
        for _ in range(random.randint(1, 3)): # Add 1-3 new orders per simulation
            asset = random.choice(assets)
            order_type = random.choice(["buy", "sell"])
            amount = round(random.uniform(0.01, 5.0), 2)
            price = round(random.uniform(1000.0, 50000.0), 2)

            new_order = {
                "id": str(uuid.uuid4()),
                "user_id": "simulated_user", # Placeholder user
                "stock": asset,
                "asset": asset, # For consistency with frontend
                "qty": amount,
                "amount": amount, # For consistency with frontend
                "side": order_type,
                "type": order_type, # For consistency with frontend
                "price": price,
                "timestamp": str(random.randint(1, 1000000)) # Placeholder
            }
            self.add_order(new_order)

class MatchingEngine:
    def __init__(self, order_book):
        self.order_book = order_book

    def match_order(self, new_order):
        trades = []
        if new_order['type'] == 'buy':
            if new_order['asset'] in self.order_book.sell_orders:
                for order in self.order_book.sell_orders[new_order['asset']]:
                    if new_order['price'] >= order['price']:
                        # Match found
                        trade_price = order['price']
                        trade_amount = min(new_order['amount'], order['amount'])
                        
                        trades.append({
                            "buy_order_id": new_order['id'],
                            "sell_order_id": order['id'],
                            "price": trade_price,
                            "amount": trade_amount
                        })

                        new_order['amount'] -= trade_amount
                        order['amount'] -= trade_amount

                        if order['amount'] == 0:
                            self.order_book.sell_orders[new_order['asset']].remove(order)
                        
                        if new_order['amount'] == 0:
                            break
        else: # Sell order
            if new_order['asset'] in self.order_book.buy_orders:
                for order in self.order_book.buy_orders[new_order['asset']]:
                    if new_order['price'] <= order['price']:
                        # Match found
                        trade_price = order['price']
                        trade_amount = min(new_order['amount'], order['amount'])
                        
                        trades.append({
                            "buy_order_id": order['id'],
                            "sell_order_id": new_order['id'],
                            "price": trade_price,
                            "amount": trade_amount
                        })

                        new_order['amount'] -= trade_amount
                        order['amount'] -= trade_amount

                        if order['amount'] == 0:
                            self.order_book.buy_orders[new_order['asset']].remove(order)
                        
                        if new_order['amount'] == 0:
                            break
        
        if new_order['amount'] > 0:
            self.order_book.add_order(new_order)
            
        return trades
