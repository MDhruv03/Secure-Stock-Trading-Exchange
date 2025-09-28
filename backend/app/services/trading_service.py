import json
import time
from typing import Dict, Any, List, Optional
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service
from backend.app.models.order import OrderSide, OrderStatus, OrderType
from backend.app.models.transaction import TransactionStatus

class TradingService:
    """
    Trading Service for the Secure Trading Platform
    Handles order creation, execution, and management with real encryption
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
    
    def create_order(self, user_id: int, symbol: str, side: str, quantity: float, price: float, order_type: str = "MARKET") -> Dict[str, Any]:
        """
        Create a new secure order with real encryption
        """
        try:
            # Prepare order data
            order_data = {
                "user_id": user_id,
                "symbol": symbol,
                "side": side,
                "order_type": order_type,
                "quantity": quantity,
                "price": price,
                "timestamp": int(time.time()),
                "nonce": f"nonce_{int(time.time() * 1000000)}"
            }
            
            # Encrypt order data
            encrypted_package = self.crypto.encrypt_data(order_data)
            
            # Create digital signature
            signature = self.crypto.sign_data(order_data)
            
            # Create Merkle leaf
            merkle_leaf = self.crypto.create_merkle_leaf(order_data)
            
            # Store in database
            order_id = self.db.create_order(
                user_id=user_id,
                symbol=symbol,
                side=side,
                order_type=order_type,
                quantity=quantity,
                price=price,
                encrypted_data=json.dumps(encrypted_package),
                signature=signature,
                merkle_leaf=merkle_leaf,
                nonce=encrypted_package["nonce"],
                tag=encrypted_package["tag"]
            )
            
            if order_id:
                # Add to Merkle tree
                self.db.add_merkle_leaf(merkle_leaf, f"ORDER-{order_id}")
                
                # Log security event
                self.db.log_security_event(
                    "ORDER_CREATED",
                    f"New {side} {order_type} order for {quantity} {symbol} created",
                    user_id=user_id,
                    resource="ORDER",
                    severity="INFO"
                )
                
                return {
                    "success": True,
                    "order_id": order_id,
                    "merkle_leaf": merkle_leaf,
                    "encrypted_data": encrypted_package,
                    "signature": signature[:32] + "...",  # Shortened for display
                    "message": "Order created successfully with cryptographic protection"
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to create order"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Order creation failed: {str(e)}"
            }
    
    def get_user_orders(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all orders for a user with real data from database
        """
        try:
            # Get orders from database
            orders = self.db.get_user_orders(user_id)
            
            # Add security event
            self.db.log_security_event(
                "ORDER_HISTORY_ACCESS",
                f"User {user_id} accessed order history",
                severity="INFO"
            )
            
            return orders
        except Exception as e:
            return []
    
    def get_all_orders(self) -> List[Dict[str, Any]]:
        """
        Get all orders (for admin view)
        """
        try:
            # Get all orders from database
            orders = self.db.get_all_orders()
            
            return orders
        except Exception as e:
            print(f"[TRADING] Error getting all orders: {str(e)}")
            return []
    
    def get_order_book(self, symbol: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get order book for a symbol with real data
        """
        try:
            # Get all orders for this symbol
            all_orders = self.db.get_all_orders()
            symbol_orders = [order for order in all_orders if order["symbol"] == symbol]
            
            # Separate buy and sell orders
            buy_orders = [order for order in symbol_orders if order["side"] == "buy"]
            sell_orders = [order for order in symbol_orders if order["side"] == "sell"]
            
            # Aggregate by price level
            buy_levels = {}
            sell_levels = {}
            
            for order in buy_orders:
                price = order["price"]
                if price not in buy_levels:
                    buy_levels[price] = {"quantity": 0, "count": 0}
                buy_levels[price]["quantity"] += order["quantity"]
                buy_levels[price]["count"] += 1
            
            for order in sell_orders:
                price = order["price"]
                if price not in sell_levels:
                    sell_levels[price] = {"quantity": 0, "count": 0}
                sell_levels[price]["quantity"] += order["quantity"]
                sell_levels[price]["count"] += 1
            
            # Convert to list format sorted by price
            buy_list = [
                {"price": price, "quantity": data["quantity"], "count": data["count"]}
                for price, data in sorted(buy_levels.items(), reverse=True)
            ][:10]  # Top 10 levels
            
            sell_list = [
                {"price": price, "quantity": data["quantity"], "count": data["count"]}
                for price, data in sorted(sell_levels.items())
            ][:10]  # Top 10 levels
            
            return {
                "symbol": symbol,
                "buy_orders": buy_list,
                "sell_orders": sell_list,
                "timestamp": int(time.time())
            }
        except Exception as e:
            print(f"[TRADING] Error getting order book: {str(e)}")
            return {
                "symbol": symbol,
                "buy_orders": [],
                "sell_orders": [],
                "timestamp": int(time.time())
            }
    
    def calculate_vwap(self, symbol: str) -> float:
        """
        Calculate Volume Weighted Average Price with real data
        """
        try:
            # Get all orders for this symbol
            all_orders = self.db.get_all_orders()
            symbol_orders = [order for order in all_orders if order["symbol"] == symbol]
            
            if not symbol_orders:
                return 0.0
            
            # Calculate VWAP
            total_value = 0.0
            total_quantity = 0.0
            
            for order in symbol_orders:
                total_value += order["price"] * order["quantity"]
                total_quantity += order["quantity"]
            
            if total_quantity == 0:
                return 0.0
            
            vwap = total_value / total_quantity
            return round(vwap, 2)
        except Exception as e:
            print(f"[TRADING] Error calculating VWAP: {str(e)}")
            return 0.0
    
    def search_trades(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Search trades by keyword with real data
        """
        try:
            # Get all orders
            all_orders = self.db.get_all_orders()
            
            # Filter by keyword
            filtered_orders = [
                order for order in all_orders
                if keyword.lower() in str(order.values()).lower()
            ]
            
            return filtered_orders
        except Exception as e:
            print(f"[TRADING] Error searching trades: {str(e)}")
            return []
    
    def execute_order(self, order_id: int) -> Dict[str, Any]:
        """
        Execute an order and create a transaction
        """
        try:
            # Get order details
            all_orders = self.db.get_all_orders()
            order = None
            for o in all_orders:
                if o["id"] == order_id:
                    order = o
                    break
            
            if not order:
                return {"success": False, "message": "Order not found"}
            
            if order["status"] == "FILLED":
                return {"success": False, "message": "Order already filled"}
            
            # For demo purposes, we'll just execute the order
            # In a real system, we'd match orders against a book
            transaction_data = {
                "order_id": order["id"],
                "user_id": order["user_id"],
                "symbol": order["symbol"],
                "side": order["side"],
                "quantity": order["quantity"],
                "price": order["price"],
                "total_value": order["quantity"] * order["price"],
                "timestamp": int(time.time())
            }
            
            # Encrypt transaction data
            encrypted_package = self.crypto.encrypt_data(transaction_data)
            
            # Create digital signature
            signature = self.crypto.sign_data(transaction_data)
            
            # Create Merkle leaf
            merkle_leaf = self.crypto.create_merkle_leaf(transaction_data)
            
            # Create transaction in database
            transaction_id = self.db.create_transaction(
                order_id=order["id"],
                user_id=order["user_id"],
                symbol=order["symbol"],
                side=order["side"],
                quantity=order["quantity"],
                price=order["price"],
                total_value=transaction_data["total_value"],
                encrypted_data=json.dumps(encrypted_package),
                signature=signature,
                merkle_leaf=merkle_leaf
            )
            
            if transaction_id:
                # Add to Merkle tree
                self.db.add_merkle_leaf(merkle_leaf, f"TX-{transaction_id}")
                
                # Update order status
                self.db.update_order_status(order_id, "FILLED")
                
                # Log security event
                self.db.log_security_event(
                    "TRANSACTION_EXECUTED",
                    f"Order {order_id} executed: {order['side']} {order['quantity']} {order['symbol']} @ ${order['price']}",
                    user_id=order["user_id"],
                    resource="TRANSACTION",
                    severity="INFO"
                )
                
                # Update user portfolio
                self.db.update_portfolio_after_transaction(
                    user_id=order["user_id"],
                    symbol=order["symbol"],
                    quantity=order["quantity"],
                    side=order["side"],
                    price=order["price"]
                )
                
                return {
                    "success": True,
                    "transaction_id": transaction_id,
                    "message": "Order executed successfully"
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to create transaction"
                }
                
        except Exception as e:
            return {
                "success": False,
                "message": f"Order execution failed: {str(e)}"
            }
    
    def get_user_portfolio(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get user's portfolio holdings
        """
        try:
            return self.db.get_user_portfolio(user_id)
        except Exception as e:
            print(f"[TRADING] Error getting user portfolio: {str(e)}")
            return []
    
    def get_market_data(self, symbol: str = None) -> List[Dict[str, Any]]:
        """
        Get market data for all or specific symbol
        """
        try:
            return self.db.get_market_data(symbol)
        except Exception as e:
            print(f"[TRADING] Error getting market data: {str(e)}")
            return []
    
    def decrypt_order(self, encrypted_data: str) -> Dict[str, Any]:
        """
        Decrypt order data (for authorized users only)
        """
        try:
            # Parse encrypted package
            encrypted_package = json.loads(encrypted_data)
            
            # Decrypt data
            decrypted_data = self.crypto.decrypt_data(encrypted_package)
            
            return decrypted_data
        except Exception as e:
            print(f"[TRADING] Error decrypting order: {str(e)}")
            return {}

# Global trading service instance
trading_service = TradingService()

def get_trading_service():
    """Get the global trading service instance"""
    return trading_service

def demo_trading_operations():
    """Demonstrate trading operations with real encryption"""
    print("=== Trading Service Demo ===")
    
    # Get trading service
    ts = get_trading_service()
    
    # Test order creation with real encryption
    print("\n1. Creating Secure Orders with Real Encryption:")
    
    # Create buy order
    buy_order = ts.create_order(
        user_id=12345,
        symbol="BTC",
        side="buy",
        quantity=0.5,
        price=45000.00
    )
    print(f"   Buy Order: {buy_order['message']}")
    if buy_order["success"]:
        print(f"   Order ID: {buy_order['order_id']}")
        print(f"   Merkle Leaf: {buy_order['merkle_leaf'][:32]}...")
        print(f"   Signature: {buy_order['signature']}")
    
    # Create sell order
    sell_order = ts.create_order(
        user_id=12345,
        symbol="ETH",
        side="sell",
        quantity=2.1,
        price=3200.00
    )
    print(f"   Sell Order: {sell_order['message']}")
    if sell_order["success"]:
        print(f"   Order ID: {sell_order['order_id']}")
        print(f"   Merkle Leaf: {sell_order['merkle_leaf'][:32]}...")
    
    # Test getting user order
    print("\n2. Retrieving User Orders from Database:")
    orders = ts.get_user_orders(12345)
    print(f"   Found {len(orders)} orders")
    for order in orders[:3]:  # Show first 3 orders
        print(f"   - Order {order['id']}: {order['side']} {order['quantity']} {order['symbol']} @ ${order['price']}")
        print(f"     Merkle Leaf: {order['merkle_leaf'][:32]}...")
    
    # Test order book
    print("\n3. Order Book for BTC:")
    order_book = ts.get_order_book("BTC")
    print(f"   Buy Orders: {len(order_book['buy_orders'])}")
    for order in order_book['buy_orders'][:3]:
        print(f"   - ${order['price']}: {order['quantity']} BTC ({order['count']} orders)")
    
    print(f"   Sell Orders: {len(order_book['sell_orders'])}")
    for order in order_book['sell_orders'][:3]:
        print(f"   - ${order['price']}: {order['quantity']} BTC ({order['count']} orders)")
    
    # Test VWAP calculation
    print("\n4. VWAP Calculation:")
    vwap = ts.calculate_vwap("BTC")
    print(f"   BTC VWAP: ${vwap}")
    
    vwap_eth = ts.calculate_vwap("ETH")
    print(f"   ETH VWAP: ${vwap_eth}")
    
    # Test trade search
    print("\n5. Trade Search:")
    search_results = ts.search_trades("BTC")
    print(f"   Found {len(search_results)} results for 'BTC'")
    for result in search_results[:3]:
        print(f"   - #{result['id']}: {result['side'].upper()} {result['quantity']} {result['symbol']} @ ${result['price']}")
    
    # Test order execution
    print("\n6. Executing Orders:")
    if buy_order["success"]:
        execution_result = ts.execute_order(buy_order["order_id"])
        print(f"   Order execution: {execution_result['message']}")
    
    # Test portfolio
    print("\n7. User Portfolio:")
    portfolio = ts.get_user_portfolio(12345)
    print(f"   User has {len(portfolio)} assets in portfolio")
    for asset in portfolio:
        print(f"   - {asset['symbol']}: {asset['quantity']} shares at avg ${asset['avg_buy_price']}")
    
    print("\n=== Trading Demo Completed ===")

if __name__ == "__main__":
    demo_trading_operations()