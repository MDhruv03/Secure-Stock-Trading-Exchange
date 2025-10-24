"""
Order Matching Engine for the Secure Trading Platform
Implements price-time priority matching algorithm (FIFO)
Prevents self-trading (same user cannot trade with themselves)
"""
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OrderMatchingEngine:
    """
    Order Matching Engine using price-time priority algorithm
    Matches buy and sell orders based on price and time priority
    """
    
    def __init__(self):
        self.db = get_db_manager()
        self.crypto = get_crypto_service()
        self.min_order_size = 0.001  # Minimum order size
    
    def match_orders(self, symbol: str) -> List[Dict[str, Any]]:
        """
        Match pending orders for a given symbol
        Prevents self-trading (same user orders)
        Returns list of executed trades
        """
        executions = []
        
        # Get all pending orders for this symbol
        pending_orders = self.db.get_pending_orders_by_symbol(symbol)
        
        if not pending_orders or len(pending_orders) < 2:
            logger.info(f"[MATCHING] Not enough orders to match for {symbol}: {len(pending_orders) if pending_orders else 0} orders")
            return executions  # Need at least 2 orders to match
        
        # Separate buy and sell orders (case-insensitive comparison)
        buy_orders = [o for o in pending_orders if o['side'].upper() == 'BUY']
        sell_orders = [o for o in pending_orders if o['side'].upper() == 'SELL']
        
        logger.info(f"[MATCHING] {symbol}: {len(buy_orders)} buy orders, {len(sell_orders)} sell orders")
        
        # Sort orders: buy by price DESC, sell by price ASC, then by time
        buy_orders.sort(key=lambda x: (-x['price'], x['created_at']))
        sell_orders.sort(key=lambda x: (x['price'], x['created_at']))
        
        # Match orders
        while buy_orders and sell_orders:
            buy_order = buy_orders[0]
            sell_order = sell_orders[0]
            
            # Prevent self-trading: skip if same user
            if buy_order['user_id'] == sell_order['user_id']:
                logger.warning(f"[MATCHING] Prevented self-trading: User {buy_order['user_id']} has both buy and sell orders")
                # Try to find a different sell order from a different user
                found_match = False
                for i in range(1, len(sell_orders)):
                    if sell_orders[i]['user_id'] != buy_order['user_id']:
                        # Swap with the first sell order
                        sell_orders[0], sell_orders[i] = sell_orders[i], sell_orders[0]
                        sell_order = sell_orders[0]
                        found_match = True
                        logger.info(f"[MATCHING] Found alternative sell order from user {sell_order['user_id']}")
                        break
                
                if not found_match:
                    # No matching sell orders from different users, try next buy order
                    logger.info(f"[MATCHING] No alternative sell orders found, moving to next buy order")
                    buy_orders.pop(0)
                    continue
            
            # Check if orders can match
            if buy_order['price'] >= sell_order['price']:
                logger.info(f"[MATCHING] Match found: Buy@{buy_order['price']} >= Sell@{sell_order['price']}")
                # Execute trade at seller's price (or avg of both)
                execution_price = sell_order['price']
                
                # Determine quantity to execute
                buy_qty = buy_order['quantity'] - buy_order.get('filled_quantity', 0)
                sell_qty = sell_order['quantity'] - sell_order.get('filled_quantity', 0)
                execution_qty = min(buy_qty, sell_qty)
                
                if execution_qty >= self.min_order_size:
                    # Execute the trade
                    logger.info(f"[MATCHING] Executing trade: {execution_qty} {buy_order['symbol']} @ {execution_price}")
                    execution = self._execute_trade(
                        buy_order, 
                        sell_order, 
                        execution_qty, 
                        execution_price
                    )
                    
                    if execution:
                        executions.append(execution)
                        logger.info(f"[MATCHING] Trade executed successfully: buyer={buy_order['user_id']}, seller={sell_order['user_id']}")
                        
                        # Update filled quantities
                        buy_order['filled_quantity'] = buy_order.get('filled_quantity', 0) + execution_qty
                        sell_order['filled_quantity'] = sell_order.get('filled_quantity', 0) + execution_qty
                        
                        # Remove fully filled orders
                        if buy_order['filled_quantity'] >= buy_order['quantity']:
                            buy_orders.pop(0)
                        if sell_order['filled_quantity'] >= sell_order['quantity']:
                            sell_orders.pop(0)
                else:
                    # Quantity too small, remove orders
                    buy_orders.pop(0)
                    sell_orders.pop(0)
            else:
                # No more matches possible (best buy price < best sell price)
                logger.info(f"[MATCHING] No more matches: Best buy price {buy_order['price']} < Best sell price {sell_order['price']}")
                break
        
        logger.info(f"[MATCHING] Completed for {symbol}: {len(executions)} trades executed")
        return executions
    
    def _execute_trade(
        self, 
        buy_order: Dict[str, Any], 
        sell_order: Dict[str, Any],
        quantity: float,
        price: float
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a trade between two orders
        Ensures buyer and seller are different users
        """
        try:
            # Sanity check: prevent self-trading
            if buy_order['user_id'] == sell_order['user_id']:
                logger.error(f"[MATCHING] Prevented self-trade execution for user {buy_order['user_id']}")
                return None
            
            # Calculate trade details
            total_value = quantity * price
            
            logger.info(f"[MATCHING] Executing: User {buy_order['user_id']} buys from User {sell_order['user_id']}: {quantity} @ {price}")
            
            # Create transaction records for both buyer and seller
            buyer_transaction = {
                "order_id": buy_order['id'],
                "user_id": buy_order['user_id'],
                "symbol": buy_order['symbol'],
                "side": "BUY",
                "quantity": quantity,
                "price": price,
                "total_value": total_value
            }
            
            seller_transaction = {
                "order_id": sell_order['id'],
                "user_id": sell_order['user_id'],
                "symbol": sell_order['symbol'],
                "side": "SELL",
                "quantity": quantity,
                "price": price,
                "total_value": total_value
            }
            
            # Encrypt and create Merkle leaf for transactions
            buyer_encrypted = self.crypto.encrypt_data(buyer_transaction)
            seller_encrypted = self.crypto.encrypt_data(seller_transaction)
            
            buyer_signature = self.crypto.sign_data(buyer_transaction)
            seller_signature = self.crypto.sign_data(seller_transaction)
            
            # Create merkle leaves
            buyer_merkle = self.crypto.create_merkle_leaf(buyer_transaction)
            seller_merkle = self.crypto.create_merkle_leaf(seller_transaction)
            
            # Convert encrypted dicts to JSON strings for database storage
            import json
            buyer_encrypted_str = json.dumps(buyer_encrypted)
            seller_encrypted_str = json.dumps(seller_encrypted)
            
            # Record transactions in database
            buyer_tx_id = self.db.create_transaction(
                buyer_transaction['order_id'],
                buyer_transaction['user_id'],
                buyer_transaction['symbol'],
                buyer_transaction['side'],
                buyer_transaction['quantity'],
                buyer_transaction['price'],
                buyer_transaction['total_value'],
                buyer_encrypted_str,
                buyer_signature,
                buyer_merkle
            )
            
            seller_tx_id = self.db.create_transaction(
                seller_transaction['order_id'],
                seller_transaction['user_id'],
                seller_transaction['symbol'],
                seller_transaction['side'],
                seller_transaction['quantity'],
                seller_transaction['price'],
                seller_transaction['total_value'],
                seller_encrypted_str,
                seller_signature,
                seller_merkle
            )
            
            if buyer_tx_id and seller_tx_id:
                # Update order statuses
                self._update_order_status(buy_order, quantity)
                self._update_order_status(sell_order, quantity)
                
                # Update user portfolios
                self._update_portfolio(buy_order['user_id'], buy_order['symbol'], quantity, price, 'BUY')
                self._update_portfolio(sell_order['user_id'], sell_order['symbol'], quantity, price, 'SELL')
                
                # Update user balances
                self._update_balances(buy_order['user_id'], sell_order['user_id'], total_value)
                
                # Log the execution
                self.db.log_security_event(
                    "TRADE_EXECUTED",
                    f"Trade executed: {quantity} {buy_order['symbol']} @ {price}",
                    severity="INFO",
                    details={
                        "buyer_id": buy_order['user_id'],
                        "seller_id": sell_order['user_id'],
                        "symbol": buy_order['symbol'],
                        "quantity": quantity,
                        "price": price,
                        "total_value": total_value
                    }
                )
                
                return {
                    "buyer_tx_id": buyer_tx_id,
                    "seller_tx_id": seller_tx_id,
                    "symbol": buy_order['symbol'],
                    "quantity": quantity,
                    "price": price,
                    "total_value": total_value,
                    "executed_at": datetime.now().isoformat()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"[MATCHING] Error executing trade: {str(e)}")
            return None
    
    def _update_order_status(self, order: Dict[str, Any], filled_qty: float):
        """
        Update order status based on filled quantity
        """
        total_filled = order.get('filled_quantity', 0) + filled_qty
        
        if total_filled >= order['quantity']:
            # Fully filled
            self.db.update_order_status(order['id'], 'FILLED', total_filled)
        else:
            # Partially filled
            self.db.update_order_status(order['id'], 'PARTIAL', total_filled)
    
    def _update_portfolio(self, user_id: int, symbol: str, quantity: float, price: float, side: str):
        """
        Update user's portfolio after trade execution
        """
        if side == 'BUY':
            # Add to portfolio
            self.db.add_to_portfolio(user_id, symbol, quantity, price)
        else:  # SELL
            # Remove from portfolio
            self.db.remove_from_portfolio(user_id, symbol, quantity)
    
    def _update_balances(self, buyer_id: int, seller_id: int, amount: float):
        """
        Update user balances after trade execution
        Deduct from buyer, add to seller
        """
        self.db.update_user_balance(buyer_id, -amount)
        self.db.update_user_balance(seller_id, amount)
    
    def match_all_symbols(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Match orders for all symbols
        Returns dict of symbol -> executions
        """
        results = {}
        
        # Get all unique symbols with pending orders
        symbols = self.db.get_symbols_with_pending_orders()
        
        for symbol in symbols:
            executions = self.match_orders(symbol)
            if executions:
                results[symbol] = executions
        
        return results
    
    def get_matching_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about order matching
        """
        stats = {
            "pending_orders": self.db.count_pending_orders(),
            "filled_orders": self.db.count_filled_orders(),
            "total_transactions": self.db.count_transactions(),
            "symbols_with_pending": len(self.db.get_symbols_with_pending_orders())
        }
        
        return stats


# Global order matching engine instance
_matching_engine = None


def get_matching_engine() -> OrderMatchingEngine:
    """
    Get the global order matching engine instance
    """
    global _matching_engine
    if _matching_engine is None:
        _matching_engine = OrderMatchingEngine()
    return _matching_engine


if __name__ == "__main__":
    # Test the matching engine
    engine = get_matching_engine()
    print("=== Order Matching Engine Test ===")
    
    # Get statistics
    stats = engine.get_matching_statistics()
    print(f"\nMatching Statistics:")
    print(f"  Pending Orders: {stats['pending_orders']}")
    print(f"  Filled Orders: {stats['filled_orders']}")
    print(f"  Total Transactions: {stats['total_transactions']}")
    print(f"  Symbols with Pending Orders: {stats['symbols_with_pending']}")
    
    # Try to match all symbols
    print("\nAttempting to match all symbols...")
    results = engine.match_all_symbols()
    
    if results:
        print(f"\nMatched {len(results)} symbols:")
        for symbol, executions in results.items():
            print(f"\n{symbol}:")
            for execution in executions:
                print(f"  - {execution['quantity']} @ {execution['price']} = {execution['total_value']}")
    else:
        print("\nNo matches found")
    
    print("\n=== Test Complete ===")
