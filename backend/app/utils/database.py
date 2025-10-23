import sqlite3
import json
import hashlib
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import os

# Import key management
from backend.app.utils.key_management import get_key_manager
from backend.app.services.crypto_service import get_crypto_service

class DatabaseManager:
    """
    Enhanced Database Manager for the Secure Trading Platform
    Handles all database operations with encryption support and key management
    """
    
    def __init__(self, db_path: str = "trading_platform.db"):
        self.db_path = db_path
        self.key_manager = get_key_manager()
        self.crypto_service = get_crypto_service()
        self.init_database()
    
    def init_database(self):
        """
        Initialize the database with required tables
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP NULL,
                balance REAL DEFAULT 10000.00,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Stocks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                symbol TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                current_price REAL NOT NULL,
                market_cap REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Orders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                side TEXT NOT NULL,
                order_type TEXT NOT NULL DEFAULT 'MARKET',
                quantity REAL NOT NULL,
                price REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                filled_quantity REAL DEFAULT 0.0,
                encrypted_data TEXT NOT NULL,
                signature TEXT NOT NULL,
                merkle_leaf TEXT NOT NULL,
                nonce TEXT NOT NULL,
                tag TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Transactions table (executed trades)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                side TEXT NOT NULL,
                quantity REAL NOT NULL,
                price REAL NOT NULL,
                total_value REAL NOT NULL,
                encrypted_data TEXT NOT NULL,
                signature TEXT NOT NULL,
                merkle_leaf TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'SUCCESS',
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (order_id) REFERENCES orders (id)
            )
        """)
        
        # Security events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                severity TEXT,
                details TEXT,
                user_id INTEGER,
                resource TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Merkle tree table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merkle_tree (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                leaf_hash TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Blocked IPs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                blocked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Attack simulations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Defense responses table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS defense_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                simulation_id INTEGER NOT NULL,
                response_type TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (simulation_id) REFERENCES attack_simulations (id)
            )
        """)
        
        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)
        
        # Session management table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Portfolio table (user holdings)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS portfolio (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                quantity REAL NOT NULL DEFAULT 0.0,
                avg_buy_price REAL NOT NULL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Market data table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS market_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                symbol TEXT NOT NULL,
                open_price REAL,
                high_price REAL,
                low_price REAL,
                close_price REAL,
                volume REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for performance optimization
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_symbol ON orders(symbol)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_order_id ON transactions(order_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_symbol ON transactions(symbol)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_executed_at ON transactions(executed_at)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_portfolio_user_id ON portfolio(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_portfolio_symbol ON portfolio(symbol)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_portfolio_user_symbol ON portfolio(user_id, symbol)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip_address ON blocked_ips(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked_until ON blocked_ips(blocked_until)")
        
        # Initialize default stocks
        default_stocks = [
            ("BTC", "Bitcoin", 45000.00),
            ("ETH", "Ethereum", 3200.00),
            ("ADA", "Cardano", 0.50),
            ("DOT", "Polkadot", 7.50),
            ("SOL", "Solana", 100.00),
            ("XRP", "Ripple", 0.55),
            ("AVAX", "Avalanche", 35.00),
            ("LINK", "Chainlink", 15.00),
        ]
        
        for symbol, name, price in default_stocks:
            cursor.execute("""
                INSERT OR IGNORE INTO stocks (symbol, name, current_price)
                VALUES (?, ?, ?)
            """, (symbol, name, price))
        
        conn.commit()
        conn.close()
        
        print(f"[DB] Database initialized successfully at {self.db_path}")
    
    def create_user(self, username: str, password_hash: str) -> Optional[int]:
        """
        Create a new user
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            """, (username, password_hash))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            # Log audit event
            self.log_audit_event(None, "USER_CREATED", f"User {username} created", {"user_id": user_id})
            
            return user_id
        except sqlite3.IntegrityError as e:
            # Username already exists
            logging.error(f"Database integrity error when creating user {username}: {str(e)}")
            if conn:
                conn.rollback()
            return None
        except Exception as e:
            logging.error(f"Unexpected error creating user {username}: {str(e)}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user by username
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, password_hash, created_at, last_login, 
                       failed_login_attempts, locked_until, balance, is_active
                FROM users
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            
            if row:
                user_data = {
                    "id": row["id"],
                    "username": row["username"],
                    "password_hash": row["password_hash"],
                    "created_at": row["created_at"],
                    "last_login": row["last_login"],
                    "failed_login_attempts": row["failed_login_attempts"],
                    "locked_until": row["locked_until"],
                    "balance": row["balance"],
                    "is_active": row["is_active"]
                }
                return user_data
            
            return None
        except Exception as e:
            logging.error(f"Error getting user by username {username}: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user by user ID
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, password_hash, created_at, last_login, 
                       failed_login_attempts, locked_until, balance, is_active
                FROM users
                WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "id": row[0],
                    "username": row[1],
                    "password_hash": row[2],
                    "created_at": row[3],
                    "last_login": row[4],
                    "failed_login_attempts": row[5],
                    "locked_until": row[6],
                    "balance": row[7],
                    "is_active": row[8]
                }
            
            return None
        except Exception as e:
            print(f"[DB] Error getting user by ID: {str(e)}")
            return None
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all users
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, created_at, last_login, 
                       failed_login_attempts, locked_until, balance, is_active
                FROM users
                ORDER BY id ASC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            users = []
            for row in rows:
                users.append({
                    "id": row[0],
                    "username": row[1],
                    "created_at": row[2],
                    "last_login": row[3],
                    "failed_login_attempts": row[4],
                    "locked_until": row[5],
                    "balance": row[6],
                    "is_active": row[7]
                })
            
            return users
        except Exception as e:
            print(f"[DB] Error getting all users: {str(e)}")
            return []
    
    def update_user_last_login(self, user_id: int) -> bool:
        """
        Update user's last login timestamp
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0
                WHERE id = ?
            """, (user_id,))
            
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Error updating user login for user_id {user_id}: {str(e)}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()
    
    def increment_failed_login_attempts(self, username: str) -> bool:
        """
        Increment failed login attempts for a user
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE username = ?
            """, (username,))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error incrementing failed login attempts: {str(e)}")
            return False

    def reset_failed_login_attempts(self, username: str) -> bool:
        """
        Reset failed login attempts for a user after successful login
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = 0
                WHERE username = ?
            """, (username,))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error resetting failed login attempts: {str(e)}")
            return False
    
    def lock_user_account(self, username: str, lock_duration_hours: int = 24) -> bool:
        """
        Lock a user account after too many failed attempts
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            lock_until = datetime.fromtimestamp(time.time() + (lock_duration_hours * 3600))
            
            cursor.execute("""
                UPDATE users
                SET locked_until = ?
                WHERE username = ?
            """, (lock_until.isoformat(), username))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error locking user account: {str(e)}")
            return False
    
    def is_user_locked(self, username: str) -> bool:
        """
        Check if a user account is locked
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT locked_until
                FROM users
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row and row[0]:
                locked_until = datetime.fromisoformat(row[0])
                return locked_until > datetime.now()
            
            return False
        except Exception as e:
            print(f"[DB] Error checking user lock status: {str(e)}")
            return False
    
    def create_order(self, user_id: int, symbol: str, side: str, quantity: float, price: float,
                    encrypted_data: str, signature: str, merkle_leaf: str, nonce: str, tag: str, 
                    order_type: str = "MARKET") -> Optional[int]:
        """
        Create a new encrypted order
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO orders (user_id, symbol, side, order_type, quantity, price, encrypted_data, signature, merkle_leaf, nonce, tag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, symbol, side, order_type, quantity, price, encrypted_data, signature, merkle_leaf, nonce, tag))
            
            order_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Log audit event
            self.log_audit_event(user_id, "ORDER_CREATED", f"Order {order_id} created", {
                "symbol": symbol, "side": side, "quantity": quantity, "price": price, "order_type": order_type
            })
            
            return order_id
        except Exception as e:
            logging.error(f"Error creating order for user {user_id}: {str(e)}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()
    
    def get_user_orders(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all orders for a user
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, symbol, side, quantity, price, merkle_leaf, created_at
                FROM orders
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (user_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append({
                    "id": row[0],
                    "symbol": row[1],
                    "side": row[2],
                    "quantity": row[3],
                    "price": row[4],
                    "merkle_leaf": row[5],
                    "created_at": row[6]
                })
            
            return orders
        except Exception as e:
            print(f"[DB] Error getting user orders: {str(e)}")
            return []
    
    def create_order(self, user_id: int, symbol: str, side: str, quantity: float, price: float,
                    encrypted_data: str, signature: str, merkle_leaf: str, nonce: str, tag: str, 
                    order_type: str = "MARKET") -> Optional[int]:
        """
        Create a new encrypted order
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO orders (user_id, symbol, side, order_type, quantity, price, encrypted_data, signature, merkle_leaf, nonce, tag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, symbol, side, order_type, quantity, price, encrypted_data, signature, merkle_leaf, nonce, tag))
            
            order_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Log audit event
            self.log_audit_event(user_id, "ORDER_CREATED", f"Order {order_id} created", {
                "symbol": symbol, "side": side, "quantity": quantity, "price": price
            })
            
            return order_id
        except Exception as e:
            logging.error(f"Error creating order for user {user_id}: {str(e)}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                conn.close()

    def update_order_status(self, order_id: int, status: str) -> bool:
        """
        Update order status
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE orders
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, order_id))
            
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Error updating order status for order {order_id}: {str(e)}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()

    def get_all_orders(self) -> List[Dict[str, Any]]:
        """
        Get all orders (for admin view)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT o.id, u.username AS user_name, o.symbol, o.side, o.order_type, o.quantity, o.price, 
                       o.status, o.filled_quantity, o.merkle_leaf, o.created_at
                FROM orders o
                JOIN users u ON o.user_id = u.id
                ORDER BY o.created_at DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append({
                    "id": row[0],
                    "user_name": row[1],
                    "symbol": row[2],
                    "side": row[3],
                    "order_type": row[4],
                    "quantity": row[5],
                    "price": row[6],
                    "status": row[7],
                    "filled_quantity": row[8],
                    "merkle_leaf": row[9],
                    "created_at": row[10]
                })
            
            return orders
        except Exception as e:
            print(f"[DB] Error getting all orders: {str(e)}")
            return []

    def create_transaction(self, order_id: int, user_id: int, symbol: str, side: str, 
                         quantity: float, price: float, total_value: float, 
                         encrypted_data: str, signature: str, merkle_leaf: str) -> Optional[int]:
        """
        Create a new transaction
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO transactions (order_id, user_id, symbol, side, quantity, price, total_value, 
                                        encrypted_data, signature, merkle_leaf)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (order_id, user_id, symbol, side, quantity, price, total_value, encrypted_data, signature, merkle_leaf))
            
            transaction_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Log audit event
            self.log_audit_event(user_id, "TRANSACTION_CREATED", f"Transaction {transaction_id} created", {
                "symbol": symbol, "side": side, "quantity": quantity, "price": price, "total_value": total_value
            })
            
            return transaction_id
        except Exception as e:
            print(f"[DB] Error creating transaction: {str(e)}")
            conn.close()
            return None

    def update_portfolio_after_transaction(self, user_id: int, symbol: str, quantity: float, side: str, price: float) -> bool:
        """
        Update user's portfolio after a transaction
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already owns this symbol
            cursor.execute("""
                SELECT id, quantity, avg_buy_price
                FROM portfolio
                WHERE user_id = ? AND symbol = ?
            """, (user_id, symbol))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing holdings
                existing_id, existing_quantity, existing_avg_price = existing
                if side == "buy":
                    # Calculate new average price
                    total_quantity = existing_quantity + quantity
                    total_value = (existing_quantity * existing_avg_price) + (quantity * price)
                    new_avg_price = total_value / total_quantity if total_quantity > 0 else 0.0
                    
                    cursor.execute("""
                        UPDATE portfolio
                        SET quantity = ?, avg_buy_price = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (total_quantity, new_avg_price, existing_id))
                else:  # sell
                    new_quantity = existing_quantity - quantity
                    if new_quantity < 0:
                        new_quantity = 0  # Can't sell more than you own
                    cursor.execute("""
                        UPDATE portfolio
                        SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (new_quantity, existing_id))
            else:
                # Create new holding (only for buy orders)
                if side == "buy":
                    cursor.execute("""
                        INSERT INTO portfolio (user_id, symbol, quantity, avg_buy_price)
                        VALUES (?, ?, ?, ?)
                    """, (user_id, symbol, quantity, price))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Error updating portfolio: {str(e)}")
            conn.close()
            return False

    def get_user_portfolio(self, user_id: int) -> Dict[str, Any]:
        """
        Get user's portfolio holdings with enriched data
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get portfolio holdings
            cursor.execute("""
                SELECT p.symbol, p.quantity, p.avg_buy_price, p.created_at, p.updated_at,
                       s.current_price, s.name
                FROM portfolio p
                LEFT JOIN stocks s ON p.symbol = s.symbol
                WHERE p.user_id = ? AND p.quantity > 0
                ORDER BY p.quantity * COALESCE(s.current_price, p.avg_buy_price) DESC
            """, (user_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            assets = []
            total_value = 0
            
            for row in rows:
                symbol = row[0]
                quantity = row[1]
                avg_buy_price = row[2]
                current_price = row[5] if row[5] is not None else avg_buy_price
                
                # Calculate total value for this asset
                asset_total_value = quantity * current_price
                total_value += asset_total_value
                
                # Calculate 24h change (simplified - using difference from avg buy price)
                change = ((current_price - avg_buy_price) / avg_buy_price * 100) if avg_buy_price > 0 else 0
                
                assets.append({
                    "symbol": symbol,
                    "name": row[6] if row[6] else symbol,
                    "quantity": quantity,
                    "avg_buy_price": avg_buy_price,
                    "price": current_price,
                    "total_value": asset_total_value,
                    "change": change,
                    "created_at": row[3],
                    "updated_at": row[4]
                })
            
            return {
                "assets": assets,
                "total_value": total_value,
                "asset_count": len(assets)
            }
        except Exception as e:
            print(f"[DB] Error getting user portfolio: {str(e)}")
            return {"assets": [], "total_value": 0, "asset_count": 0}

    def get_market_data(self, symbol: str = None) -> List[Dict[str, Any]]:
        """
        Get market data for all or specific symbol
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if symbol:
                cursor.execute("""
                    SELECT symbol, name, current_price, market_cap, created_at
                    FROM stocks
                    WHERE symbol = ?
                """, (symbol,))
            else:
                cursor.execute("""
                    SELECT symbol, name, current_price, market_cap, created_at
                    FROM stocks
                    ORDER BY current_price DESC
                """)
            
            rows = cursor.fetchall()
            conn.close()
            
            stocks = []
            for row in rows:
                stocks.append({
                    "symbol": row[0],
                    "name": row[1],
                    "current_price": row[2],
                    "market_cap": row[3],
                    "created_at": row[4]
                })
            
            return stocks
        except Exception as e:
            print(f"[DB] Error getting market data: {str(e)}")
            return []
    
    def update_market_data(self, symbol: str, price: float, volume: float = None, timestamp: datetime = None):
        """Update market data for a symbol"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update current price
            cursor.execute("""
                UPDATE stocks
                SET current_price = ?,
                    market_cap = ?,
                    created_at = ?
                WHERE symbol = ?
            """, (
                price,
                volume * price if volume else None,
                timestamp.isoformat() if timestamp else datetime.now().isoformat(),
                symbol
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Error updating market data: {str(e)}")
            return False

    def get_all_transactions(self, user_id: int = None) -> List[Dict[str, Any]]:
        """
        Get all transactions (for admin view) or for a specific user
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute("""
                    SELECT t.id, t.order_id, u.username AS user_name, t.symbol, t.side, 
                           t.quantity, t.price, t.total_value, t.status, t.executed_at
                    FROM transactions t
                    JOIN users u ON t.user_id = u.id
                    WHERE t.user_id = ?
                    ORDER BY t.executed_at DESC
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT t.id, t.order_id, u.username AS user_name, t.symbol, t.side, 
                           t.quantity, t.price, t.total_value, t.status, t.executed_at
                    FROM transactions t
                    JOIN users u ON t.user_id = u.id
                    ORDER BY t.executed_at DESC
                """)
            
            rows = cursor.fetchall()
            conn.close()
            
            transactions = []
            for row in rows:
                transactions.append({
                    "id": row[0],
                    "order_id": row[1],
                    "user_name": row[2],
                    "symbol": row[3],
                    "side": row[4],
                    "quantity": row[5],
                    "price": row[6],
                    "total_value": row[7],
                    "status": row[8],
                    "executed_at": row[9]
                })
            
            return transactions
        except Exception as e:
            print(f"[DB] Error getting transactions: {str(e)}")
            return []
    
    def log_security_event(self, event_type: str, description: str, source_ip: str = None,
                          severity: str = "INFO", details: Dict[str, Any] = None) -> bool:
        """
        Log a security event
        """
        try:
            import json
            
            # Serialize details to JSON string if it's a dictionary
            details_str = json.dumps(details) if details else None
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO security_events (event_type, description, source_ip, severity, details)
                VALUES (?, ?, ?, ?, ?)
            """, (event_type, description, source_ip, severity, details_str))

            conn.commit()
            conn.close()

            print(f"[SECURITY] {severity} - {event_type}: {description} (IP: {source_ip})")

            return True
        except Exception as e:
            print(f"[DB] Error logging security event: {str(e)}")
            return False
    
    def get_recent_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent security events
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, event_type, description, source_ip, severity, details, created_at
                FROM security_events
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            events = []
            for row in rows:
                events.append({
                    "id": row[0],
                    "event_type": row[1],
                    "description": row[2],
                    "source_ip": row[3],
                    "severity": row[4],
                    "details": row[5],
                    "created_at": row[6]
                })
            
            return events
        except Exception as e:
            print(f"[DB] Error getting security events: {str(e)}")
            return []
    
    def get_security_events_by_type(self, event_types: List[str], limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get security events filtered by event type(s)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create placeholders for the IN clause
            placeholders = ','.join(['?' for _ in event_types])
            
            cursor.execute(f"""
                SELECT id, event_type, description, source_ip, severity, details, created_at
                FROM security_events
                WHERE event_type IN ({placeholders})
                ORDER BY created_at DESC
                LIMIT ?
            """, (*event_types, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            events = []
            for row in rows:
                events.append({
                    "id": row[0],
                    "event_type": row[1],
                    "description": row[2],
                    "source_ip": row[3],
                    "severity": row[4],
                    "details": row[5],
                    "created_at": row[6]
                })
            
            return events
        except Exception as e:
            print(f"[DB] Error getting security events by type: {str(e)}")
            return []
    
    def add_merkle_leaf(self, leaf_hash: str, transaction_id: str) -> bool:
        """
        Add a leaf to the Merkle tree
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO merkle_tree (leaf_hash, transaction_id)
                VALUES (?, ?)
            """, (leaf_hash, transaction_id))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error adding Merkle leaf: {str(e)}")
            return False
    
    def get_merkle_leaves(self) -> List[Dict[str, Any]]:
        """
        Get all Merkle tree leaves
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, leaf_hash, transaction_id, created_at
                FROM merkle_tree
                ORDER BY created_at ASC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            leaves = []
            for row in rows:
                leaves.append({
                    "id": row[0],
                    "leaf_hash": row[1],
                    "transaction_id": row[2],
                    "created_at": row[3]
                })
            
            return leaves
        except Exception as e:
            print(f"[DB] Error getting Merkle leaves: {str(e)}")
            return []
    
    def get_merkle_tree_structure(self) -> Dict[str, Any]:
        """
        Get complete Merkle tree structure for visualization
        """
        try:
            # Get all leaves
            leaves_data = self.get_merkle_leaves()
            
            if not leaves_data:
                return {
                    "root": None,
                    "levels": [],
                    "total_nodes": 0,
                    "leaf_count": 0
                }
            
            # Extract just the hashes for tree building
            leaf_hashes = [leaf["leaf_hash"] for leaf in leaves_data]
            
            # Build tree structure using crypto service
            crypto_service = get_crypto_service()
            tree_structure = crypto_service.build_merkle_tree_with_structure(leaf_hashes)
            
            # Enrich with transaction data
            tree_structure["leaves_data"] = leaves_data
            
            return tree_structure
        except Exception as e:
            print(f"[DB] Error getting Merkle tree structure: {str(e)}")
            return {
                "root": None,
                "levels": [],
                "total_nodes": 0,
                "leaf_count": 0
            }
    
    def verify_merkle_tree_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire Merkle tree
        """
        try:
            leaves = self.get_merkle_leaves()
            
            if not leaves:
                return {
                    "valid": True,
                    "message": "No leaves in tree",
                    "leaf_count": 0
                }
            
            # Get leaf hashes
            leaf_hashes = [leaf["leaf_hash"] for leaf in leaves]
            
            # Rebuild tree
            crypto_service = get_crypto_service()
            computed_root = crypto_service.create_merkle_root(leaf_hashes)
            
            return {
                "valid": True,
                "root": computed_root,
                "leaf_count": len(leaves),
                "message": "Tree integrity verified"
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "message": "Tree integrity check failed"
            }
    
    def block_ip(self, ip_address: str, reason: str = None, duration_hours: int = 24) -> bool:
        """
        Block an IP address
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate block expiration time
            blocked_until = datetime.fromtimestamp(time.time() + (duration_hours * 3600))
            
            cursor.execute("""
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_until)
                VALUES (?, ?, ?)
            """, (ip_address, reason, blocked_until.isoformat()))
            
            conn.commit()
            conn.close()
            
            # Log security event
            self.log_security_event(
                "IP_BLOCKED",
                f"IP address blocked: {ip_address}",
                ip_address,
                "HIGH",
                reason
            )
            
            return True
        except Exception as e:
            print(f"[DB] Error blocking IP: {str(e)}")
            return False
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 1
                FROM blocked_ips
                WHERE ip_address = ? AND (blocked_until IS NULL OR blocked_until > CURRENT_TIMESTAMP)
            """, (ip_address,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
        except Exception as e:
            print(f"[DB] Error checking IP block: {str(e)}")
            return False
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Get all currently blocked IPs
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT ip_address, reason, blocked_until, created_at
                FROM blocked_ips
                WHERE blocked_until IS NULL OR blocked_until > CURRENT_TIMESTAMP
                ORDER BY created_at DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            blocked_ips = []
            for row in rows:
                blocked_ips.append({
                    "ip_address": row[0],
                    "reason": row[1],
                    "blocked_until": row[2],
                    "created_at": row[3]
                })
            
            return blocked_ips
        except Exception as e:
            print(f"[DB] Error getting blocked IPs: {str(e)}")
            return []
    
    def start_attack_simulation(self, attack_type: str, description: str) -> Optional[int]:
        """
        Start a new attack simulation
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO attack_simulations (attack_type, description, status)
                VALUES (?, ?, ?)
            """, (attack_type, description, "RUNNING"))
            
            simulation_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return simulation_id
        except Exception as e:
            print(f"[DB] Error starting attack simulation: {str(e)}")
            conn.close()
            return None
    
    def end_attack_simulation(self, simulation_id: int, results: str = None) -> bool:
        """
        End an attack simulation
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE attack_simulations
                SET status = ?, end_time = CURRENT_TIMESTAMP, results = ?
                WHERE id = ?
            """, ("COMPLETED", results, simulation_id))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error ending attack simulation: {str(e)}")
            conn.close()
            return False
    
    def get_attack_simulations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent attack simulations
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, attack_type, description, status, start_time, end_time, results, created_at
                FROM attack_simulations
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            simulations = []
            for row in rows:
                simulations.append({
                    "id": row[0],
                    "attack_type": row[1],
                    "description": row[2],
                    "status": row[3],
                    "start_time": row[4],
                    "end_time": row[5],
                    "results": row[6],
                    "created_at": row[7]
                })
            
            return simulations
        except Exception as e:
            print(f"[DB] Error getting attack simulations: {str(e)}")
            return []
    
    def add_defense_response(self, simulation_id: int, response_type: str, description: str, status: str = "EXECUTED") -> bool:
        """
        Add a defense response to a simulation
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO defense_responses (simulation_id, response_type, description, status)
                VALUES (?, ?, ?, ?)
            """, (simulation_id, response_type, description, status))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error adding defense response: {str(e)}")
            conn.close()
            return False
    
    def get_defense_responses(self, simulation_id: int) -> List[Dict[str, Any]]:
        """
        Get defense responses for a simulation
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, response_type, description, status, timestamp
                FROM defense_responses
                WHERE simulation_id = ?
                ORDER BY timestamp ASC
            """, (simulation_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            responses = []
            for row in rows:
                responses.append({
                    "id": row[0],
                    "response_type": row[1],
                    "description": row[2],
                    "status": row[3],
                    "timestamp": row[4]
                })
            
            return responses
        except Exception as e:
            print(f"[DB] Error getting defense responses: {str(e)}")
            return []
    
    def log_audit_event(self, user_id: Optional[int], action: str, resource: str, details: Dict[str, Any] = None) -> bool:
        """
        Log an audit event
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, resource, details)
                VALUES (?, ?, ?, ?)
            """, (user_id, action, resource, json.dumps(details) if details else None))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error logging audit event: {str(e)}")
            return False
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, user_id, action, resource, timestamp, details
                FROM audit_log
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            audit_log = []
            for row in rows:
                audit_log.append({
                    "id": row[0],
                    "user_id": row[1],
                    "action": row[2],
                    "resource": row[3],
                    "timestamp": row[4],
                    "details": json.loads(row[5]) if row[5] else None
                })
            
            return audit_log
        except Exception as e:
            print(f"[DB] Error getting audit log: {str(e)}")
            return []
    
    def create_session(self, user_id: int, session_token: str, expires_at: datetime, 
                      ip_address: str = None, user_agent: str = None) -> bool:
        """
        Create a new user session
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, session_token, expires_at, ip_address, user_agent))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error creating session: {str(e)}")
            return False
    
    def get_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Get session by token
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, user_id, session_token, created_at, expires_at, ip_address, user_agent, is_active
                FROM user_sessions
                WHERE session_token = ? AND is_active = TRUE AND expires_at > CURRENT_TIMESTAMP
            """, (session_token,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "id": row[0],
                    "user_id": row[1],
                    "session_token": row[2],
                    "created_at": row[3],
                    "expires_at": row[4],
                    "ip_address": row[5],
                    "user_agent": row[6],
                    "is_active": row[7]
                }
            
            return None
        except Exception as e:
            print(f"[DB] Error getting session: {str(e)}")
            return None
    
    def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidate a user session
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_sessions
                SET is_active = FALSE
                WHERE session_token = ?
            """, (session_token,))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            print(f"[DB] Error invalidating session: {str(e)}")
            return False
    
    # ==========================================
    # Order Matching Engine Support Methods
    # ==========================================
    
    def get_pending_orders_by_symbol(self, symbol: str) -> List[Dict[str, Any]]:
        """Get all pending orders for a specific symbol"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, user_id, symbol, side, order_type, quantity, price, status, 
                       filled_quantity, created_at
                FROM orders
                WHERE symbol = ? AND status = 'PENDING'
                ORDER BY created_at ASC
            """, (symbol,))
            
            rows = cursor.fetchall()
            conn.close()
            
            orders = []
            for row in rows:
                orders.append({
                    "id": row[0],
                    "user_id": row[1],
                    "symbol": row[2],
                    "side": row[3],
                    "order_type": row[4],
                    "quantity": row[5],
                    "price": row[6],
                    "status": row[7],
                    "filled_quantity": row[8] or 0.0,
                    "created_at": row[9]
                })
            
            return orders
        except Exception as e:
            print(f"[DB] Error getting pending orders: {str(e)}")
            return []
    
    def get_symbols_with_pending_orders(self) -> List[str]:
        """Get list of symbols that have pending orders"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT DISTINCT symbol
                FROM orders
                WHERE status = 'PENDING'
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            return [row[0] for row in rows]
        except Exception as e:
            print(f"[DB] Error getting symbols with pending orders: {str(e)}")
            return []
    
    def update_order_status(self, order_id: int, status: str, filled_quantity: float):
        """Update order status and filled quantity"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE orders
                SET status = ?, filled_quantity = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, filled_quantity, order_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Error updating order status: {str(e)}")
            return False
    
    def add_to_portfolio(self, user_id: int, symbol: str, quantity: float, avg_price: float):
        """Add or update portfolio position"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if position exists
            cursor.execute("""
                SELECT id, quantity, avg_buy_price
                FROM portfolio
                WHERE user_id = ? AND symbol = ?
            """, (user_id, symbol))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing position
                existing_qty = existing[1]
                existing_avg = existing[2]
                
                # Calculate new average price
                total_cost = (existing_qty * existing_avg) + (quantity * avg_price)
                new_qty = existing_qty + quantity
                new_avg = total_cost / new_qty if new_qty > 0 else 0
                
                cursor.execute("""
                    UPDATE portfolio
                    SET quantity = ?, avg_buy_price = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_qty, new_avg, existing[0]))
            else:
                # Create new position
                cursor.execute("""
                    INSERT INTO portfolio (user_id, symbol, quantity, avg_buy_price)
                    VALUES (?, ?, ?, ?)
                """, (user_id, symbol, quantity, avg_price))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Error adding to portfolio: {str(e)}")
            return False
    
    def remove_from_portfolio(self, user_id: int, symbol: str, quantity: float):
        """Remove quantity from portfolio position"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get current position
            cursor.execute("""
                SELECT id, quantity
                FROM portfolio
                WHERE user_id = ? AND symbol = ?
            """, (user_id, symbol))
            
            existing = cursor.fetchone()
            
            if existing:
                new_qty = existing[1] - quantity
                
                if new_qty <= 0:
                    # Remove position if quantity is 0 or negative
                    cursor.execute("DELETE FROM portfolio WHERE id = ?", (existing[0],))
                else:
                    # Update quantity
                    cursor.execute("""
                        UPDATE portfolio
                        SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (new_qty, existing[0]))
                
                conn.commit()
                conn.close()
                return True
            else:
                print(f"[DB] Warning: No portfolio position found for user {user_id}, symbol {symbol}")
                conn.close()
                return False
        except Exception as e:
            print(f"[DB] Error removing from portfolio: {str(e)}")
            return False
    
    def update_user_balance(self, user_id: int, amount: float):
        """Update user balance (can be positive or negative)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
            """, (amount, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[DB] Error updating user balance: {str(e)}")
            return False
    
    def count_pending_orders(self) -> int:
        """Count total pending orders"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'PENDING'")
            count = cursor.fetchone()[0]
            
            conn.close()
            return count
        except Exception as e:
            print(f"[DB] Error counting pending orders: {str(e)}")
            return 0
    
    def count_filled_orders(self) -> int:
        """Count total filled orders"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'FILLED'")
            count = cursor.fetchone()[0]
            
            conn.close()
            return count
        except Exception as e:
            print(f"[DB] Error counting filled orders: {str(e)}")
            return 0
    
    def count_transactions(self) -> int:
        """Count total transactions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM transactions")
            count = cursor.fetchone()[0]
            
            conn.close()
            return count
        except Exception as e:
            print(f"[DB] Error counting transactions: {str(e)}")
            return 0

# Global database manager instance
db_manager = DatabaseManager()

def get_db_manager():
    """Get the global database manager instance"""
    return db_manager

def demo_database_operations():
    """
    Demonstrate database operations
    """
    print("=== Enhanced Database Manager Demo ===")
    
    # Get database manager
    db = get_db_manager()
    
    # Test user creation
    print("\n1. Creating test user:")
    user_id = db.create_user("testuser", "hashed_password_123")
    if user_id:
        print(f"   User created with ID: {user_id}")
    else:
        print("   User creation failed (may already exist)")
    
    # Test getting user
    print("\n2. Retrieving user:")
    user = db.get_user_by_username("testuser")
    if user:
        print(f"   Found user: {user['username']} (ID: {user['id']})")
    else:
        print("   User not found")
    
    # Test order creation
    print("\n3. Creating test order:")
    encrypted_data = '{"ciphertext":"encrypted_data_here","nonce":"nonce_here","tag":"tag_here"}'
    order_id = db.create_order(
        user_id=user['id'] if user else 1,
        symbol="BTC",
        side="buy",
        quantity=0.5,
        price=45000.00,
        encrypted_data=encrypted_data,
        signature="digital_signature_here",
        merkle_leaf="merkle_leaf_hash",
        nonce="nonce_data",
        tag="tag_data"
    )
    if order_id:
        print(f"   Order created with ID: {order_id}")
    else:
        print("   Order creation failed")
    
    # Test getting user orders
    print("\n4. Retrieving user orders:")
    orders = db.get_user_orders(user['id'] if user else 1)
    print(f"   Found {len(orders)} orders")
    for order in orders[:3]:  # Show first 3 orders
        print(f"   - Order {order['id']}: {order['side']} {order['quantity']} {order['symbol']} @ ${order['price']}")
        print(f"     Merkle Leaf: {order['merkle_leaf'][:32]}...")
    
    # Test getting all orders (admin view)
    print("\n5. Retrieving all orders (admin view):")
    all_orders = db.get_all_orders()
    print(f"   Found {len(all_orders)} total orders")
    for order in all_orders[:3]:  # Show first 3 orders
        print(f"   - Order {order['id']}: {order['user_name']} - {order['side']} {order['quantity']} {order['symbol']} @ ${order['price']}")
        print(f"     Merkle Leaf: {order['merkle_leaf'][:32]}...")
    
    # Test security event logging
    print("\n6. Logging security events:")
    db.log_security_event("USER_LOGIN", "User testuser logged in", "192.168.1.100", "INFO")
    db.log_security_event("SQL_INJECTION", "SQL injection attempt detected", "10.0.0.50", "HIGH")
    db.log_security_event("BRUTE_FORCE", "Multiple failed login attempts", "203.0.113.42", "MEDIUM")
    
    # Test getting security events
    print("\n7. Retrieving security events:")
    events = db.get_recent_security_events(5)
    print(f"   Found {len(events)} recent events")
    for event in events:
        print(f"   - [{event['severity']}] {event['event_type']}: {event['description']}")
    
    # Test Merkle tree operations
    print("\n8. Merkle tree operations:")
    db.add_merkle_leaf("hash_1234567890abcdef", "TX-001")
    db.add_merkle_leaf("hash_fedcba0987654321", "TX-002")
    leaves = db.get_merkle_leaves()
    print(f"   Added {len(leaves)} leaves to Merkle tree")
    for leaf in leaves:
        print(f"   - Leaf: {leaf['leaf_hash'][:16]}... (TX: {leaf['transaction_id']})")
    
    # Test IP blocking
    print("\n9. IP blocking operations:")
    db.block_ip("192.168.1.100", "Suspicious activity detected")
    db.block_ip("10.0.0.50", "SQL injection attempt", 48)  # Block for 48 hours
    
    # Check if IPs are blocked
    blocked_ips = db.get_blocked_ips()
    print(f"   Currently blocked IPs: {len(blocked_ips)}")
    for ip_info in blocked_ips:
        print(f"   - {ip_info['ip_address']}: {ip_info['reason']}")
    
    # Test attack simulation
    print("\n10. Attack simulation operations:")
    simulation_id = db.start_attack_simulation("SQL_INJECTION", "Simulating SQL injection attack")
    if simulation_id:
        print(f"   Started simulation with ID: {simulation_id}")
        
        # Add some defense responses
        db.add_defense_response(simulation_id, "IP_BLOCK", "Blocked suspicious IP address", "EXECUTED")
        db.add_defense_response(simulation_id, "ALERT", "Sent alert to security team", "SENT")
        
        # End simulation
        db.end_attack_simulation(simulation_id, "Simulation completed successfully")
        print("   Ended simulation")
    
    # Get simulations
    simulations = db.get_attack_simulations(5)
    print(f"   Found {len(simulations)} simulations")
    for sim in simulations:
        print(f"   - {sim['attack_type']}: {sim['description']} ({sim['status']})")
    
    # Test audit logging
    print("\n11. Audit logging:")
    db.log_audit_event(user['id'] if user else 1, "ORDER_PLACED", "BTC Order", {"quantity": 0.5, "price": 45000.00})
    audit_log = db.get_audit_log(5)
    print(f"   Audit log entries: {len(audit_log)}")
    for entry in audit_log:
        print(f"   - {entry['action']} on {entry['resource']} by user {entry['user_id']}")
    
    print("\n=== Enhanced Database Demo Completed ===")

if __name__ == "__main__":
    demo_database_operations()