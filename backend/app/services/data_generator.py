import random
import time
import logging
from datetime import datetime, timedelta
from backend.app.utils.database import get_db_manager
from backend.app.services.auth_service import get_auth_service
from backend.app.services.crypto_service import get_crypto_service
from backend.app.services.trading_service import get_trading_service

logger = logging.getLogger(__name__)

class DataGenerator:
    def __init__(self):
        self.db = get_db_manager()
        self.auth = get_auth_service()
        self.crypto = get_crypto_service()
        self.trading = get_trading_service()
        
        # Sample data
        self.symbols = ["BTC", "ETH", "ADA", "DOT", "SOL", "XRP", "AVAX", "LINK"]
        self.attack_types = ["SQL_INJECTION", "BRUTE_FORCE", "REPLAY", "MITM"]
        self.event_types = ["USER_LOGIN", "ORDER_PLACED", "TRANSACTION_EXECUTED", "ATTACK_DETECTED", "DEFENSE_ACTIVATED"]
        self.severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.status_options = ["SUCCESS", "FAILED", "PENDING", "IN_PROGRESS"]
    
    def generate_sample_users(self, count=10):
        """Generate sample users"""
        logger.info("Generating sample users...")
        for i in range(count):
            username = f"trader{i+1}"
            password = f"pass{i+1}"
            self.auth.register_user(username, password)
            logger.info(f"Created user: {username}")
    
    def generate_sample_orders(self, count=50):
        """Generate sample orders"""
        logger.info("Generating sample orders...")
        users = self.db.get_all_users()
        
        for _ in range(count):
            user = random.choice(users) if users else {"id": 1}
            symbol = random.choice(self.symbols)
            side = random.choice(["buy", "sell"])
            quantity = round(random.uniform(0.1, 10.0), 2)
            price = round(random.uniform(100, 50000), 2)
            
            result = self.trading.create_order(
                user_id=user["id"],
                symbol=symbol,
                side=side,
                quantity=quantity,
                price=price
            )
            
            logger.info(f"Created order: {side} {quantity} {symbol} @ ${price} for user {user['id']}")
    
    def generate_sample_transactions(self, count=30):
        """Generate sample transactions"""
        logger.info("Generating sample transactions...")
        orders = self.db.get_all_orders()
        
        for order in orders[:count]:
            result = self.trading.execute_order(order["id"])
            if result["success"]:
                logger.info(f"Executed order {order['id']}")
    
    def generate_security_events(self, count=100):
        """Generate sample security events"""
        logger.info("Generating security events...")
        for _ in range(count):
            event_type = random.choice(self.event_types)
            description = f"Sample security event: {event_type}"
            source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            severity = random.choice(self.severities)
            
            self.db.log_security_event(
                event_type=event_type,
                description=description,
                source_ip=source_ip,
                severity=severity,
                details={"sample": "data"}
            )
            
            logger.info(f"Created security event: {event_type} ({severity})")
    
    def generate_attack_simulations(self, count=20):
        """Generate sample attack simulations"""
        logger.info("Generating attack simulations...")
        for _ in range(count):
            attack_type = random.choice(self.attack_types)
            description = f"Simulated {attack_type} attack"
            
            sim_id = self.db.start_attack_simulation(attack_type, description)
            if sim_id:
                # Add defense responses
                response_types = ["BLOCK_IP", "ALERT", "LOCKOUT", "RATE_LIMIT"]
                for response_type in random.sample(response_types, 2):
                    self.db.add_defense_response(
                        sim_id,
                        response_type,
                        f"Automated {response_type} response activated",
                        random.choice(self.status_options)
                    )
                
                # End simulation
                self.db.end_attack_simulation(sim_id, "Simulation completed with automated defenses")
                logger.info(f"Created attack simulation: {attack_type}")
    
    def generate_market_data(self):
        """Generate and update market data"""
        logger.info("Generating market data...")
        for symbol in self.symbols:
            base_price = random.uniform(100, 50000)
            for _ in range(24):  # 24 hours of data
                price = round(base_price * random.uniform(0.95, 1.05), 2)
                volume = round(random.uniform(100, 10000), 2)
                
                # Update market data
                self.db.update_market_data(
                    symbol=symbol,
                    price=price,
                    volume=volume,
                    timestamp=datetime.now() - timedelta(hours=_)
                )
                logger.info(f"Created market data for {symbol}")
    
    def generate_all_sample_data(self):
        """Generate all types of sample data"""
        logger.info("Starting sample data generation...")
        self.generate_sample_users()
        self.generate_sample_orders()
        self.generate_sample_transactions()
        self.generate_security_events()
        self.generate_attack_simulations()
        self.generate_market_data()
        logger.info("Sample data generation completed!")

def generate_sample_data():
    """Helper function to generate all sample data"""
    generator = DataGenerator()
    generator.generate_all_sample_data()

if __name__ == "__main__":
    generate_sample_data()
