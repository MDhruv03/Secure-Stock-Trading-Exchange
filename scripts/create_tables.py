import os
import sys

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import create_engine
from app.database import DATABASE_URL, metadata
from app.models import users, orders, trades, merkle_roots, ids_alerts, incidents, blocklist, merkle_trades, encrypted_vwap

def create_tables():
    engine = create_engine(str(DATABASE_URL))
    metadata.create_all(engine)

if __name__ == "__main__":
    create_tables()