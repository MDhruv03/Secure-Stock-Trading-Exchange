from sqlalchemy import Table, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import metadata

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("username", String, unique=True, index=True),
    Column("password_hash", String), # Renamed from hashed_password
    Column("public_key", String),    # PEM
    Column("private_key", String, nullable=True), # PEM (for lab only; prod would use HSM/keystore)
    Column("role", String, default="customer"), # Keeping for MVP functionality
    Column("balance", Float, default=10000.0), # Keeping for MVP functionality
    Column("created_at", DateTime, default=func.now())
)

orders = Table(
    "orders",
    metadata,
    Column("id", Integer, primary_key=True, index=True), # Changed to Integer
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("stock", String), # Renamed from asset
    Column("qty", Integer), # Renamed from amount, changed to Integer
    Column("side", String), # Renamed from type
    Column("price", Float), # Added
    Column("ciphertext", String), # Added
    Column("nonce", String), # Added
    Column("signature", String), # Added
    Column("created_at", DateTime, default=func.now())
    # Removed 'status'
)

merkle_trades = Table(
    "merkle_trades",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("trade_data", String, unique=True),
)

trades = Table( # Keeping existing trades table as it's used
    "trades",
    metadata,
    Column("id", String, primary_key=True, index=True),
    Column("buy_order_id", String, ForeignKey("orders.id")),
    Column("sell_order_id", String, ForeignKey("orders.id")),
    Column("price", Float),
    Column("amount", Float),
    Column("timestamp", String)
)

merkle_roots = Table(
    "merkle_roots",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("root_hash", String),
    Column("total_leaves", Integer),
    Column("created_at", DateTime, default=func.now())
)

ids_alerts = Table(
    "ids_alerts",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("alert_type", String),
    Column("description", String),
    Column("src_ip", String, nullable=True),
    Column("dst_ip", String, nullable=True),
    Column("raw", String, nullable=True),
    Column("created_at", DateTime, default=func.now())
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("alert_id", Integer, ForeignKey("ids_alerts.id"), nullable=True),
    Column("action", String),
    Column("result", String, nullable=True),
    Column("created_at", DateTime, default=func.now())
)

blocklist = Table(
    "blocklist",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("ip", String, unique=True),
    Column("reason", String, nullable=True),
    Column("created_at", DateTime, default=func.now())
)

encrypted_vwap = Table(
    "encrypted_vwap",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("encrypted_price", String),
    Column("encrypted_quantity", String),
)

login_attempts = Table(
    "login_attempts",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("ip_address", String),
    Column("username", String),
    Column("timestamp", DateTime, default=func.now()),
)