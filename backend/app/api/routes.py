from fastapi import APIRouter, HTTPException, Depends, Request, Header, WebSocket
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import json
import time

# Import platform components
from backend.app.services.auth_service import get_auth_service
from backend.app.services.trading_service import get_trading_service
from backend.app.utils.database import get_db_manager
from backend.app.services.crypto_service import get_crypto_service
from backend.app.services.security_service import get_security_service
from backend.app.services.websocket_service import manager, handle_websocket_messages

# Create router
router = APIRouter()

# Pydantic models for request/response validation
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class OrderCreate(BaseModel):
    symbol: str
    side: str
    quantity: float
    price: float

class SearchRequest(BaseModel):
    keyword: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

# Dependency injection
def get_current_user(request: Request):
    """Get current user from request (simplified for demo)"""
    # In a real implementation, this would verify the JWT token
    # For this demo, we'll return a mock user
    return {
        "id": 12345,
        "username": "demo_user",
        "role": "trader"
    }

# Authentication endpoints
@router.post("/api/auth/register")
async def register_user(user_data: UserCreate, request: Request):
    """Register a new user"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    auth_service = get_auth_service()
    result = auth_service.register_user(user_data.username, user_data.password)
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    
    return result

@router.post("/api/auth/login")
async def login_user(user_data: UserLogin, request: Request):
    """Authenticate a user"""
    # Get client IP and user agent
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    auth_service = get_auth_service()
    result = auth_service.authenticate_user(
        user_data.username, 
        user_data.password,
        ip_address=client_host,
        user_agent=user_agent
    )
    
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])
    
    return result

@router.post("/api/auth/logout")
async def logout_user(request: Request, authorization: str = Header(None)):
    """Logout current user"""
    # Extract session token from authorization header
    session_token = None
    if authorization and authorization.startswith("Bearer "):
        session_token = authorization[7:]  # Remove "Bearer " prefix
    
    auth_service = get_auth_service()
    
    # For demo, we'll use a mock user ID
    # In a real implementation, we would extract this from the token
    user_id = 12345
    
    result = auth_service.logout_user(user_id, session_token)
    
    if not result:
        raise HTTPException(status_code=500, detail="Logout failed")
    
    return {"success": True, "message": "Logged out successfully"}

@router.post("/api/auth/change-password")
async def change_password(password_data: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    """Change user password"""
    auth_service = get_auth_service()
    result = auth_service.change_password(
        current_user["id"],
        password_data.old_password,
        password_data.new_password
    )
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    
    return result

# Trading endpoints
@router.post("/api/trading/orders")
async def create_order(order_data: OrderCreate, request: Request, current_user: dict = Depends(get_current_user)):
    """Create a new secure order"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    trading_service = get_trading_service()
    result = trading_service.create_order(
        user_id=current_user["id"],
        symbol=order_data.symbol,
        side=order_data.side,
        quantity=order_data.quantity,
        price=order_data.price
    )
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    
    return result

@router.get("/api/trading/orders")
async def get_user_orders(current_user: dict = Depends(get_current_user)):
    """Get all orders for current user"""
    trading_service = get_trading_service()
    orders = trading_service.get_user_orders(current_user["id"])
    
    return {"orders": orders}

@router.get("/api/trading/orders/all")
async def get_all_orders():
    """Get all orders (admin view)"""
    trading_service = get_trading_service()
    orders = trading_service.get_all_orders()
    
    return {"orders": orders}

@router.get("/api/trading/orderbook/{symbol}")
async def get_order_book(symbol: str):
    """Get order book for a symbol"""
    trading_service = get_trading_service()
    order_book = trading_service.get_order_book(symbol)
    
    return order_book

@router.get("/api/trading/vwap/{symbol}")
async def get_vwap(symbol: str):
    """Get VWAP for a symbol"""
    trading_service = get_trading_service()
    vwap = trading_service.calculate_vwap(symbol)
    
    return {"symbol": symbol, "vwap": vwap}

# Search endpoint
@router.post("/api/search")
async def search_trades(search_data: SearchRequest, request: Request):
    """Search trades by keyword"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    trading_service = get_trading_service()
    results = trading_service.search_trades(search_data.keyword)
    
    return {"results": results, "count": len(results)}

# Security endpoints
@router.get("/api/security/events")
async def get_security_events():
    """Get recent security events"""
    db = get_db_manager()
    events = db.get_recent_security_events(50)
    
    return {"events": events}

@router.get("/api/security/blocked_ips")
async def get_blocked_ips():
    """Get currently blocked IPs"""
    security = get_security_service()
    blocked_ips = security.get_blocked_ips()
    
    return {"blocked_ips": blocked_ips}

@router.post("/api/security/unblock_ip/{ip_address}")
async def unblock_ip(ip_address: str):
    """Unblock an IP address"""
    security = get_security_service()
    result = security.unblock_ip(ip_address)
    
    if not result:
        raise HTTPException(status_code=500, detail="Failed to unblock IP")
    
    return {"success": True, "message": f"IP {ip_address} unblocked successfully"}

@router.get("/api/security/merkle_leaves")
async def get_merkle_leaves():
    """Get Merkle tree leaves"""
    db = get_db_manager()
    leaves = db.get_merkle_leaves()
    
    return {"leaves": leaves}

@router.get("/api/security/audit_log")
async def get_audit_log():
    """Get audit log"""
    db = get_db_manager()
    audit_log = db.get_audit_log(100)
    
    return {"audit_log": audit_log}

# Simulation endpoints
@router.post("/api/security/simulate/sql_injection")
async def simulate_sql_injection(request: Request):
    """Simulate SQL injection attack"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Log the simulation event
    db.log_security_event(
        "SIMULATION_STARTED",
        "SQL Injection simulation initiated",
        client_host,
        "INFO"
    )
    
    return {
        "success": True,
        "message": "SQL Injection simulation started",
        "simulation_id": "SIM-SQLI-001",
        "phases": [
            {"phase": "attack_initiation", "status": "completed", "description": "Attack vector initiated"},
            {"phase": "pattern_scanning", "status": "completed", "description": "Scanning for SQL injection patterns"},
            {"phase": "payload_delivery", "status": "completed", "description": "Attack payload delivered"},
            {"phase": "defense_response", "status": "completed", "description": "Automated defense mechanisms activated"}
        ]
    }

@router.post("/api/security/simulate/brute_force")
async def simulate_brute_force(request: Request):
    """Simulate brute force attack"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Log the simulation event
    db.log_security_event(
        "SIMULATION_STARTED",
        "Brute Force simulation initiated",
        client_host,
        "INFO"
    )
    
    return {
        "success": True,
        "message": "Brute Force simulation started",
        "simulation_id": "SIM-BRUTE-001",
        "phases": [
            {"phase": "attack_initiation", "status": "completed", "description": "Brute force attack vector initiated"},
            {"phase": "credential_stuffing", "status": "completed", "description": "Attempting credential stuffing"},
            {"phase": "pattern_analysis", "status": "completed", "description": "Analyzing login attempt patterns"},
            {"phase": "defense_response", "status": "completed", "description": "Automated defense mechanisms activated"}
        ]
    }

@router.post("/api/security/simulate/replay")
async def simulate_replay(request: Request):
    """Simulate replay attack"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Log the simulation event
    db.log_security_event(
        "SIMULATION_STARTED",
        "Replay Attack simulation initiated",
        client_host,
        "INFO"
    )
    
    return {
        "success": True,
        "message": "Replay Attack simulation started",
        "simulation_id": "SIM-REPLAY-001",
        "phases": [
            {"phase": "attack_initiation", "status": "completed", "description": "Replay attack vector initiated"},
            {"phase": "transaction_capture", "status": "completed", "description": "Capturing transaction data"},
            {"phase": "replay_attempt", "status": "completed", "description": "Attempting to replay captured transaction"},
            {"phase": "defense_response", "status": "completed", "description": "Automated defense mechanisms activated"}
        ]
    }

@router.post("/api/security/simulate/mitm")
async def simulate_mitm(request: Request):
    """Simulate MITM attack"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Log the simulation event
    db.log_security_event(
        "SIMULATION_STARTED",
        "MITM Attack simulation initiated",
        client_host,
        "INFO"
    )
    
    return {
        "success": True,
        "message": "MITM Attack simulation started",
        "simulation_id": "SIM-MITM-001",
        "phases": [
            {"phase": "attack_initiation", "status": "completed", "description": "MITM attack vector initiated"},
            {"phase": "traffic_interception", "status": "completed", "description": "Intercepting network traffic"},
            {"phase": "data_manipulation", "status": "completed", "description": "Manipulating intercepted data"},
            {"phase": "defense_response", "status": "completed", "description": "Automated defense mechanisms activated"}
        ]
    }

# Real-time data endpoints
@router.get("/api/data/orders/latest")
async def get_latest_orders(limit: int = 10):
    """Get latest orders for real-time updates"""
    trading_service = get_trading_service()
    orders = trading_service.get_all_orders()
    
    # Return only the latest orders
    latest_orders = orders[:limit] if len(orders) > limit else orders
    
    return {"orders": latest_orders, "count": len(latest_orders)}

@router.get("/api/data/market/overview")
async def get_market_overview():
    """Get market overview data"""
    trading_service = get_trading_service()
    
    # Get data for multiple symbols
    symbols = ["BTC", "ETH", "ADA", "DOT", "SOL"]
    market_data = {}
    
    for symbol in symbols:
        order_book = trading_service.get_order_book(symbol)
        vwap = trading_service.calculate_vwap(symbol)
        
        market_data[symbol] = {
            "symbol": symbol,
            "vwap": vwap,
            "buy_orders": len(order_book["buy_orders"]),
            "sell_orders": len(order_book["sell_orders"]),
            "best_bid": order_book["buy_orders"][0]["price"] if order_book["buy_orders"] else 0,
            "best_ask": order_book["sell_orders"][0]["price"] if order_book["sell_orders"] else 0
        }
    
    return {"market_data": market_data, "timestamp": int(time.time())}

# Real-time data endpoints
@router.get("/api/data/orders/latest")
async def get_latest_orders(limit: int = 10):
    """Get latest orders for real-time updates"""
    trading_service = get_trading_service()
    orders = trading_service.get_all_orders()
    
    # Return only the latest orders
    latest_orders = orders[:limit] if len(orders) > limit else orders
    
    return {"orders": latest_orders, "count": len(latest_orders)}

@router.get("/api/data/market/overview")
async def get_market_overview():
    """Get market overview data"""
    trading_service = get_trading_service()
    
    # Get data for multiple symbols
    symbols = ["BTC", "ETH", "ADA", "DOT", "SOL"]
    market_data = {}
    
    for symbol in symbols:
        order_book = trading_service.get_order_book(symbol)
        vwap = trading_service.calculate_vwap(symbol)
        
        market_data[symbol] = {
            "symbol": symbol,
            "vwap": vwap,
            "buy_orders": len(order_book["buy_orders"]),
            "sell_orders": len(order_book["sell_orders"]),
            "best_bid": order_book["buy_orders"][0]["price"] if order_book["buy_orders"] else 0,
            "best_ask": order_book["sell_orders"][0]["price"] if order_book["sell_orders"] else 0
        }
    
    return {"market_data": market_data, "timestamp": int(time.time())}

@router.get("/api/data/portfolio/{user_id}")
async def get_user_portfolio(user_id: int, current_user: dict = Depends(get_current_user)):
    """Get user portfolio"""
    # Verify user authorization
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this portfolio")
    
    trading_service = get_trading_service()
    portfolio = trading_service.get_user_portfolio(user_id)
    
    return {"portfolio": portfolio}

@router.get("/api/data/transactions/{user_id}")
async def get_user_transactions(user_id: int, current_user: dict = Depends(get_current_user)):
    """Get user transactions"""
    # Verify user authorization
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access these transactions")
    
    db = get_db_manager()
    transactions = db.get_all_transactions(user_id)
    
    return {"transactions": transactions}

# WebSocket endpoint for real-time updates
@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time updates"""
    await handle_websocket_messages(websocket, user_id)

# Health check endpoint
@router.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "secure-trading-platform",
        "timestamp": int(time.time())
    }

# New endpoints for encrypted data operations
@router.post("/api/crypto/encrypt")
async def encrypt_data(data: dict, request: Request):
    """Encrypt data using AES-256-GCM"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    encrypted_package = crypto_service.encrypt_data(data)
    
    return {"encrypted_data": encrypted_package}

@router.post("/api/crypto/decrypt")
async def decrypt_data(encrypted_package: dict, request: Request):
    """Decrypt data using AES-256-GCM"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    decrypted_data = crypto_service.decrypt_data(encrypted_package)
    
    return {"decrypted_data": decrypted_data}

@router.post("/api/crypto/sign")
async def sign_data(data: dict, request: Request):
    """Sign data using RSA digital signature"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    signature = crypto_service.sign_data(data)
    
    return {"signature": signature}

@router.post("/api/crypto/verify")
async def verify_signature(data: dict, signature: str, request: Request):
    """Verify RSA digital signature"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    is_valid = crypto_service.verify_signature(data, signature)
    
    return {"valid": is_valid}

@router.post("/api/crypto/merkle/generate")
async def generate_merkle_root(leaves: List[str], request: Request):
    """Generate Merkle tree root from leaves"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    merkle_root = crypto_service.create_merkle_root(leaves)
    
    return {"merkle_root": merkle_root}

@router.post("/api/crypto/hmac/sign")
async def hmac_sign(data: dict, request: Request):
    """Create HMAC signature for message authentication"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    hmac_signature = crypto_service.hmac_sign(data)
    
    return {"hmac_signature": hmac_signature}

@router.post("/api/crypto/hmac/verify")
async def hmac_verify(data: dict, hmac_signature: str, request: Request):
    """Verify HMAC signature"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    crypto_service = get_crypto_service()
    is_valid = crypto_service.hmac_verify(data, hmac_signature)
    
    return {"valid": is_valid}