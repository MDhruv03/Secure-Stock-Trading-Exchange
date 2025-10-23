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
from security.blue_team.defense_system import IntrusionDetectionSystem


# =========================
# API Router Setup
# =========================
router = APIRouter()

# Initialize Blue Team Intrusion Detection System
ids_system = IntrusionDetectionSystem()

## =========================
# Pydantic Models for Request/Response Validation
## =========================
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

## =========================
# Dependency Injection & Auth Helpers
## =========================
def get_current_user(request: Request):
    """Get current user from request"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="No valid authentication token provided")
    
    token = auth_header.split(' ')[1]
    
    # For demo purposes, we'll use a simplified token validation
    # In production, you would validate the JWT token properly
    try:
        # Get auth service to validate token
        auth_service = get_auth_service()
        user = auth_service.verify_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

## =========================
# Authentication Endpoints
## =========================
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
    
    # For demo purposes, set a default user ID if not provided
    if "user_id" not in result:
        result["user_id"] = 1
    
    # Add user role if not present
    if "role" not in result:
        result["role"] = "trader"
    
    return result

@router.post("/api/auth/logout")
async def logout_user(request: Request, authorization: str = Header(None)):
    """Logout current user"""
    # Extract session token from authorization header
    session_token = None
    if authorization and authorization.startswith("Bearer "):
        session_token = authorization[7:]  # Remove "Bearer " prefix
    
    auth_service = get_auth_service()
    # Look up session in DB to get user_id
    db = auth_service.db
    print(f"[DEBUG] Logout requested. Session token: {session_token}")
    session = db.get_session(session_token)
    print(f"[DEBUG] Session lookup result: {session}")
    if session and session.get("user_id"):
        user_id = session["user_id"]
        result = auth_service.logout_user(user_id, session_token)
        if not result:
            print("[DEBUG] Logout failed during session invalidation.")
            # Still return success for idempotency
    else:
        print("[DEBUG] Invalid or expired session. Returning success for idempotency.")
    print(f"[DEBUG] Logout endpoint returning success.")
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

## =========================
# Trading Endpoints
## =========================
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

## =========================
# Search Endpoint
## =========================
@router.post("/api/search")
async def search_trades(search_data: SearchRequest, request: Request):
    """Search trades by keyword"""
    # Get client IP for security monitoring
    client_host = request.client.host if request.client else "unknown"
    
    trading_service = get_trading_service()
    results = trading_service.search_trades(search_data.keyword)
    
    return {"results": results, "count": len(results)}

## =========================
# Security Endpoints
## =========================
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

## =========================
# Simulation Endpoints
## =========================
@router.post("/api/security/simulate/sql_injection")
async def simulate_sql_injection(request: Request):
    """Simulate SQL injection attack with Blue Team defense"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Simulate malicious SQL query
    malicious_query = "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --"
    
    # Blue Team: Check for SQL injection
    ids_result = ids_system.check_sql_injection(malicious_query, client_host)
    
    # Log the simulation event
    db.log_security_event(
        "SQL_INJECTION_ATTEMPT",
        f"SQL Injection simulation from {client_host}",
        client_host,
        "WARNING" if ids_result["detected"] else "INFO"
    )
    
    if ids_result["detected"]:
        # Blue Team blocked the attack
        db.log_security_event(
            "ATTACK_BLOCKED",
            f"SQL Injection blocked by IDS. Patterns: {', '.join(ids_result['patterns'])}",
            client_host,
            "INFO"
        )
        
        return {
            "success": False,
            "blocked": True,
            "message": "SQL Injection attack detected and blocked by IDS",
            "simulation_id": "SIM-SQLI-001",
            "detected_patterns": ids_result["patterns"],
            "threat_level": ids_result["threat_level"],
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: SQL injection attack initiated"},
                {"phase": "pattern_scanning", "status": "completed", "description": f"🔵 BLUE_TEAM: Detected {len(ids_result['patterns'])} malicious patterns"},
                {"phase": "payload_delivery", "status": "blocked", "description": "⛔ Attack payload delivery blocked by IDS"},
                {"phase": "defense_response", "status": "completed", "description": "🛡️ DEFENSE: Automated blocking activated - IDS signature match"}
            ]
        }
    else:
        return {
            "success": True,
            "blocked": False,
            "message": "SQL Injection simulation completed (bypassed detection)",
            "simulation_id": "SIM-SQLI-001",
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: SQL injection attack initiated"},
                {"phase": "payload_delivery", "status": "completed", "description": "⚠️ WARNING: Attack payload delivered successfully"},
                {"phase": "database_compromise", "status": "completed", "description": "⚠️ CRITICAL: Database potentially compromised"}
            ]
        }

@router.post("/api/security/simulate/brute_force")
async def simulate_brute_force(request: Request):
    """Simulate brute force attack with Blue Team defense"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    
    # Blue Team: Check for brute force attack
    ids_result = ids_system.check_brute_force(client_host, attempts=50)
    
    # Log the simulation event
    db.log_security_event(
        "BRUTE_FORCE_ATTEMPT",
        f"Brute Force simulation from {client_host} - {ids_result['attempt_count']} attempts",
        client_host,
        "CRITICAL" if ids_result["blocked"] else "WARNING"
    )
    
    if ids_result["blocked"]:
        # Blue Team blocked and blacklisted the IP
        db.log_security_event(
            "IP_BLOCKED",
            f"IP {client_host} blacklisted for {ids_result['block_duration']} minutes due to brute force",
            client_host,
            "INFO"
        )
        
        return {
            "success": False,
            "blocked": True,
            "message": f"Brute Force attack blocked - IP blacklisted for {ids_result['block_duration']} minutes",
            "simulation_id": "SIM-BRUTE-001",
            "attempt_count": ids_result["attempt_count"],
            "threshold": ids_result["threshold"],
            "block_duration": ids_result["block_duration"],
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: Brute force attack initiated"},
                {"phase": "credential_stuffing", "status": "detected", "description": f"🔵 BLUE_TEAM: Detected {ids_result['attempt_count']} rapid login attempts"},
                {"phase": "rate_limiting", "status": "activated", "description": "🛡️ DEFENSE: Rate limiting triggered - threshold exceeded"},
                {"phase": "ip_blacklist", "status": "completed", "description": f"🛡️ DEFENSE: IP blacklisted for {ids_result['block_duration']} minutes"}
            ]
        }
    else:
        return {
            "success": True,
            "blocked": False,
            "message": "Brute Force simulation in progress (under threshold)",
            "simulation_id": "SIM-BRUTE-001",
            "attempt_count": ids_result["attempt_count"],
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: Brute force attack initiated"},
                {"phase": "credential_stuffing", "status": "in_progress", "description": f"⚠️ WARNING: {ids_result['attempt_count']} login attempts detected"}
            ]
        }

@router.post("/api/security/simulate/replay")
async def simulate_replay(request: Request):
    """Simulate replay attack with Blue Team defense"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    crypto_service = get_crypto_service()
    
    # Simulate captured transaction
    fake_transaction = {
        "from": "user123",
        "to": "attacker",
        "amount": 1000,
        "timestamp": int(time.time()) - 3600  # Old timestamp (1 hour ago)
    }
    
    # Blue Team: Check for replay attack
    ids_result = ids_system.check_replay_attack(fake_transaction, client_host)
    
    # Log the simulation event
    db.log_security_event(
        "REPLAY_ATTACK_ATTEMPT",
        f"Replay attack simulation from {client_host}",
        client_host,
        "WARNING"
    )
    
    if ids_result["blocked"]:
        # Blue Team blocked the attack
        db.log_security_event(
            "ATTACK_BLOCKED",
            f"Replay attack blocked: {ids_result['reason']}",
            client_host,
            "INFO"
        )
        
        return {
            "success": False,
            "blocked": True,
            "message": f"Replay attack blocked - {ids_result['reason']}",
            "simulation_id": "SIM-REPLAY-001",
            "timestamp_age": ids_result["timestamp_age"],
            "nonce_check": ids_result["nonce_valid"],
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: Replay attack initiated"},
                {"phase": "transaction_capture", "status": "completed", "description": "🔴 RED_TEAM: Captured transaction from network"},
                {"phase": "replay_attempt", "status": "blocked", "description": "🔵 BLUE_TEAM: Replay detected - stale timestamp or invalid nonce"},
                {"phase": "defense_response", "status": "completed", "description": f"🛡️ DEFENSE: {ids_result['reason']}"}
            ]
        }
    else:
        return {
            "success": True,
            "blocked": False,
            "message": "Replay attack succeeded (defense bypassed)",
            "simulation_id": "SIM-REPLAY-001",
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: Replay attack initiated"},
                {"phase": "transaction_capture", "status": "completed", "description": "🔴 RED_TEAM: Transaction captured"},
                {"phase": "replay_attempt", "status": "completed", "description": "⚠️ WARNING: Transaction replayed successfully"}
            ]
        }

@router.post("/api/security/simulate/mitm")
async def simulate_mitm(request: Request):
    """Simulate MITM attack with Blue Team defense"""
    # Get client IP
    client_host = request.client.host if request.client else "unknown"
    
    db = get_db_manager()
    crypto_service = get_crypto_service()
    
    # Simulate intercepted data
    intercepted_data = {
        "user_id": "12345",
        "transaction": "buy_order",
        "amount": 500
    }
    
    # Blue Team: Check encryption and certificate validation
    ids_result = ids_system.check_mitm_attack(intercepted_data, client_host)
    
    # Log the simulation event
    db.log_security_event(
        "MITM_ATTACK_ATTEMPT",
        f"MITM attack simulation from {client_host}",
        client_host,
        "CRITICAL" if not ids_result["encrypted"] else "INFO"
    )
    
    if ids_result["blocked"]:
        # Blue Team blocked the attack due to encryption
        db.log_security_event(
            "ATTACK_BLOCKED",
            f"MITM attack thwarted by encryption - {ids_result['encryption_type']}",
            client_host,
            "INFO"
        )
        
        return {
            "success": False,
            "blocked": True,
            "message": f"MITM attack blocked - Data protected by {ids_result['encryption_type']}",
            "simulation_id": "SIM-MITM-001",
            "encryption_type": ids_result["encryption_type"],
            "certificate_valid": ids_result["certificate_valid"],
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: MITM attack initiated"},
                {"phase": "traffic_interception", "status": "completed", "description": "🔴 RED_TEAM: Network traffic intercepted"},
                {"phase": "decryption_attempt", "status": "failed", "description": "🔵 BLUE_TEAM: Decryption failed - AES-256-GCM protection"},
                {"phase": "defense_response", "status": "completed", "description": f"🛡️ DEFENSE: {ids_result['encryption_type']} encryption verified"}
            ]
        }
    else:
        return {
            "success": True,
            "blocked": False,
            "message": "MITM attack succeeded (unencrypted connection)",
            "simulation_id": "SIM-MITM-001",
            "phases": [
                {"phase": "attack_initiation", "status": "completed", "description": "🔴 RED_TEAM: MITM attack initiated"},
                {"phase": "traffic_interception", "status": "completed", "description": "🔴 RED_TEAM: Traffic intercepted"},
                {"phase": "data_manipulation", "status": "completed", "description": "⚠️ CRITICAL: Data intercepted and manipulated"}
            ]
        }

## =========================
# Real-Time Data Endpoints
## =========================
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
    # Allow access if:
    # 1. User is accessing their own portfolio
    # 2. User has admin role
    # 3. For demo purposes, allow access to portfolio 1
    if user_id == 1 or current_user["id"] == user_id or current_user.get("role") == "admin":
        trading_service = get_trading_service()
        portfolio = trading_service.get_user_portfolio(user_id)
        return {"portfolio": portfolio}
    
    raise HTTPException(
        status_code=403,
        detail="Access denied. You do not have permission to access this portfolio."
    )

@router.get("/api/data/transactions/{user_id}")
async def get_user_transactions(user_id: int, current_user: dict = Depends(get_current_user)):
    """Get user transactions"""
    # Verify user authorization
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access these transactions")
    
    db = get_db_manager()
    transactions = db.get_all_transactions(user_id)
    
    return {"transactions": transactions}

## =========================
# Logs, Orders, and Attacks Views Endpoints
## =========================
@router.get("/api/logs/security")
async def get_security_logs():
    """Get security logs with pagination"""
    db = get_db_manager()
    events = db.get_recent_security_events(50)
    
    return {"logs": events}

@router.get("/api/logs/audit")
async def get_audit_logs(limit: int = 50):
    """Get audit logs with pagination"""
    db = get_db_manager()
    audit_log = db.get_audit_log(limit)
    
    return {"logs": audit_log}

@router.get("/api/logs/user-activity")
async def get_user_activity_logs():
    """Get user activity logs (logins, logouts, registrations, etc.)"""
    db = get_db_manager()
    
    # Get events filtered by user activity types (up to 100 most recent)
    event_types = ["USER_LOGIN", "USER_LOGOUT", "USER_REGISTERED"]
    events = db.get_security_events_by_type(event_types, limit=100)
    
    # Add logout_time field for logout events for backward compatibility
    user_activity = []
    for event in events:
        entry = dict(event)
        if event["event_type"] == "USER_LOGOUT":
            entry["logout_time"] = event.get("created_at")
        user_activity.append(entry)
    
    return {"logs": user_activity}

@router.get("/api/orders/user/{user_id}")
async def get_user_orders_api(user_id: int):  # Removed current_user dependency for demo
    """Get orders for a specific user"""
    # For demo purposes, we'll return orders for the requested user_id
    # In a real system, we would have proper authorization checks
    
    trading_service = get_trading_service()
    orders = trading_service.get_user_orders(user_id)
    
    return {"orders": orders}

@router.get("/api/orders/all")
async def get_all_orders_api():
    """Get all orders (admin view) - returns all orders for demo"""
    trading_service = get_trading_service()
    orders = trading_service.get_all_orders()
    
    return {"orders": orders}

@router.get("/api/attacks/simulations")
async def get_attack_simulations():
    """Get attack simulation data"""
    db = get_db_manager()
    simulations = db.get_attack_simulations(20)
    
    # Get defense responses for each simulation
    for sim in simulations:
        responses = db.get_defense_responses(sim["id"])
        sim["responses"] = responses
    
    return {"simulations": simulations}

@router.get("/api/security/blue_team/status")
async def get_blue_team_status():
    """Get real-time Blue Team IDS status"""
    db = get_db_manager()
    
    # Get recent security events (last hour)
    recent_events = db.get_recent_security_events(100)
    
    # Count events by type
    sql_injection_detected = sum(1 for e in recent_events if e.get("event_type") == "SQL_INJECTION_DETECTED")
    brute_force_detected = sum(1 for e in recent_events if e.get("event_type") == "BRUTE_FORCE_DETECTED")
    replay_detected = sum(1 for e in recent_events if e.get("event_type") == "REPLAY_ATTACK_DETECTED")
    mitm_detected = sum(1 for e in recent_events if e.get("event_type") == "MITM_ATTACK_DETECTED")
    attacks_blocked = sum(1 for e in recent_events if e.get("event_type") in ["ATTACK_BLOCKED", "IP_BLOCKED"])
    
    # Get blocked IPs
    blocked_ips = db.get_blocked_ips()
    
    # Calculate threat level
    total_attacks = sql_injection_detected + brute_force_detected + replay_detected + mitm_detected
    threat_level = "LOW"
    if total_attacks > 20:
        threat_level = "CRITICAL"
    elif total_attacks > 10:
        threat_level = "HIGH"
    elif total_attacks > 5:
        threat_level = "MEDIUM"
    
    # IDS status
    ids_active = ids_system.monitoring_active
    
    return {
        "ids_active": ids_active,
        "threat_level": threat_level,
        "monitoring_uptime": "Active" if ids_active else "Inactive",
        "detections": {
            "sql_injection": sql_injection_detected,
            "brute_force": brute_force_detected,
            "replay_attack": replay_detected,
            "mitm_attack": mitm_detected,
            "total": total_attacks
        },
        "defenses": {
            "attacks_blocked": attacks_blocked,
            "ips_blacklisted": len(blocked_ips),
            "defense_rate": round((attacks_blocked / total_attacks * 100) if total_attacks > 0 else 100, 1)
        },
        "recent_events": recent_events[:10],  # Last 10 events
        "blocked_ips": blocked_ips[:10],  # Last 10 blocked IPs
        "timestamp": int(time.time())
    }

## =========================
# WebSocket Endpoint for Real-Time Updates
## =========================
@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time updates"""
    await handle_websocket_messages(websocket, user_id)

## =========================
# Health Check Endpoint
## =========================
@router.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "secure-trading-platform",
        "timestamp": int(time.time())
    }

## =========================
# Encrypted Data Operations Endpoints
## =========================
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