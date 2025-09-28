"""
Security Middleware for the Secure Trading Platform
"""
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Callable, Awaitable

from backend.app.services.security_service import get_security_service
from backend.app.utils.database import get_db_manager

security_service = get_security_service()
db_manager = get_db_manager()

async def security_middleware(request: Request, call_next: Callable[[Request], Awaitable]):
    """
    Enhanced security middleware for request monitoring and filtering
    """
    # Get client information
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Check if IP is blocked (checking the set directly)
    if client_host in security_service.blocked_ips:
        # Log the blocked attempt using db manager
        db_manager.log_security_event(
            "REQUEST_BLOCKED",
            f"Blocked request from {client_host}",
            client_host,
            "HIGH",
            {"method": request.method, "url": str(request.url), "user_agent": user_agent}
        )
        return JSONResponse(
            content={"error": "Access denied", "message": "Your IP has been blocked for security reasons."},
            status_code=403
        )
    
    # Check for suspicious user agent
    security_service.check_suspicious_user_agent(user_agent, client_host)
    
    # Continue with the request
    try:
        response = await call_next(request)
        
        # Log successful request using db manager
        db_manager.log_security_event(
            "REQUEST_SUCCESS",
            f"Allowed request from {client_host}",
            client_host,
            "INFO",
            {
                "method": request.method, 
                "url": str(request.url), 
                "user_agent": user_agent,
                "status_code": response.status_code
            }
        )
        
        return response
    except Exception as e:
        # Log error using db manager
        db_manager.log_security_event(
            "REQUEST_ERROR",
            f"Error processing request from {client_host}: {str(e)}",
            client_host,
            "ERROR",
            {
                "method": request.method, 
                "url": str(request.url), 
                "user_agent": user_agent,
                "error": str(e)
            }
        )
        raise e