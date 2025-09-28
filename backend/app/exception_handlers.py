"""
Exception handlers for the Secure Trading Platform
"""
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.app.services.security_service import get_security_service
from backend.app.utils.database import get_db_manager

security_service = get_security_service()
db_manager = get_db_manager()

async def not_found_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    db_manager.log_security_event(
        "NOT_FOUND",
        f"404 Not Found for {request.method} {request.url}",
        client_host,
        "LOW",
        {"method": request.method, "url": str(request.url)}
    )
    return HTMLResponse(
        content="<html><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>",
        status_code=404
    )

async def internal_error_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    db_manager.log_security_event(
        "INTERNAL_ERROR",
        f"500 Internal Server Error for {request.method} {request.url}: {str(exc)}",
        client_host,
        "HIGH",
        {"method": request.method, "url": str(request.url), "error": str(exc)}
    )
    return HTMLResponse(
        content="<html><body><h1>500 Internal Server Error</h1><p>An internal server error occurred.</p></body></html>",
        status_code=500
    )

async def forbidden_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    db_manager.log_security_event(
        "FORBIDDEN",
        f"403 Forbidden for {request.method} {request.url}",
        client_host,
        "MEDIUM",
        {"method": request.method, "url": str(request.url)}
    )
    return JSONResponse(
        content={"error": "Forbidden", "message": "Access denied."},
        status_code=403
    )

async def rate_limit_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    db_manager.log_security_event(
        "RATE_LIMIT_EXCEEDED",
        f"429 Too Many Requests for {request.method} {request.url}",
        client_host,
        "MEDIUM",
        {"method": request.method, "url": str(request.url)}
    )
    return JSONResponse(
        content={"error": "Too Many Requests", "message": "Rate limit exceeded. Please try again later."},
        status_code=429
    )