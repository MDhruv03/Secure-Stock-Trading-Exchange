"""
Enhanced Exception handlers for the Secure Trading Platform
"""
import logging
import traceback
from datetime import datetime
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional

from backend.app.services.security_service import get_security_service
from backend.app.utils.database import get_db_manager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security_service = get_security_service()
db_manager = get_db_manager()

async def not_found_handler(request: Request, exc):
    """
    Handle 404 Not Found errors
    """
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    db_manager.log_security_event(
        "NOT_FOUND",
        f"404 Not Found for {request.method} {request.url}",
        client_host,
        "LOW",
        {
            "method": request.method, 
            "url": str(request.url),
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat()
        }
    )
    
    # Log for debugging
    logger.warning(f"404 Not Found: {request.method} {request.url} from {client_host}")
    
    return HTMLResponse(
        content="""
        <html>
        <head>
            <title>404 Not Found</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background-color: #1a202c; 
                    color: #e2e8f0; 
                    text-align: center; 
                    padding: 50px; 
                }
                .container { 
                    max-width: 600px; 
                    margin: 0 auto; 
                    background-color: #2d3748; 
                    padding: 30px; 
                    border-radius: 8px; 
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
                }
                h1 { color: #f56565; }
                p { margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>404 - Resource Not Found</h1>
                <p>The requested resource could not be found on the server.</p>
                <p>Please check the URL and try again.</p>
                <p><a href="/" style="color: #63b3ed;">Return to Home</a></p>
            </div>
        </body>
        </html>
        """,
        status_code=404
    )

async def internal_error_handler(request: Request, exc):
    """
    Handle 500 Internal Server Errors
    """
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create error ID for tracking
    error_id = f"ERR_{int(datetime.now().timestamp())}_{hash(str(exc)) % 10000:04d}"
    
    db_manager.log_security_event(
        "INTERNAL_ERROR",
        f"500 Internal Server Error for {request.method} {request.url}: {str(exc)} (Error ID: {error_id})",
        client_host,
        "CRITICAL",
        {
            "method": request.method,
            "url": str(request.url),
            "error": str(exc),
            "error_id": error_id,
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat(),
            "traceback": traceback.format_exc()[:1000] if traceback.format_exc() else None  # Limit traceback length
        }
    )
    
    # Log for debugging with traceback
    logger.error(f"500 Internal Error (ID: {error_id}): {request.method} {request.url} from {client_host}\nError: {str(exc)}\nTraceback: {traceback.format_exc()}")
    
    return HTMLResponse(
        content=f"""
        <html>
        <head>
            <title>500 Internal Server Error</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    background-color: #1a202c; 
                    color: #e2e8f0; 
                    text-align: center; 
                    padding: 50px; 
                }}
                .container {{ 
                    max-width: 600px; 
                    margin: 0 auto; 
                    background-color: #2d3748; 
                    padding: 30px; 
                    border-radius: 8px; 
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
                }}
                h1 {{ color: #f56565; }}
                .error-id {{ 
                    background-color: #4a5568; 
                    padding: 10px; 
                    border-radius: 4px; 
                    display: inline-block; 
                    margin: 15px 0; 
                }}
                p {{ margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>500 - Internal Server Error</h1>
                <p>An unexpected error occurred on the server.</p>
                <div class="error-id">Error ID: {error_id}</div>
                <p>Please try again later or contact support if the problem persists.</p>
                <p><a href="/" style="color: #63b3ed;">Return to Home</a></p>
            </div>
        </body>
        </html>
        """,
        status_code=500
    )

async def forbidden_handler(request: Request, exc):
    """
    Handle 403 Forbidden errors
    """
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    db_manager.log_security_event(
        "FORBIDDEN",
        f"403 Forbidden for {request.method} {request.url}",
        client_host,
        "MEDIUM",
        {
            "method": request.method,
            "url": str(request.url),
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat()
        }
    )
    
    # Log for debugging
    logger.warning(f"403 Forbidden: {request.method} {request.url} from {client_host}")
    
    return JSONResponse(
        content={
            "error": "Forbidden",
            "message": "Access denied. You do not have permission to access this resource.",
            "timestamp": datetime.now().isoformat()
        },
        status_code=403
    )

async def rate_limit_handler(request: Request, exc):
    """
    Handle 429 Too Many Requests errors
    """
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    db_manager.log_security_event(
        "RATE_LIMIT_EXCEEDED",
        f"429 Too Many Requests for {request.method} {request.url}",
        client_host,
        "MEDIUM",
        {
            "method": request.method,
            "url": str(request.url),
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat()
        }
    )
    
    # Log for debugging
    logger.warning(f"429 Rate Limit Exceeded: {request.method} {request.url} from {client_host}")
    
    return JSONResponse(
        content={
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please slow down your requests and try again later.",
            "retry_after": 60,
            "timestamp": datetime.now().isoformat()
        },
        status_code=429
    )