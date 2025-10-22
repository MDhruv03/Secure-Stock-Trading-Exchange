import logging
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os

from backend.app.config import APP_TITLE, APP_DESCRIPTION, APP_VERSION
from backend.app.middleware import security_middleware
from backend.app.exception_handlers import (
    not_found_handler, internal_error_handler, 
    forbidden_handler, rate_limit_handler
)
from backend.app.api.routes import router as api_router

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8001", "http://127.0.0.1:8001", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Include API routes
app.include_router(api_router)

# Add security middleware
app.middleware("http")(security_middleware)

# Add exception handlers
app.add_exception_handler(404, not_found_handler)
app.add_exception_handler(500, internal_error_handler)
app.add_exception_handler(403, forbidden_handler)
app.add_exception_handler(429, rate_limit_handler)

from fastapi import Request

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main application page"""
    return FileResponse("frontend/templates/index.html")

@app.get("/crypto", response_class=HTMLResponse)
async def crypto_page():
    """Serve the crypto page"""
    return FileResponse("frontend/templates/index.html")

@app.get("/logs", response_class=HTMLResponse)
async def logs_page():
    """Serve the logs page"""
    return FileResponse("frontend/templates/index.html")

@app.get("/sim", response_class=HTMLResponse)
async def sim_page():
    """Serve the simulation page"""
    return FileResponse("frontend/templates/index.html")

# Add catch-all route for SPA (Single Page Application)
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve the SPA for any other routes"""
    return FileResponse("frontend/templates/index.html")

if __name__ == "__main__":
    import uvicorn
    print("Starting Secure Trading Platform...")
    print("Access the application at: http://localhost:8000")
    print("Press Ctrl+C to stop the server")
    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )