from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
import os

from backend.app.config import APP_TITLE, APP_DESCRIPTION, APP_VERSION
from backend.app.middleware import security_middleware
from backend.app.exception_handlers import (
    not_found_handler, internal_error_handler, 
    forbidden_handler, rate_limit_handler
)
from backend.app.api.routes import router as api_router

# Set up Jinja2 templates
templates = Jinja2Templates(directory="frontend/templates")

# Create FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create static directory if it doesn't exist
import os
os.makedirs("frontend/static", exist_ok=True)

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
async def read_root(request: Request):
    """Serve the main application page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/crypto", response_class=HTMLResponse)
async def crypto_page(request: Request):
    """Serve the crypto page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Serve the logs page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/sim", response_class=HTMLResponse)
async def sim_page(request: Request):
    """Serve the simulation page"""
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    print("Starting Secure Trading Platform...")
    print("Access the application at: http://localhost:8000")
    print("Press Ctrl+C to stop the server")
    uvicorn.run(app, host="127.0.0.1", port=8000)