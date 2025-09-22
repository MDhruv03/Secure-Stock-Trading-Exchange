from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os

# Import platform components
from backend.app.routes import router as api_router
from backend.app.security_service import get_security_service

# Create FastAPI app
app = FastAPI(
    title="Secure Trading Platform - Information Security Lab",
    description="A secure trading platform demonstrating cryptographic security and red/blue team simulations",
    version="2.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Set up templates
# Note: In this simplified version, we'll serve HTML directly
# In a full implementation, we would use Jinja2 templates

# Include API routes
app.include_router(api_router)

# Get security service
security_service = get_security_service()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serve the main application page"""
    return get_html_template()

@app.get("/crypto", response_class=HTMLResponse)
async def crypto_page(request: Request):
    """Serve the crypto page"""
    return get_html_template()

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Serve the logs page"""
    return get_html_template()

@app.get("/sim", response_class=HTMLResponse)
async def sim_page(request: Request):
    """Serve the simulation page"""
    return get_html_template()

# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Enhanced security middleware for request monitoring and filtering"""
    
    # Get client information
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Check if IP is blocked
    if security_service.is_blocked(client_host):
        # Log the blocked attempt
        security_service.log_event(
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
    
    # Check rate limiting
    if security_service.check_rate_limit(client_host, max_requests=200, time_window=60):
        # Log the rate limit violation
        security_service.log_event(
            "RATE_LIMIT_VIOLATION",
            f"Rate limit exceeded for {client_host}",
            client_host,
            "MEDIUM",
            {"method": request.method, "url": str(request.url), "user_agent": user_agent}
        )
        return JSONResponse(
            content={"error": "Rate limit exceeded", "message": "Too many requests. Please try again later."},
            status_code=429
        )
    
    # Check for suspicious user agent
    security_service.check_suspicious_user_agent(user_agent, client_host)
    
    # Continue with the request
    try:
        response = await call_next(request)
        
        # Log successful request
        security_service.log_event(
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
        # Log error
        security_service.log_event(
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

# Exception handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    security_service.log_event(
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

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    security_service.log_event(
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

@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    security_service.log_event(
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

@app.exception_handler(429)
async def rate_limit_handler(request: Request, exc):
    client_host = request.client.host if request.client else "unknown"
    security_service.log_event(
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

def get_html_template():
    """Return a simple HTML template for the application"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Trading Platform - Information Security Lab</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'JetBrains Mono', monospace;
            background-color: #0a0a0f;
            color: #e2e8f0;
        }
        .terminal-bg {
            background-color: #0a0a0f;
        }
        .terminal-surface {
            background-color: #141420;
        }
        .terminal-border {
            border-color: #1a1a2e;
        }
        .terminal-accent {
            color: #00ff88;
        }
        .terminal-text {
            color: #e2e8f0;
        }
        .terminal-muted {
            color: #64748b;
        }
        .terminal-danger {
            color: #ff4757;
        }
        .terminal-warning {
            color: #ffa726;
        }
        /* Button styles */
        .btn-terminal {
            background-color: #141420;
            border: 1px solid #1a1a2e;
            color: #00ff88;
            font-family: 'JetBrains Mono', monospace;
            transition: all 0.2s ease;
        }
        .btn-terminal:hover {
            background-color: #00ff88;
            color: #0a0a0f;
            border-color: #00ff88;
        }
        /* Input styles */
        .input-terminal {
            background-color: #141420;
            border: 1px solid #1a1a2e;
            color: #00ff88;
            font-family: 'JetBrains Mono', monospace;
        }
        .input-terminal:focus {
            outline: none;
            border-color: #00ff88;
            box-shadow: 0 0 0 2px rgba(0, 255, 136, 0.2);
        }
        /* Card styles */
        .card-terminal {
            background-color: #141420;
            border: 1px solid #1a1a2e;
            border-radius: 0.5rem;
            transition: border-color 0.2s ease;
        }
        .card-terminal:hover {
            border-color: #00ff88;
        }
        /* Status indicators */
        .status-indicator {
            display: inline-block;
            width: 0.75rem;
            height: 0.75rem;
            border-radius: 50%;
        }
        .status-success {
            background-color: #00ff88;
        }
        .status-warning {
            background-color: #ffa726;
        }
        .status-danger {
            background-color: #ff4757;
        }
        .status-loading {
            background-color: #00ff88;
            animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
    </style>
</head>
<body class="bg-black text-slate-200 font-mono min-h-screen">
    <!-- Login/Register View -->
    <div id="logged-out-view" class="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-black to-gray-800">
        <div class="w-full max-w-md">
            <div class="bg-gray-900 border border-gray-700 rounded-lg p-8 backdrop-blur-sm shadow-2xl">
                <!-- Terminal Header -->
                <div class="text-center mb-8">
                    <div class="flex items-center justify-center mb-4">
                        <div class="w-3 h-3 bg-red-500 rounded-full mr-2"></div>
                        <div class="w-3 h-3 bg-yellow-500 rounded-full mr-2"></div>
                        <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                    </div>
                    <h2 class="text-2xl font-bold text-green-400 tracking-wider">SECURE_TRADING_LAB</h2>
                    <p class="text-sm text-gray-400 mt-2">$ sudo access --crypto-security</p>
                </div>

                <div id="message-area-logged-out" class="mb-4 text-center text-sm font-medium"></div>
                
                <!-- Tab Buttons -->
                <div class="flex mb-6 bg-gray-800 rounded-lg p-1">
                    <button id="show-login" class="flex-1 py-2 px-4 text-sm font-medium rounded-md bg-green-500 text-black transition-all duration-200">
                        login
                    </button>
                    <button id="show-register" class="flex-1 py-2 px-4 text-sm font-medium rounded-md text-gray-400 hover:text-green-400 transition-all duration-200">
                        register
                    </button>
                </div>

                <!-- Login Form -->
                <form id="login-form" class="space-y-4">
                    <div>
                        <label class="block text-xs text-gray-400 mb-1">USERNAME</label>
                        <input id="login-username" type="text" required 
                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                               placeholder="enter username...">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-400 mb-1">PASSWORD</label>
                        <input id="login-password" type="password" required 
                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                               placeholder="enter password...">
                    </div>
                    <button type="submit" class="w-full bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                        $ execute login
                    </button>
                </form>

                <!-- Register Form -->
                <form id="register-form" class="space-y-4 hidden">
                    <div>
                        <label class="block text-xs text-gray-400 mb-1">USERNAME</label>
                        <input id="register-username" type="text" required 
                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                               placeholder="choose username...">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-400 mb-1">PASSWORD</label>
                        <input id="register-password" type="password" required 
                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                               placeholder="create password...">
                    </div>
                    <div>
                        <label class="block text-xs text-gray-400 mb-1">CONFIRM PASSWORD</label>
                        <input id="register-confirm-password" type="password" required 
                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 placeholder-gray-500 focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                               placeholder="confirm password...">
                    </div>
                    <button type="submit" class="w-full bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                        $ create account
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- Main Application View -->
    <div id="loggedIn-view" class="hidden h-screen bg-black">
        <!-- Header -->
        <header class="bg-gray-900 border-b border-gray-700 px-6 py-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <div class="flex items-center">
                        <div class="w-2 h-2 bg-red-500 rounded-full mr-1"></div>
                        <div class="w-2 h-2 bg-yellow-500 rounded-full mr-1"></div>
                        <div class="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                    </div>
                    <h1 class="text-green-400 font-bold text-lg tracking-wider">SECURE_TRADING_LAB</h1>
                </div>
                <div class="flex items-center space-x-4 text-sm">
                    <span class="text-gray-400">user:</span>
                    <span id="current-username" class="text-green-400 font-semibold"></span>
                    <span class="text-gray-400">|</span>
                    <span class="text-gray-400">role:</span>
                    <span id="current-user-role" class="text-blue-400"></span>
                    <span class="text-gray-400">|</span>
                    <span class="text-gray-400">balance:</span>
                    <span class="text-green-400">$<span id="current-user-balance"></span></span>
                </div>
            </div>
        </header>

        <div class="flex h-screen">
            <!-- Sidebar Navigation -->
            <aside class="w-16 bg-gray-900 border-r border-gray-700 flex flex-col items-center py-4 space-y-2">
                <a href="#" id="home-link" class="group flex items-center justify-center w-10 h-10 text-gray-400 hover:text-green-400 hover:bg-gray-800 rounded-lg transition-all duration-200">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0h6"/>
                    </svg>
                </a>
                <a href="/crypto" id="crypto-link" class="group flex items-center justify-center w-10 h-10 text-gray-400 hover:text-green-400 hover:bg-gray-800 rounded-lg transition-all duration-200">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                </a>
                <a href="/logs" id="logs-link" class="group flex items-center justify-center w-10 h-10 text-gray-400 hover:text-green-400 hover:bg-gray-800 rounded-lg transition-all duration-200">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m3 8H5m14 0a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                </a>
                <a href="/sim" id="sim-link" class="group flex items-center justify-center w-10 h-10 text-gray-400 hover:text-green-400 hover:bg-gray-800 rounded-lg transition-all duration-200">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                </a>
                
                <!-- Logout at bottom -->
                <div class="flex-1"></div>
                <button id="logout-button" class="flex items-center justify-center w-10 h-10 text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition-all duration-200">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                    </svg>
                </button>
            </aside>

            <!-- Main Content -->
            <main class="flex-1 overflow-hidden">
                <div class="h-full overflow-y-auto p-6 bg-gradient-to-br from-gray-900 to-black">
                    <div id="message-area-logged-in" class="mb-4 text-center text-sm font-medium"></div>
                    
                    <!-- Main Dashboard -->
                    <div id="main-dashboard">
                        <!-- Terminal Command Line Style Header -->
                        <div class="mb-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
                            <div class="flex items-center space-x-2">
                                <span class="text-green-400">$</span>
                                <span class="text-blue-400">trading-session</span>
                                <span class="text-gray-400">--active</span>
                                <div class="ml-auto flex items-center space-x-2">
                                    <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                                    <span class="text-xs text-gray-400">LIVE</span>
                                </div>
                            </div>
                        </div>

                        <!-- System Status & Order Form Grid -->
                        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                            <!-- System Status -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors duration-300">
                                <h3 class="text-lg font-semibold text-green-400 mb-4 flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    SYSTEM_STATUS
                                </h3>
                                <div class="space-y-3 text-sm">
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">merkle_root:</span>
                                        <span id="merkle-root" class="font-mono text-xs text-green-400 break-all">loading...</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">encryption:</span>
                                        <span class="font-semibold text-green-400">AES-256-GCM</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">signatures:</span>
                                        <span class="font-semibold text-green-400">RSA-2048</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">status:</span>
                                        <span class="text-green-400 flex items-center">
                                            <div class="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></div>
                                            SECURE
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <!-- Place Order -->
                            <div class="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors duration-300">
                                <h3 class="text-lg font-semibold text-green-400 mb-4 flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
                                    </svg>
                                    PLACE_SECURE_ORDER
                                </h3>
                                <form id="order-form" class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">ASSET</label>
                                        <input type="text" id="asset" value="BTC" required 
                                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">TYPE</label>
                                        <select id="type" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                            <option value="buy">BUY</option>
                                            <option value="sell">SELL</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">AMOUNT</label>
                                        <input type="number" id="amount" step="0.01" required 
                                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">PRICE</label>
                                        <input type="number" id="price" step="0.01" required 
                                               class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                    </div>
                                    <div class="md:col-span-2">
                                        <button type="submit" class="w-full bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                                            $ execute secure_order
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <!-- Cryptographic Features -->
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <!-- Encryption Demo -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors duration-300">
                                <h3 class="text-lg font-semibold text-green-400 mb-4 flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                    </svg>
                                    CRYPTOGRAPHIC_SECURITY
                                </h3>
                                <div class="space-y-3 text-sm">
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">Data Encryption:</span>
                                        <span class="font-semibold text-green-400">AES-256-GCM</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">Digital Signatures:</span>
                                        <span class="font-semibold text-green-400">RSA-2048</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">Merkle Tree:</span>
                                        <span class="font-semibold text-green-400">SHA-256</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span class="text-gray-400">Homomorphic:</span>
                                        <span class="font-semibold text-green-400">Paillier</span>
                                    </div>
                                </div>
                                <div class="mt-4 p-3 bg-gray-800 rounded-lg">
                                    <div class="text-xs text-gray-400 mb-1">ORDER_HASH</div>
                                    <div id="order-hash" class="font-mono text-xs text-green-400 break-all">0x0000000000000000000000000000000000000000000000000000000000000000</div>
                                </div>
                            </div>

                            // Security Events -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors duration-300">
                                <h3 class="text-lg font-semibold text-green-400 mb-4 flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                                    </svg>
                                    USER_ACTIVITY_LOGS
                                </h3>
                                <div id="security-events" class="space-y-2 text-xs text-gray-400 max-h-40 overflow-y-auto">
                                    <div class="p-2 bg-gray-800 rounded">
                                        <div class="flex justify-between">
                                            <span class="text-green-400">SYSTEM_BOOT</span>
                                            <span class="text-gray-500">00:00:01</span>
                                        </div>
                                        <div class="text-gray-400">Secure trading platform initialized</div>
                                    </div>
                                    <div class="p-2 bg-gray-800 rounded">
                                        <div class="flex justify-between">
                                            <span class="text-blue-400">CRYPTO_LOADED</span>
                                            <span class="text-gray-500">00:00:02</span>
                                        </div>
                                        <div class="text-gray-400">Cryptographic modules loaded</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Admin Content (Hidden by default) -->
                    <div id="admin-content" class="hidden">
                        <!-- Dynamic admin content will be loaded here -->
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            // DOM elements
            const loggedOutView = document.getElementById('logged-out-view');
            const loggedInView = document.getElementById('loggedIn-view');
            const mainDashboard = document.getElementById('main-dashboard');
            const adminContent = document.getElementById('admin-content');
            
            // Tab switching logic
            const showLoginBtn = document.getElementById('show-login');
            const showRegisterBtn = document.getElementById('show-register');
            const loginForm = document.getElementById('login-form');
            const registerForm = document.getElementById('register-form');
            
            showLoginBtn.addEventListener('click', () => {
                loginForm.classList.remove('hidden');
                registerForm.classList.add('hidden');
                showLoginBtn.classList.add('bg-green-500', 'text-black');
                showLoginBtn.classList.remove('text-gray-400');
                showRegisterBtn.classList.remove('bg-green-500', 'text-black');
                showRegisterBtn.classList.add('text-gray-400');
            });

            showRegisterBtn.addEventListener('click', () => {
                registerForm.classList.remove('hidden');
                loginForm.classList.add('hidden');
                showRegisterBtn.classList.add('bg-green-500', 'text-black');
                showRegisterBtn.classList.remove('text-gray-400');
                showLoginBtn.classList.remove('bg-green-500', 'text-black');
                showLoginBtn.classList.add('text-gray-400');
            });

            // Demo login functionality
            const loginFormEl = document.getElementById('login-form');
            loginFormEl.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('login-username').value;
                const password = document.getElementById('login-password').value;
                
                // Show loading state
                const loginButton = loginFormEl.querySelector('button[type="submit"]');
                const originalText = loginButton.textContent;
                loginButton.textContent = '$ authenticating...';
                loginButton.disabled = true;
                
                try {
                    // Simulate API call to login
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        
                        if (result.success) {
                            // Update UI with user data
                            document.getElementById('current-username').textContent = username;
                            document.getElementById('current-user-role').textContent = 'trader';
                            document.getElementById('current-user-balance').textContent = '10000.00';
                            
                            // Show logged in view
                            loggedOutView.classList.add('hidden');
                            loggedInView.classList.remove('hidden');
                            
                            // Add login event
                            addSecurityEvent('USER_LOGIN', `User ${username} logged in successfully`);
                            
                            // Clear form
                            loginFormEl.reset();
                        } else {
                            showTerminalMessage(result.message, 'danger');
                        }
                    } else {
                        showTerminalMessage('Login failed. Please check your credentials.', 'danger');
                    }
                } catch (error) {
                    showTerminalMessage('Login error: Network error occurred', 'danger');
                    console.error('Login error:', error);
                } finally {
                    // Restore button state
                    loginButton.textContent = originalText;
                    loginButton.disabled = false;
                }
            });

            // Demo register functionality
            const registerFormEl = document.getElementById('register-form');
            registerFormEl.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('register-username').value;
                const password = document.getElementById('register-password').value;
                const confirmPassword = document.getElementById('register-confirm-password').value;
                
                if (password !== confirmPassword) {
                    showTerminalMessage('Passwords do not match', 'danger');
                    return;
                }
                
                // Show loading state
                const registerButton = registerFormEl.querySelector('button[type="submit"]');
                const originalText = registerButton.textContent;
                registerButton.textContent = '$ creating account...';
                registerButton.disabled = true;
                
                try {
                    // Simulate API call to register
                    const response = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        
                        if (result.success) {
                            const messageArea = document.getElementById('message-area-logged-out');
                            messageArea.textContent = 'Registration successful! Please log in.';
                            messageArea.className = 'mb-4 text-center text-sm font-medium text-green-400';
                            showLoginBtn.click();
                            
                            // Add registration event
                            addSecurityEvent('USER_REGISTER', `New user ${username} registered successfully`);
                            
                            // Clear form
                            registerFormEl.reset();
                        } else {
                            showTerminalMessage(result.message, 'danger');
                        }
                    } else {
                        showTerminalMessage('Registration failed. Please try again.', 'danger');
                    }
                } catch (error) {
                    showTerminalMessage('Registration error: Network error occurred', 'danger');
                    console.error('Registration error:', error);
                } finally {
                    // Restore button state
                    registerButton.textContent = originalText;
                    registerButton.disabled = false;
                }
            });

            // Navigation functionality
            document.getElementById('home-link').addEventListener('click', (e) => {
                e.preventDefault();
                mainDashboard.classList.remove('hidden');
                adminContent.classList.add('hidden');
            });

            document.getElementById('crypto-link').addEventListener('click', (e) => {
                e.preventDefault();
                loadCryptoDemo();
            });

            document.getElementById('logs-link').addEventListener('click', (e) => {
                e.preventDefault();
                loadLogs();
            });

            document.getElementById('sim-link').addEventListener('click', (e) => {
                e.preventDefault();
                loadSimulation();
            });

            document.getElementById('logout-button').addEventListener('click', () => {
                loggedInView.classList.add('hidden');
                loggedOutView.classList.remove('hidden');
                
                // Add logout event
                addSecurityEvent('USER_LOGOUT', 'User logged out');
            });

            // Order form submission
            document.getElementById('order-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const asset = document.getElementById('asset').value;
                const type = document.getElementById('type').value;
                const amount = parseFloat(document.getElementById('amount').value);
                const price = parseFloat(document.getElementById('price').value);
                
                if (!asset || !type || !amount || !price) {
                    showTerminalMessage('Please fill all order fields', 'danger');
                    return;
                }
                
                // Show loading state
                const orderButton = document.querySelector('#order-form button[type="submit"]');
                const originalText = orderButton.textContent;
                orderButton.textContent = '$ placing order...';
                orderButton.disabled = true;
                
                try {
                    // Simulate API call to place order
                    const response = await fetch('/api/trading/orders', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ symbol: asset, side: type, quantity: amount, price: price })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        
                        if (result.success) {
                            // Generate a hash for demo
                            const hash = '0x' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
                            document.getElementById('order-hash').textContent = hash;
                            
                            // Add order event
                            addSecurityEvent('ORDER_PLACED', `${type.toUpperCase()} order for ${amount} ${asset} at $${price}`);
                            
                            // Show crypto process visualization update
                            updateCryptoProcessOnOrder();
                            
                            // Show success message
                            const messageArea = document.getElementById('message-area-logged-in');
                            messageArea.textContent = `Secure order placed successfully for ${amount} ${asset} with cryptographic protection`;
                            messageArea.className = 'mb-4 text-center text-sm font-medium text-green-400';
                            
                            // Clear form
                            document.getElementById('order-form').reset();
                            document.getElementById('asset').value = 'BTC';
                        } else {
                            showTerminalMessage(result.message, 'danger');
                        }
                    } else {
                        showTerminalMessage('Order placement failed. Please try again.', 'danger');
                    }
                } catch (error) {
                    showTerminalMessage('Order error: Network error occurred', 'danger');
                    console.error('Order error:', error);
                } finally {
                    // Restore button state
                    orderButton.textContent = originalText;
                    orderButton.disabled = false;
                }
            });

            // Load crypto demo page
            function loadCryptoDemo() {
                adminContent.innerHTML = `
                    <div class="space-y-6">
                        <!-- Header -->
                        <div class="flex items-center justify-between">
                            <h1 class="text-2xl font-bold text-green-400 flex items-center">
                                <svg class="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                </svg>
                                CRYPTOGRAPHIC_SECURITY_DEMO
                            </h1>
                            <button id="generate-crypto-demo-btn" class="bg-blue-500 hover:bg-blue-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                GENERATE_DEMO
                            </button>
                        </div>

                        <!-- Crypto Demo Grid -->
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <!-- AES Encryption Demo -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                                <h2 class="text-lg font-semibold text-green-400 mb-4">AES-256-GCM ENCRYPTION</h2>
                                <div class="space-y-3">
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">PLAINTEXT</label>
                                        <textarea id="plaintext" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors" rows="3">{"order_id": "ORD-001", "symbol": "BTC", "quantity": 0.5, "price": 45000.00}</textarea>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">ENCRYPTED DATA</label>
                                        <div id="encrypted-data" class="bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 font-mono text-xs break-all min-h-[60px]">Click "Encrypt" to generate</div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <button id="encrypt-btn" class="flex-1 bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            ENCRYPT
                                        </button>
                                        <button id="decrypt-btn" class="flex-1 bg-blue-500 hover:bg-blue-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            DECRYPT
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <!-- RSA Signature Demo -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                                <h2 class="text-lg font-semibold text-green-400 mb-4">RSA DIGITAL SIGNATURES</h2>
                                <div class="space-y-3">
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">DATA TO SIGN</label>
                                        <textarea id="data-to-sign" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors" rows="3">{"order_id": "ORD-001", "timestamp": "2023-01-01T12:00:00Z", "user_id": 12345}</textarea>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">SIGNATURE</label>
                                        <div id="signature" class="bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 font-mono text-xs break-all min-h-[60px]">Click "Sign" to generate</div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <button id="sign-btn" class="flex-1 bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            SIGN
                                        </button>
                                        <button id="verify-btn" class="flex-1 bg-blue-500 hover:bg-blue-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            VERIFY
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <!-- Merkle Tree Demo -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                                <h2 class="text-lg font-semibold text-green-400 mb-4">MERKLE_TREE_VERIFICATION</h2>
                                <div class="space-y-3">
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">TRANSACTION_DATA</label>
                                        <textarea id="transaction-data" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors" rows="3">{"tx_id": "TX-001", "from": "user1", "to": "user2", "amount": 1.5}</textarea>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">MERKLE_ROOT</label>
                                        <div id="merkle-root-demo" class="bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 font-mono text-xs break-all">0x0000000000000000000000000000000000000000000000000000000000000000</div>
                                    </div>
                                    <button id="generate-merkle-btn" class="w-full bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                        GENERATE_MERKLE_PROOF
                                    </button>
                                </div>
                            </div>

                            <!-- Homomorphic Encryption Demo -->
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                                <h2 class="text-lg font-semibold text-green-400 mb-4">HOMOMORPHIC_ENCRYPTION</h2>
                                <div class="space-y-3">
                                    <div class="grid grid-cols-2 gap-2">
                                        <div>
                                            <label class="block text-xs text-gray-400 mb-1">VALUE_1</label>
                                            <input type="number" id="hom-value1" value="100" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                        </div>
                                        <div>
                                            <label class="block text-xs text-gray-400 mb-1">VALUE_2</label>
                                            <input type="number" id="hom-value2" value="200" class="w-full bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 focus:outline-none focus:border-green-500 transition-colors">
                                        </div>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">ENCRYPTED_SUM</label>
                                        <div id="hom-encrypted-sum" class="bg-gray-800 border border-gray-600 rounded-md px-3 py-2 text-sm text-green-400 font-mono text-xs break-all min-h-[40px]">Click "Add" to compute</div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <button id="hom-encrypt-btn" class="flex-1 bg-green-500 hover:bg-green-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            ENCRYPT
                                        </button>
                                        <button id="hom-add-btn" class="flex-1 bg-blue-500 hover:bg-blue-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            ADD_ENCRYPTED
                                        </button>
                                        <button id="hom-decrypt-btn" class="flex-1 bg-purple-500 hover:bg-purple-400 text-black font-semibold py-2 px-4 rounded-md transition-colors">
                                            DECRYPT
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                mainDashboard.classList.add('hidden');
                adminContent.classList.remove('hidden');
                initCryptoDemo();
            }

            // Initialize crypto demo
            function initCryptoDemo() {
                // AES Encryption Demo
                document.getElementById('encrypt-btn').addEventListener('click', () => {
                    const plaintext = document.getElementById('plaintext').value;
                    const encrypted = '0x' + Array.from({length: 128}, () => Math.floor(Math.random() * 16).toString(16)).join('');
                    document.getElementById('encrypted-data').textContent = encrypted;
                    addSecurityEvent('AES_ENCRYPT', 'Data encrypted with AES-256-GCM');
                });

                document.getElementById('decrypt-btn').addEventListener('click', () => {
                    const encrypted = document.getElementById('encrypted-data').textContent;
                    if (encrypted !== 'Click "Encrypt" to generate') {
                        document.getElementById('plaintext').value = document.getElementById('plaintext').value;
                        addSecurityEvent('AES_DECRYPT', 'Data decrypted successfully');
                    }
                });

                // RSA Signature Demo
                document.getElementById('sign-btn').addEventListener('click', () => {
                    const data = document.getElementById('data-to-sign').value;
                    const signature = '0x' + Array.from({length: 256}, () => Math.floor(Math.random() * 16).toString(16)).join('');
                    document.getElementById('signature').textContent = signature;
                    addSecurityEvent('RSA_SIGN', 'Digital signature generated');
                });

                document.getElementById('verify-btn').addEventListener('click', () => {
                    const signature = document.getElementById('signature').textContent;
                    if (signature !== 'Click "Sign" to generate') {
                        addSecurityEvent('RSA_VERIFY', 'Signature verified successfully');
                    }
                });

                // Merkle Tree Demo
                document.getElementById('generate-merkle-btn').addEventListener('click', () => {
                    const root = '0x' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
                    document.getElementById('merkle-root-demo').textContent = root;
                    addSecurityEvent('MERKLE_UPDATE', 'Merkle tree updated with new transaction');
                });

                // Homomorphic Encryption Demo
                document.getElementById('hom-encrypt-btn').addEventListener('click', () => {
                    addSecurityEvent('HOM_ENCRYPT', 'Values encrypted with Paillier encryption');
                });

                document.getElementById('hom-add-btn').addEventListener('click', () => {
                    const val1 = parseInt(document.getElementById('hom-value1').value);
                    const val2 = parseInt(document.getElementById('hom-value2').value);
                    const sum = val1 + val2;
                    document.getElementById('hom-encrypted-sum').textContent = `Encrypted sum represents: ${sum}`;
                    addSecurityEvent('HOM_ADD', 'Homomorphic addition performed on encrypted values');
                });

                document.getElementById('hom-decrypt-btn').addEventListener('click', () => {
                    addSecurityEvent('HOM_DECRYPT', 'Encrypted result decrypted successfully');
                });

                // Generate demo button
                document.getElementById('generate-crypto-demo-btn').addEventListener('click', () => {
                    document.getElementById('plaintext').value = '{"order_id": "ORD-' + Math.floor(Math.random() * 1000) + '", "symbol": "BTC", "quantity": ' + (Math.random() * 10).toFixed(2) + ', "price": ' + (Math.random() * 50000 + 30000).toFixed(2) + '}';
                    document.getElementById('data-to-sign').value = '{"tx_id": "TX-' + Math.floor(Math.random() * 1000) + '", "timestamp": "' + new Date().toISOString() + '", "user_id": ' + Math.floor(Math.random() * 10000) + '}';
                    document.getElementById('transaction-data').value = '{"tx_id": "TX-' + Math.floor(Math.random() * 1000) + '", "from": "user' + Math.floor(Math.random() * 100) + '", "to": "user' + Math.floor(Math.random() * 100) + '", "amount": ' + (Math.random() * 10).toFixed(2) + '}';
                    addSecurityEvent('DEMO_GENERATE', 'Cryptographic demo data generated');
                });
            }

            // Load logs page
            function loadLogs() {
                adminContent.innerHTML = `
                    <div class="space-y-6">
                        <h1 class="text-2xl font-bold text-green-400 flex items-center">
                            <svg class="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m3 8H5m14 0a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                            </svg>
                            SECURITY_LOGS
                        </h1>

                        <!-- Crypto Security Events -->
                        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                            <h2 class="text-lg font-semibold text-green-400 mb-4">CRYPTOGRAPHIC_EVENTS</h2>
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm">
                                    <thead>
                                        <tr class="border-b border-gray-700">
                                            <th class="text-left text-gray-400 py-2">ID</th>
                                            <th class="text-left text-gray-400 py-2">TYPE</th>
                                            <th class="text-left text-gray-400 py-2">DESCRIPTION</th>
                                            <th class="text-left text-gray-400 py-2">TIMESTAMP</th>
                                        </tr>
                                    </thead>
                                    <tbody class="text-gray-300">
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">001</td>
                                            <td class="py-2 text-blue-400">AES_ENCRYPT</td>
                                            <td class="py-2">Order data encrypted successfully</td>
                                            <td class="py-2 text-gray-400">2024-01-15 10:30:42</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">002</td>
                                            <td class="py-2 text-purple-400">RSA_SIGN</td>
                                            <td class="py-2">Digital signature generated</td>
                                            <td class="py-2 text-gray-400">2024-01-15 11:15:23</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">003</td>
                                            <td class="py-2 text-yellow-400">MERKLE_UPDATE</td>
                                            <td class="py-2">Merkle tree updated with new transaction</td>
                                            <td class="py-2 text-gray-400">2024-01-15 12:45:10</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">004</td>
                                            <td class="py-2 text-green-400">HOM_ENCRYPT</td>
                                            <td class="py-2">Homomorphic encryption applied to analytics data</td>
                                            <td class="py-2 text-gray-400">2024-01-15 13:22:15</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- Attack Detection Logs -->
                        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                            <h2 class="text-lg font-semibold text-green-400 mb-4">ATTACK_DETECTION_LOGS</h2>
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm">
                                    <thead>
                                        <tr class="border-b border-gray-700">
                                            <th class="text-left text-gray-400 py-2">ID</th>
                                            <th class="text-left text-gray-400 py-2">TYPE</th>
                                            <th class="text-left text-gray-400 py-2">DESCRIPTION</th>
                                            <th class="text-left text-gray-400 py-2">SOURCE_IP</th>
                                            <th class="text-left text-gray-400 py-2">ACTION</th>
                                            <th class="text-left text-gray-400 py-2">TIMESTAMP</th>
                                        </tr>
                                    </thead>
                                    <tbody class="text-gray-300">
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">A01</td>
                                            <td class="py-2 text-yellow-400">BRUTE_FORCE</td>
                                            <td class="py-2">Multiple failed login attempts detected</td>
                                            <td class="py-2 font-mono">192.168.1.100</td>
                                            <td class="py-2 text-blue-400">IP_BLOCKED</td>
                                            <td class="py-2 text-gray-400">2024-01-15 10:30:42</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">A02</td>
                                            <td class="py-2 text-red-400">SQL_INJECTION</td>
                                            <td class="py-2">Malicious SQL pattern in request</td>
                                            <td class="py-2 font-mono">10.0.0.50</td>
                                            <td class="py-2 text-blue-400">REQUEST_FILTERED</td>
                                            <td class="py-2 text-gray-400">2024-01-15 11:15:23</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">A03</td>
                                            <td class="py-2 text-orange-400">REPLAY_ATTACK</td>
                                            <td class="py-2">Duplicate transaction detected</td>
                                            <td class="py-2 font-mono">203.0.113.42</td>
                                            <td class="py-2 text-blue-400">TX_REJECTED</td>
                                            <td class="py-2 text-gray-400">2024-01-15 12:45:10</td>
                                        </tr>
                                        <tr class="border-b border-gray-800">
                                            <td class="py-2 text-green-400">A04</td>
                                            <td class="py-2 text-purple-400">MITM_ATTEMPT</td>
                                            <td class="py-2">Signature verification failed</td>
                                            <td class="py-2 font-mono">198.51.100.25</td>
                                            <td class="py-2 text-blue-400">SESSION_TERMINATED</td>
                                            <td class="py-2 text-gray-400">2024-01-15 14:33:55</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
                mainDashboard.classList.add('hidden');
                adminContent.classList.remove('hidden');
            }

            // Load simulation page
            function loadSimulation() {
                adminContent.innerHTML = `
                    <div class="space-y-6">
                        <h1 class="text-2xl font-bold text-green-400 flex items-center">
                            <svg class="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                            </svg>
                            RED_BLUE_TEAM_SIMULATION
                        </h1>

                        <!-- Simulation Controls -->
                        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                            <h2 class="text-lg font-semibold text-green-400 mb-4">SIMULATE_SECURITY_ATTACKS</h2>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <button id="sqlmap-sim-btn" class="bg-red-500 hover:bg-red-400 text-white font-semibold py-3 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                                    SQL_INJECTION
                                </button>
                                <button id="bruteforce-sim-btn" class="bg-red-500 hover:bg-red-400 text-white font-semibold py-3 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                                    BRUTE_FORCE
                                </button>
                                <button id="replay-sim-btn" class="bg-red-500 hover:bg-red-400 text-white font-semibold py-3 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                                    REPLAY_ATTACK
                                </button>
                                <button id="mitm-sim-btn" class="bg-red-500 hover:bg-red-400 text-white font-semibold py-3 px-4 rounded-md transition-all duration-200 transform hover:scale-105">
                                    MITM_ATTACK
                                </button>
                            </div>
                        </div>

                        <!-- Defense Response -->
                        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                            <h2 class="text-lg font-semibold text-green-400 mb-4">AUTOMATED_DEFENSE_RESPONSE</h2>
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div class="p-4 bg-gray-800 rounded-lg">
                                    <h3 class="text-md font-medium text-blue-400 mb-2">INTRUSION_DETECTION</h3>
                                    <p class="text-sm text-gray-300">Real-time pattern matching for malicious activities</p>
                                </div>
                                <div class="p-4 bg-gray-800 rounded-lg">
                                    <h3 class="text-md font-medium text-green-400 mb-2">AUTOMATED_RESPONSE</h3>
                                    <p class="text-sm text-gray-300">Instant blocking of detected threats</p>
                                </div>
                                <div class="p-4 bg-gray-800 rounded-lg">
                                    <h3 class="text-md font-medium text-purple-400 mb-2">INCIDENT_LOGGING</h3>
                                    <p class="text-sm text-gray-300">Comprehensive audit trail of all security events</p>
                                </div>
                            </div>
                        </div>

                        <!-- Simulation Output -->
                        <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-colors">
                            <h2 class="text-lg font-semibold text-green-400 mb-4">SIMULATION_OUTPUT</h2>
                            <div id="simulation-output" class="bg-black border border-gray-600 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
                                <div class="text-gray-400">$ waiting for simulation...</div>
                                <div class="text-green-400 animate-pulse">_</div>
                            </div>
                        </div>
                    </div>
                `;
                mainDashboard.classList.add('hidden');
                adminContent.classList.remove('hidden');
                setupSimulationButtons();
            }

            // Setup simulation buttons
            function setupSimulationButtons() {
                const output = document.getElementById('simulation-output');
                
                function runSimulation(type) {
                    output.innerHTML = `<div class="text-green-400">$ running ${type} simulation...</div>`;
                    
                    setTimeout(() => {
                        const steps = [
                            { actor: 'Red Team', action: `Initiating ${type.replace('_', ' ')} attack vector` },
                            { actor: 'Red Team', action: 'Scanning for vulnerabilities...' },
                            { actor: 'Blue Team', action: 'Anomaly detected in traffic patterns' },
                            { actor: 'Blue Team', action: 'Triggering automated response protocols' },
                            { actor: 'Red Team', action: 'Attack payload delivered' },
                            { actor: 'Blue Team', action: 'Blocking suspicious IP addresses' },
                            { actor: 'Blue Team', action: 'Incident logged and escalated' },
                            { actor: 'System', action: 'Simulation completed successfully' }
                        ];

                        output.innerHTML = '';
                        steps.forEach((step, index) => {
                            setTimeout(() => {
                                const div = document.createElement('div');
                                div.className = `mb-2 p-2 rounded ${
                                    step.actor === 'Red Team' ? 'bg-red-900/30 text-red-400' :
                                    step.actor === 'Blue Team' ? 'bg-blue-900/30 text-blue-400' :
                                    'bg-green-900/30 text-green-400'
                                }`;
                                div.textContent = `[${step.actor}] ${step.action}`;
                                output.appendChild(div);
                                output.scrollTop = output.scrollHeight;
                                
                                // Add security event
                                addSecurityEvent(`${type.toUpperCase()}_SIM`, `${step.actor}: ${step.action}`);
                            }, index * 800);
                        });
                    }, 500);
                }

                document.getElementById('sqlmap-sim-btn').addEventListener('click', () => runSimulation('SQL_INJECTION'));
                document.getElementById('bruteforce-sim-btn').addEventListener('click', () => runSimulation('BRUTE_FORCE'));
                document.getElementById('replay-sim-btn').addEventListener('click', () => runSimulation('REPLAY_ATTACK'));
                document.getElementById('mitm-sim-btn').addEventListener('click', () => runSimulation('MITM_ATTACK'));
            }

            // Update crypto process visualization when order is placed
            function updateCryptoProcessOnOrder() {
                // This is a demo function - in a real implementation, this would update in real time
                setTimeout(() => {
                    // Reset after 3 seconds
                    setTimeout(() => {
                    }, 3000);
                }, 100);
            }

            // Add security event to the log
            function addSecurityEvent(type, description) {
                const eventsContainer = document.getElementById('security-events');
                const timestamp = new Date().toLocaleTimeString();
                
                const eventDiv = document.createElement('div');
                eventDiv.className = 'p-2 bg-gray-800 rounded';
                eventDiv.innerHTML = `
                    <div class="flex justify-between">
                        <span class="text-green-400">${type}</span>
                        <span class="text-gray-500">${timestamp}</span>
                    </div>
                    <div class="text-gray-400">${description}</div>
                `;
                
                eventsContainer.insertBefore(eventDiv, eventsContainer.firstChild);
                
                // Keep only the last 10 events
                while (eventsContainer.children.length > 10) {
                    eventsContainer.removeChild(eventsContainer.lastChild);
                }
            }

            // Show terminal message
            function showTerminalMessage(message, type = 'info') {
                const messageArea = document.getElementById('message-area-logged-in') || 
                                   document.getElementById('message-area-logged-out');
                
                if (messageArea) {
                    messageArea.textContent = message;
                    messageArea.className = `mb-4 text-center text-sm font-medium ${
                        type === 'danger' ? 'text-red-400' :
                        type === 'warning' ? 'text-yellow-400' :
                        'text-green-400'
                    }`;
                    
                    // Clear message after 5 seconds
                    setTimeout(() => {
                        messageArea.textContent = '';
                        messageArea.className = 'mb-4 text-center text-sm font-medium';
                    }, 5000);
                }
            }

            // Demo data for system status
            setTimeout(() => {
                document.getElementById('merkle-root').textContent = '0x' + Array.from({length: 16}, () => Math.floor(Math.random() * 16).toString(16)).join('') + '...';
            }, 1000);
        });
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    print("Starting Secure Trading Platform...")
    print("Access the application at: http://localhost:8000")
    print("Press Ctrl+C to stop the server")
    uvicorn.run(app, host="127.0.0.1", port=8000)