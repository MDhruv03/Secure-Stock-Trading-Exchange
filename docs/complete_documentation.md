# Secure Trading Platform - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Installation](#installation)
4. [Running the Application](#running-the-application)
5. [Testing](#testing)
6. [Security Features](#security-features)
7. [Red Team Operations](#red-team-operations)
8. [Blue Team Defense](#blue-team-defense)
9. [API Documentation](#api-documentation)
10. [Development](#development)

## Overview

The Secure Trading Platform is a comprehensive educational tool that demonstrates enterprise-grade security implementations in a financial trading environment. Students gain hands-on experience with both offensive (red team) and defensive (blue team) security techniques.

## System Architecture

### Backend Stack
- **Framework**: FastAPI (Python 3.8+)
- **Database**: SQLite with encryption
- **Security**: Cryptography library (AES, RSA, SHA-256)
- **Authentication**: JWT tokens with bcrypt password hashing

### Frontend Stack
- **Template Engine**: Jinja2 with Tailwind CSS
- **Design**: Terminal-style interface with JetBeans Mono font
- **Real-time**: WebSocket connections for live updates
- **Responsive**: Works on desktop and mobile devices

### Security Stack
- **Intrusion Detection**: Pattern matching and behavioral analysis
- **Automated Response**: Real-time threat mitigation
- **Audit Trail**: Immutable logging with Merkle tree verification
- **Monitoring**: Real-time security event visualization

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step-by-step Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/secure-trading-platform.git
   cd secure-trading-platform
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**:
   ```bash
   python init_platform.py
   ```

5. **Create environment configuration**:
   ```bash
   cp .env.template .env
   # Edit .env with your configuration
   ```

## Running the Application

### Method 1: Using the startup script
```bash
# On Windows
start.bat

# On macOS/Linux
chmod +x start.sh
./start.sh
```

### Method 2: Manual start
```bash
# On Windows
python backend\app\main.py

# On macOS/Linux
python3 backend/app/main.py
```

### Access the Application
Open your web browser and navigate to:
```
http://localhost:8000
```

## Testing

### Run All Tests
```bash
python tests/run_tests.py
```

### Run Individual Test Suites
```bash
# Run basic test suite
python tests/test_suite.py

# Run comprehensive tests
python tests/comprehensive_test_suite.py

# Run security tests
python tests/security_test_suite.py

# Run API tests
python tests/api_test_suite.py
```

### Test Coverage
The test suite includes:
- Unit tests for all modules
- Integration tests for API endpoints
- Security tests for attack simulations
- Database operation tests
- Cryptographic operation tests

## Security Features

### Cryptographic Protection
- **AES-256-GCM Encryption**: All sensitive data encrypted at rest
- **RSA-2048 Digital Signatures**: Ensures data authenticity and integrity
- **Merkle Tree Verification**: Immutable audit trail for transactions
- **Homomorphic Encryption**: Privacy-preserving analytics (Paillier-based)

### Intrusion Detection & Prevention
- **SQL Injection Detection**: Pattern matching against malicious payloads
- **Brute Force Protection**: Automatic IP blocking after failed attempts
- **Replay Attack Prevention**: Nonce verification mechanisms
- **MITM Attack Detection**: Signature verification for data integrity

### Automated Defense Systems
- **Real-time IP Blocking**: Instant blocking of detected threats
- **Rate Limiting**: Prevents resource exhaustion attacks
- **Session Management**: Automatic termination of suspicious sessions
- **Incident Logging**: Comprehensive audit trail with severity ranking

## Red Team Operations

### SQL Injection Attacks
Located in `security/red_team/sqlmap_simulator.py`:
```bash
python security/red_team/sqlmap_simulator.py
```

### Brute Force Attacks
Located in `security/red_team/hydra_simulator.py`:
```bash
python security/red_team/hydra_simulator.py
```

### Replay Attacks
Located in `security/red_team/replay_attack_simulator.py`:
```bash
python security/red_team/replay_attack_simulator.py
```

### MITM Attacks
Located in `security/red_team/mitm_simulator.py`:
```bash
python security/red_team/mitm_simulator.py
```

### Running All Red Team Simulations
```bash
python run_security_simulations.py
```

## Blue Team Defense

### Intrusion Detection System
Located in `security/blue_team/defense_system.py`:
- SQL injection detection
- Brute force protection
- Rate limiting
- Suspicious activity monitoring

### Automated Response System
Integrated response mechanisms:
- Immediate blocking
- Progressive penalties
- Incident logging

### Monitoring and Alerting
- Real-time security event dashboard
- Alert notifications
- Reporting features

## API Documentation

Complete API documentation is available at:
```
http://localhost:8000/docs
```

### Key Endpoints

#### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - User logout

#### Trading
- `POST /api/trading/orders` - Secure order placement
- `GET /api/trading/orders` - Get user orders
- `GET /api/trading/orders/all` - Get all orders
- `GET /api/trading/orderbook/{symbol}` - Get order book
- `GET /api/trading/vwap/{symbol}` - Get VWAP

#### Security
- `GET /api/security/events` - Get security events
- `GET /api/security/blocked_ips` - Get blocked IPs
- `GET /api/security/merkle_leaves` - Get Merkle leaves

#### Simulations
- `POST /api/security/simulate/sql_injection` - Simulate SQL injection
- `POST /api/security/simulate/brute_force` - Simulate brute force
- `POST /api/security/simulate/replay` - Simulate replay attack
- `POST /api/security/simulate/mitm` - Simulate MITM attack

#### Cryptography
- `POST /api/crypto/encrypt` - Encrypt data
- `POST /api/crypto/decrypt` - Decrypt data
- `POST /api/crypto/sign` - Sign data
- `POST /api/crypto/verify` - Verify signature
- `POST /api/crypto/merkle/generate` - Generate Merkle root

## Development

### Project Structure
```
secure-trading-platform/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── main.py              # Application entry point
│       ├── routes.py            # API endpoints
│       ├── database.py          # Database operations
│       ├── crypto_service.py    # Cryptographic functions
│       ├── auth_service.py      # Authentication
│       └── trading_service.py   # Trading operations
├── frontend/
│   ├── static/                  # CSS, JS, images
│   └── templates/               # HTML templates
├── security/
│   ├── red_team/                # Attack simulations
│   └── blue_team/               # Defense mechanisms
├── tests/                       # Test suite
└── docs/                        # Documentation
```

### Adding New Features

1. **Backend Components**:
   - Add new routes in `backend/app/routes.py`
   - Implement business logic in service files
   - Add database operations in `backend/app/database.py`

2. **Frontend Components**:
   - Add new templates in `frontend/templates/`
   - Add CSS/JS in `frontend/static/`

3. **Security Components**:
   - Add red team simulations in `security/red_team/`
   - Add blue team defenses in `security/blue_team/`

### Code Style and Conventions

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Write unit tests for new functionality
- Keep security in mind for all implementations

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Troubleshooting

### Common Issues

#### Module Not Found Errors
```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

#### Database Initialization Failures
```bash
# Solution: Delete existing database and reinitialize
rm trading_platform.db  # On Windows: del trading_platform.db
python init_platform.py
```

#### Port Already in Use
```bash
# Solution: Change port in backend/app/main.py
# Or stop the existing process:
# On Windows: taskkill /PID <pid> /F
# On macOS/Linux: kill -9 <pid>
```

### Performance Optimization

1. Use Production Server: For production, use Gunicorn or similar
2. Enable Caching: Implement Redis for session caching
3. Database Optimization: Use connection pooling for SQLite
4. Static Files: Serve static files through a CDN or Nginx

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the FAQ section in this document
2. Review error messages carefully
3. Consult the project documentation
4. Open an issue on the GitHub repository (if available)