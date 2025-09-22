# Secure Trading Platform - Project Structure

## Root Directory
```
secure-trading-platform/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── main.py              # FastAPI application entry point
│       ├── routes.py            # API endpoint definitions
│       ├── database.py           # Database management
│       ├── crypto_service.py     # Cryptographic operations
│       ├── auth_service.py       # Authentication services
│       ├── trading_service.py    # Trading operations
│       └── ...
├── frontend/
│   ├── static/
│   │   └── ...                  # CSS, JS, images
│   └── templates/
│       └── index.html           # Main HTML template
├── security/
│   ├── red_team/
│   │   ├── README.md
│   │   └── attack_simulator.py
│   └── blue_team/
│       ├── README.md
│       └── defense_system.py
├── tests/
│   ├── __init__.py
│   ├── test_suite.py
│   └── ...
├── docs/
│   ├── documentation.md
│   ├── PROJECT_SUMMARY.md
│   └── INSTALLATION.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── start.sh
├── start.bat
├── .gitignore
└── README.md
```

## Backend Structure (`backend/app/`)

### Core Application Files
- `main.py`: FastAPI application setup, middleware, and routing
- `routes.py`: API endpoint definitions with request/response validation
- `database.py`: Database abstraction layer with encryption support
- `crypto_service.py`: Cryptographic operations (AES, RSA, Merkle trees)
- `auth_service.py`: User authentication and session management
- `trading_service.py`: Trading operations with security features

### Security Modules
- Intrusion Detection System (IDS)
- Automated Response System (ARS)
- IP Blocking and Rate Limiting
- Session Management
- Audit Logging

## Frontend Structure (`frontend/`)

### Static Assets (`frontend/static/`)
- CSS stylesheets using Tailwind CSS
- JavaScript files for dynamic functionality
- Images and icons
- Fonts (JetBrains Mono)

### Templates (`frontend/templates/`)
- `index.html`: Main application template with terminal-style UI
- Template inheritance for consistent design
- Responsive layout for all device sizes

## Security Components (`security/`)

### Red Team (`security/red_team/`)
- Attack simulation scripts
- SQL injection simulators
- Brute force attack tools
- Replay attack demonstrators
- MITM attack simulators

### Blue Team (`security/blue_team/`)
- Intrusion Detection System (IDS)
- Automated Response System (ARS)
- IP blocking and rate limiting
- Behavioral analysis
- Incident logging and reporting

## Testing (`tests/`)
- Unit tests for all modules
- Integration tests for API endpoints
- Security tests for attack simulations
- Performance benchmarks
- Coverage reports

## Documentation (`docs/`)
- Technical documentation
- API reference
- Installation guide
- Laboratory exercises
- Project summary

## Deployment Files
- `requirements.txt`: Python dependencies
- `Dockerfile`: Containerization configuration
- `docker-compose.yml`: Multi-container deployment
- `start.sh`/`start.bat`: Platform startup scripts
- `.gitignore`: Version control exclusions

## Key Features by Component

### Cryptographic Security
Located in `backend/app/crypto_service.py`:
- AES-256-GCM encryption for data at rest
- RSA-2048 digital signatures for authenticity
- Merkle tree verification for immutable audit trails
- Homomorphic encryption for privacy-preserving analytics

### Database Management
Located in `backend/app/database.py`:
- SQLite database with encrypted storage
- User management with secure password storage
- Order storage with cryptographic protection
- Security event logging with indexing
- IP blocking with automatic expiration

### Authentication System
Located in `backend/app/auth_service.py`:
- Secure password hashing with bcrypt
- JWT token-based session management
- Login attempt rate limiting
- IP-based blocking for suspicious activity
- Session hijacking prevention

### Trading Operations
Located in `backend/app/trading_service.py`:
- Secure order creation with encryption
- Order book management
- VWAP calculation with secure aggregation
- Trade search with encrypted indexing
- Merkle tree integration for audit trails

### Security Monitoring
Located in `security/blue_team/defense_system.py`:
- Real-time attack detection
- Pattern matching for SQL injection
- Brute force protection
- Rate limiting and IP blocking
- Incident response automation

### Attack Simulation
Located in `security/red_team/attack_simulator.py`:
- SQL injection attack simulation
- Brute force login attempts
- Replay attack demonstrations
- MITM attack simulation
- Behavioral analysis of attack effectiveness

## Laboratory Exercise Structure

### Exercise 1: Cryptographic Implementation
- Observe AES encryption of order data
- Verify RSA signatures for authenticity
- Examine Merkle tree verification process
- Test homomorphic encryption for analytics

### Exercise 2: Security Monitoring
- Monitor security events in real-time
- Observe system status changes during attacks
- Review incident response logs
- Analyze alert generation mechanisms

### Exercise 3: Red Team Operations
- Execute SQL injection attacks using simulation panel
- Perform brute force login attempts
- Conduct replay and MITM attack simulations
- Analyze attack effectiveness

### Exercise 4: Blue Team Defense
- Analyze attack detection mechanisms
- Review automated response actions
- Document incident handling procedures
- Test defense system effectiveness

This structured approach ensures that students can easily navigate the codebase and understand how each security feature is implemented and how it contributes to the overall security posture of the trading platform.