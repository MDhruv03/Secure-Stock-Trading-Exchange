# Secure Stock Trading Exchange

A production-ready secure trading platform featuring enterprise-grade cryptographic security, real-time order matching, and comprehensive red vs blue team attack simulations.

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the application
python start_app.py

# 3. Access the platform
# Open http://localhost:8001 in your browser
```

**Default Credentials:**
- Username: `admin` / Password: `admin123`
- Or register a new account

## 🎯 Project Overview

A full-stack financial trading platform demonstrating advanced security implementations including:
- **Real-time order matching** with price-time priority (FIFO) algorithm
- **End-to-end encryption** for all sensitive data
- **User privacy controls** - users can only see their own orders
- **Public order book** for transparent market depth
- **Attack simulation lab** for security education and testing

## 🔐 Key Security Features

### Cryptographic Techniques Implemented

#### 1. **AES-256-GCM** (Symmetric Encryption)
- **Where Used:** Encrypting sensitive database fields, transaction details, session data
- **Benefits:** High-speed, authenticated encryption (integrity + privacy)
- **Purpose:** Prevents unauthorized data access and tampering

#### 2. **RSA-2048** (Asymmetric Encryption)
- **Where Used:** Digital signatures for transactions, key exchange
- **Benefits:** Secure communication over untrusted networks, non-repudiation
- **Purpose:** Ensures only intended parties can decrypt sensitive information

#### 3. **ECC (SECP256R1)** (Elliptic Curve Cryptography)
- **Where Used:** Digital signatures for API requests and critical operations
- **Benefits:** Strong security with smaller key sizes, efficient for web clients
- **Purpose:** Guarantees authenticity of trades and actions

#### 4. **HMAC** (Hash-based Message Authentication Code)
- **Where Used:** API request authentication, message integrity checks
- **Benefits:** Fast, robust against forgery
- **Purpose:** Ensures messages are not altered in transit

#### 5. **PBKDF2-HMAC** (Password Hashing)
- **Where Used:** User password storage with 100,000 iterations
- **Benefits:** Resistant to brute-force and rainbow table attacks
- **Purpose:** Protects user credentials even if database is compromised

#### 6. **Merkle Tree** (Data Integrity & Proofs)
- **Where Used:** Transaction history verification, audit logs, interactive visualization
- **Benefits:** Efficient integrity verification, zero-knowledge proofs
- **Purpose:** Detects tampering, provides cryptographic audit trails

#### 7. **SHA-256/SHA-512** (Hashing)
- **Where Used:** Transaction hashing, Merkle tree nodes, data integrity
- **Benefits:** Collision-resistant, fast computation
- **Purpose:** Ensures data integrity and supports cryptographic proofs

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

## 🧪 Laboratory Exercises

### Exercise 1: Cryptographic Implementation Analysis
Students observe and analyze:
- AES-256-GCM encryption of order data
- RSA digital signatures for authenticity
- **Interactive Merkle tree visualization** with full tree structure
- **Merkle proof generation and verification** for transaction validation
- Homomorphic encryption for secure analytics
- Real-time cryptographic operations in the Crypto Center

### Exercise 2: Security Monitoring & Alerting
Students learn to:
- Monitor real-time security events
- Analyze system status changes during attacks
- Review incident response logs
- Understand alert generation mechanisms

### Exercise 3: Red Team Operations
Students execute and analyze:
- SQL injection attacks using simulation panel
- Brute force login attempts
- Replay attack simulations
- MITM attack attempts

### Exercise 4: Blue Team Defense
Students implement and test:
- Attack detection mechanisms
- Automated response actions
- Incident handling procedures
- Defense system effectiveness

## 🏗️ Technical Architecture

### Backend Stack
- **Framework**: FastAPI (Python 3.8+)
- **Database**: SQLite with encryption
- **Security**: Cryptography library (AES, RSA, SHA-256)
- **Authentication**: JWT tokens with bcrypt password hashing

### Frontend Stack
- **Template Engine**: Jinja2 with Tailwind CSS
- **Design**: Terminal-style interface with JetBrains Mono font
- **Real-time**: WebSocket connections for live updates
- **Visualizations**: Interactive Merkle tree diagrams, proof verification displays
- **Responsive**: Works on desktop and mobile devices

### Security Stack
- **Intrusion Detection**: Pattern matching and behavioral analysis
- **Automated Response**: Real-time threat mitigation
- **Audit Trail**: Immutable logging with Merkle tree verification
- **Monitoring**: Real-time security event visualization

## 📁 Project Structure

```
secure-trading-platform/
├── backend/
│   └── app/
│       ├── main.py              # Application entry point
│       ├── routes.py            # API endpoints
│       ├── database.py          # Database operations
│       ├── crypto_service.py    # Cryptographic functions
│       ├── auth_service.py     # Authentication
│       └── trading_service.py   # Trading operations
├── frontend/
│   ├── static/                  # CSS, JS, images
│   └── templates/               # HTML templates
├── security/
│   ├── red_team/                # Attack simulations
│   └── blue_team/               # Defense mechanisms
├── tests/                      # Test suite
└── docs/                       # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-trading-platform.git
cd secure-trading-platform

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "
import sys
sys.path.append('.')
from backend.app.database import DatabaseManager
db = DatabaseManager()
print('Database initialized successfully!')
"

# Start the application
python backend/app/main.py
```


## 🛠️ Laboratory Setup

### Exercise 1: Cryptographic Analysis
1. Navigate to the platform homepage
2. Log in with demo credentials
3. Place a few test orders
4. Observe encryption indicators in the UI
5. Review the cryptographic security documentation

### Exercise 2: Security Monitoring
1. Access the "Logs" section
2. Observe real-time security events
3. Note system status changes during simulated attacks
4. Review incident response logs

### Exercise 3: Red Team Operations
1. Navigate to the "Simulation" section
2. Execute SQL injection attacks using the simulation panel
3. Perform brute force login attempts
4. Conduct replay and MITM attack simulations
5. Analyze attack effectiveness and system responses

### Exercise 4: Blue Team Defense
1. Review attack detection mechanisms
2. Analyze automated response actions
3. Document incident handling procedures
4. Test defense system effectiveness against various attack vectors

## 📊 API Documentation

Complete API documentation is available at:
```
http://localhost:8000/docs
```

Key endpoints include:
- `/api/auth/register` - User registration
- `/api/auth/login` - User authentication
- `/api/trading/orders` - Secure order placement
- `/api/security/events` - Security event retrieval
- `/api/security/simulate/*` - Attack simulation endpoints
- `/api/crypto/merkle/build_tree` - Interactive Merkle tree generation
- `/api/crypto/merkle/generate_proof` - Cryptographic proof generation
- `/api/crypto/merkle/verify_proof` - Proof verification

## 🔍 Security Features Demonstrated

### Data Protection
- Encryption at rest using AES-256-GCM
- Data integrity through RSA digital signatures
- **Interactive Merkle tree visualization** for audit trail transparency
- **Zero-knowledge proof verification** for transaction validation
- Immutable audit trails with Merkle tree verification
- Privacy-preserving analytics with homomorphic encryption

### Threat Detection
- SQL injection pattern matching
- Behavioral analysis for anomaly detection
- Rate limiting for brute force prevention
- Signature verification for MITM attack detection

### Incident Response
- Automated IP blocking for detected threats
- Real-time session termination for suspicious activities
- Comprehensive incident logging with severity ranking
- Escalation procedures for high-severity events