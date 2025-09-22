# Secure Trading Platform - Information Security Laboratory

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.68.0%2B-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A production-ready secure trading platform designed for information security laboratory use, featuring advanced cryptographic security and comprehensive red vs blue team simulations.

## 🎯 Project Overview

The Secure Trading Platform is a comprehensive educational tool that demonstrates enterprise-grade security implementations in a financial trading environment. Students gain hands-on experience with both offensive (red team) and defensive (blue team) security techniques.

## 🔐 Key Security Features

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

## 🧪 Laboratory Exercises

### Exercise 1: Cryptographic Implementation Analysis
Students observe and analyze:
- AES-256-GCM encryption of order data
- RSA digital signatures for authenticity
- Merkle tree verification process
- Homomorphic encryption for secure analytics

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
- **Design**: Terminal-style interface with JetBeans Mono font
- **Real-time**: WebSocket connections for live updates
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
python init_platform.py

# Start the application
python backend/app/main.py
```

### Access the Application
Open your web browser and navigate to:
```
http://localhost:8000
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

## 🧪 Testing

Run the complete test suite:
```bash
python tests/run_tests.py
```

Run individual test modules:
```bash
python tests/test_suite.py
```

## 🔍 Security Features Demonstrated

### Data Protection
- Encryption at rest using AES-256-GCM
- Data integrity through RSA digital signatures
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

## 🎓 Educational Value

This project provides students with hands-on experience in:

1. **Cryptography Implementation**: Real-world application of encryption and digital signatures
2. **Security Architecture**: Defense-in-depth approach to system design
3. **Attack/Defense Techniques**: Practical experience with common security threats
4. **Incident Response**: Hands-on experience with security event handling
5. **Compliance Awareness**: Understanding of regulatory requirements

## 📚 Documentation

For detailed documentation, see:
- [Complete Documentation](docs/complete_documentation.md)
- [Project Summary](docs/PROJECT_SUMMARY.md)
- [Installation Guide](docs/INSTALLATION.md)
- [API Documentation](docs/documentation.md)
- [Project Structure](docs/PROJECT_STRUCTURE.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [Cryptography](https://cryptography.io/) for the robust cryptographic library
- [Tailwind CSS](https://tailwindcss.com/) for the beautiful styling
- All contributors who helped make this project possible

## 📞 Support

For support, please open an issue on the GitHub repository or contact the development team.

---

**Note**: This platform is designed for educational purposes in a laboratory environment. It should not be used in production without proper security review and hardening.