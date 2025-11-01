# Secure Stock Trading Exchange

Secure trading platform with real-time matching, cryptographic protections, and attack-defense simulation lab.

## Quick start
```bash
git clone https://github.com/yourusername/secure-trading-platform.git
cd secure-trading-platform
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -c "from backend.app.database import DatabaseManager; DatabaseManager().init()"
python backend/app/main.py
