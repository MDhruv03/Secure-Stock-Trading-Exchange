# Secure & Privacy-Preserving Stock Trading Exchange with Integrated Attack–Defense Simulation

## 📌 Overview
This project aims to build a **secure stock trading simulation platform** that integrates:
- **Applied Cryptography** (confidentiality, integrity, privacy-preserving analytics)
- **Red vs Blue Team Security Simulation** (attack–defense cycles)
- **SOC-style monitoring & automated response**

The system demonstrates how **cryptographic safeguards** and **real-time intrusion detection/response** reinforce each other to secure financial systems against cyberattacks.

---

## 🎯 Objective
Design and implement a secure trading exchange where:
- Clients place **encrypted buy/sell orders**
- The system ensures **confidentiality, integrity, authentication, and privacy**
- Simulated **Red Team attacks** (SQL injection, MITM, replay) are launched
- **Blue Team defense** (IDS, SIEM, automation) detects and mitigates threats in real time

---

## 📜 Scope
1. **Cryptographic Security**
   - AES-GCM for confidentiality
   - RSA/ECC for key exchange
   - SHA-256 + digital signatures for data integrity
   - Merkle trees for tamper-proof audit logs
   - Paillier Homomorphic Encryption for secure analytics (e.g., VWAP)
   - Searchable Symmetric Encryption for log queries

2. **Attack Simulation (Red Team)**
   - Reconnaissance with Nmap, Burp Suite
   - SQL Injection with Sqlmap
   - MITM & replay attacks with Wireshark/MITMf
   - Brute-force login with Hydra

3. **Defense (Blue Team)**
   - IDS (Snort/Suricata) to monitor network traffic
   - Log aggregation & visualization with ELK/Splunk
   - Custom IDS rules for SQLi, brute-force, replay attacks
   - Python automation: block attacker IPs, terminate sessions, structured incident logging

4. **Integration**
   - If IDS misses → cryptography still protects integrity & confidentiality
   - If IDS catches → automated response neutralizes the threat
   - End-to-end workflow reflects real-world **SOC operations** in a **fintech context**

---

## 📈 Need for the Application
- Cyberattacks on financial institutions are **growing rapidly**
- Traditional projects focus only on cryptography OR intrusion detection
- This project **bridges the gap**, showcasing:
  - Advanced cryptography for privacy & integrity
  - SOC-style monitoring & defense automation
- Prepares students for **both FinSec research** and **cybersecurity operations**

---

## 🛠️ Project Description
### Workflow
1. Client submits encrypted buy/sell order
2. Trading server verifies signatures, updates tamper-proof logs
3. IDS monitors network for malicious traffic
4. Red Team launches attacks (SQLi, MITM, replay, brute force)
5. Blue Team detects anomalies & auto-blocks attacker
6. Privacy-preserving analytics are run on encrypted data

### Attack → Defense Demo
- **Attack:** SQL Injection on trade database  
- **Defense:** IDS detects query pattern → Auto firewall block → Integrity preserved by signatures & Merkle trees

---


## 🖥️ Software Requirements
- **Virtualization:** VMware / VirtualBox  
- **OS:** Kali Linux, Ubuntu/Debian  
- **Tools:** Wireshark, OpenSSL, PyCryptodome, phe, Cryptography, Hashcat, Snort/Suricata, Sqlmap, Burp Suite, Hydra  
- **Database:** SQLite/PostgreSQL  
- **Languages:** Python 3.x, Bash  
- **IDE:** PyCharm / VS Code  
- **Visualization:** Matplotlib, Pandas  
- **Log Management:** ELK Stack / Splunk  

---

## 📦 Deliverables
- ✅ System architecture & network diagrams  
- ✅ Threat analysis & vulnerability assessment reports  
- ✅ Benchmarks for encryption overhead  
- ✅ IDS detection logs & automated incident response reports  
- ✅ Demo video showing:  
  1. Encrypted order placement  
  2. Attack execution  
  3. IDS alert & automated defense  
  4. Verification of log integrity via Merkle trees  

---

## 🚀 Getting Started

To set up and run the Secure Trading Exchange, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MDhruv03/Secure-Stock-Trading-Exchange
    cd "Secure Trading Exchange"
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv .venv
    # On Windows:
    .venv\Scripts\activate
    # On macOS/Linux:
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the database and seed with demo data:**
    ```bash
    python scripts/manage.py init_db
    python scripts/manage.py seed_db
    ```

5.  **Start the FastAPI application:**
    ```bash
    python scripts/manage.py start_app
    ```

6.  **Access the application:**
    Open your web browser and navigate to `http://localhost:8000`.

---