# Secure & Privacy‑Preserving Stock Trading Exchange — **MVP Build Map** (FastAPI + SQLite + Tailwind, no React)

This is a **developer-first roadmap** for an Agentic AI (or human) to scaffold and build the MVP.  
It specifies **functions, endpoints, pages, flows, DB schema, scripts, and observability** so you can implement without guesswork.

---

## 0) Tech Constraints & Principles
- **Backend:** Python 3.11+, FastAPI, SQLite3, Jinja2 templates.
- **Frontend:** Plain HTML + TailwindCSS (built via CLI or CDN), minimal vanilla JS (no React).
- **Crypto:** `cryptography` / `pycryptodome` for AES-GCM + signatures; simple Merkle tree; optional Paillier (`phe`) for aggregates (can be stubbed).
- **IDS:** Suricata/Snort preferred; provide **IDS-lite** fallback in-app regex detection + rate limits if system tools unavailable.
- **Simulations:** Local-only Red Team scripts via `subprocess` (sqlmap, hydra, curl) against **intentional, sandboxed** vulnerable endpoints.
- **Defense:** Blue Team parsing Suricata `eve.json` (or app logs), auto-blocklist (app-level middleware), incident timeline.
- **Port map:** FastAPI on `:8000`. Static files `/static`, templates `/templates`.

---

## 1) Project Layout
stock_secure_exchange/
├─ app/
│ ├─ main.py # FastAPI init, routes mounting, Jinja, middleware
│ ├─ database.py # SQLite init, migrations, connection helpers
│ ├─ models.py # SQL schema DDL + lightweight ORM helpers
│ ├─ schemas.py # Pydantic request/response models
│ ├─ middleware.py # IP blocklist + request logging
│ ├─ crypto/
│ │ ├─ encryption.py # AES-GCM encrypt/decrypt
│ │ ├─ key_mgmt.py # RSA/ECC keypair gen + exchange
│ │ ├─ signatures.py # SHA256 + digital signatures
│ │ ├─ merkle.py # Append-only Merkle log, proofs
│ │ └─ he_stub.py # Paillier aggregates (or stubbed sums)
│ ├─ services/
│ │ ├─ ids_service.py # Suricata/Snort wrapper, eve.json tail, IDS-lite fallback
│ │ ├─ incident.py # Auto-block IP, incident lifecycle
│ │ └─ charts.py # Matplotlib chart PNGs for analytics
│ ├─ routes/
│ │ ├─ auth.py # /auth/* login, signup, logout
│ │ ├─ orders.py # /orders/* place, list, view
│ │ ├─ analytics.py # /analytics/* secure aggregates + charts
│ │ ├─ logs.py # /logs/* IDS alerts, Merkle audit, app logs
│ │ └─ redblue.py # /sim/* run red-team attacks, show blue responses
│ ├─ utils/
│ │ ├─ demo_data.py # Seed users/stocks/orders
│ │ ├─ vulns.py # Intentionally vulnerable endpoints for lab use
│ │ └─ sse.py # Server-Sent Events stream (optional)
│ └─ settings.py # Paths, feature flags (USE_IDS_LITE, etc.)
├─ frontend/
│ ├─ templates/ # Jinja2 templates (Tailwind)
│ │ ├─ base.html
│ │ ├─ index.html
│ │ ├─ login.html
│ │ ├─ dashboard.html
│ │ ├─ trade.html
│ │ ├─ analytics.html
│ │ ├─ logs.html
│ │ └─ redblue.html
│ └─ static/
│ ├─ css/tailwind.css # Built CSS (or CDN via base.html)
│ └─ charts/ # Generated PNGs
├─ scripts/
│ ├─ manage.py # CLI: init_db, seed, start_ids, ids_lite, run_all
│ └─ rules/suricata.rules # Custom rules (SQLi/bruteforce/replay patterns)
└─ README.md



---

## 2) Database Schema (SQLite3)
```sql
-- users
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  public_key TEXT,            -- PEM
  private_key TEXT,           -- PEM (for lab only; prod would use HSM/keystore)
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- orders
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stock TEXT NOT NULL,
  qty INTEGER NOT NULL,
  side TEXT CHECK(side IN ('buy','sell')) NOT NULL,
  ciphertext BLOB NOT NULL,   -- AES-GCM
  nonce BLOB NOT NULL,
  signature BLOB NOT NULL,    -- detached signature of plaintext order JSON
  merkle_leaf TEXT NOT NULL,  -- leaf hash
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- merkle_roots (append-only checkpoints every N appends)
CREATE TABLE IF NOT EXISTS merkle_roots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  root_hash TEXT NOT NULL,
  total_leaves INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ids_alerts
CREATE TABLE IF NOT EXISTS ids_alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_type TEXT NOT NULL,        -- sqli, bruteforce, replay, mitm
  description TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  raw TEXT,                        -- raw eve.json or regex hit
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- incidents
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER,
  action TEXT NOT NULL,            -- block_ip, kill_session, ignore
  result TEXT,                     -- success/fail + detail
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(alert_id) REFERENCES ids_alerts(id)
);

-- blocklist
CREATE TABLE IF NOT EXISTS blocklist(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT UNIQUE NOT NULL,
  reason TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
3) Backend: Functions & What They Do
3.1 Crypto (app/crypto)

encryption.py

encrypt_order(plaintext: dict, key: bytes) -> (ciphertext: bytes, nonce: bytes)

decrypt_order(ciphertext: bytes, nonce: bytes, key: bytes) -> dict

key_mgmt.py

generate_keypair(curve='SECP256R1') -> (pub_pem, priv_pem)

derive_session_key(server_priv, client_pub) -> bytes (ECIES-style for lab)

signatures.py

sign(data_bytes: bytes, priv_pem: str) -> bytes

verify(data_bytes: bytes, sig: bytes, pub_pem: str) -> bool

merkle.py

append_leaf(leaf_hash: str) -> new_root: str

leaf_for_order(order_id: int) -> leaf_hash: str

prove(order_id: int) -> {leaf, path[], root}

checkpoint_every(n: int) (store in merkle_roots)

he_stub.py

he_sum(encrypted_values) -> encrypted_sum (stub: normal sum for MVP)

he_vwap_stub(prices, qtys) -> float (plaintext MVP; note where HE plugs in)

3.2 Models / Data (app/models.py)

CRUD helpers:

create_user(username, password_hash, pub_pem, priv_pem)

get_user_by_username(username)

insert_order(user_id, stock, qty, side, ciphertext, nonce, signature, merkle_leaf)

get_orders_for_user(user_id)

insert_alert(alert_type, description, src_ip, dst_ip, raw)

insert_incident(alert_id, action, result)

add_block_ip(ip, reason) / is_blocked(ip)

3.3 IDS Service (app/services/ids_service.py)

External IDS:

start_suricata(config_path, iface, rules_path) -> pid

tail_eve_json(path) -> generator[dict] (yield events)

IDS-lite fallback:

scan_request_for_ioc(req) -> list[match] (regex for ' or 1=1, union select, etc.')

rate_limit_key(ip, username) -> bool (flag brute-force attempts)

Alert integration:

raise_alert(alert_type, description, src_ip, dst_ip, raw)

3.4 Incident Automation (app/services/incident.py)

block_ip(ip, reason='IDS match') -> bool (insert into blocklist)

handle_alert(alert_row) -> incident_row (policy: block SQLi/replay sources)

blocked_middleware(request): deny request if client.host in blocklist

3.5 Charts (app/services/charts.py)

vwap_png(output_path) using Matplotlib → save single-plot PNG (no seaborn).

3.6 Routes (app/routes/\*.py) — Endpoints

Auth

GET /auth/login → page

POST /auth/login → set session

GET /auth/signup / POST /auth/signup

POST /auth/logout

Orders

GET /orders → list (decrypt for current user)

GET /orders/new → page

POST /orders → encrypt+sign+store+append merkle

GET /orders/{id} → detail + merkle proof

Analytics

GET /analytics → page

GET /analytics/vwap.png → chart image

Logs

GET /logs → IDS alerts table + incident actions

GET /logs/merkle → checkpoint list, proof viewer

Sim (Red/Blue)

GET /sim → control panel page

POST /sim/sqlmap → run sqlmap vs /vuln/unsafe_search?q=

POST /sim/bruteforce → run hydra vs /auth/login

POST /sim/replay → resend captured request from /tmp/replay.json

POST /sim/mitm → (optional) local proxy replay (document fallback)

3.7 Vulnerable Endpoints (lab-only) (app/utils/vulns.py)

GET /vuln/unsafe_search?q=... → intentionally concatenates SQL (isolated read-only view)
Guard: route is behind feature flag ENABLE_VULNS + banner.

4) Frontend Pages (Jinja2 + Tailwind) — What Users See

base.html

Top nav: Dashboard | Trade | Analytics | Logs | Sim

Status pill (green/yellow/red): shows SAFE | UNDER ATTACK | MITIGATING (derived from last alert age & incidents)

If ENABLE_VULNS: red banner “LAB MODE / VULNS ENABLED”

index.html

Landing with quick links, system overview

login.html / signup

Simple forms; show brute-force lockout message when triggered

dashboard.html

My Orders table (decrypted)

System Status: last 5 alerts, last 5 incidents

Live feed: polling /logs?latest=true every 5s (vanilla JS setInterval)

trade.html

Buy/Sell form: stock, qty, side

After submit: show plaintext order JSON + signature preview + merkle leaf

analytics.html

<img src="/analytics/vwap.png" /> rendered server-side (Matplotlib)

Table of plaintext (MVP) aggregates; note where HE plugs in

logs.html

IDS Alerts: type, src_ip, desc, time

Incidents: action taken (block IP), result

Merkle: list checkpoints + “View Proof” modal for order id

redblue.html (Simulation Control)

Buttons: Run SQLi, Run Bruteforce, Run Replay, Run MITM

A timeline panel updates with:

Red attempt output (stdout tail)

Blue detection (alert)

Auto-response (incident result)

A simple <pre> log area that fetches last N lines from /logs?tail=N every 3–5s.

5) Red Team → Blue Team Simulation Flows (Exact Actions)
5.1 SQL Injection

Red: POST /sim/sqlmap runs:

Always show details
sqlmap -u "http://127.0.0.1:8000/vuln/unsafe_search?q=TEST" --batch --level=2 --risk=1


Blue: Suricata rule (or IDS-lite regex) flags SQL keywords in querystring → ids_alerts row.

Auto-Response: incident.handle_alert() blocks source IP.

UX: redblue.html timeline shows “SQLi attempt → detected → IP blocked”.

5.2 Bruteforce Login

Red: POST /sim/bruteforce runs hydra against /auth/login with a small wordlist.

Blue: Rule detects N failed logins from same IP in window → alert.

Auto-Response: temporary block for that IP; show lockout on login.html

UX: Alerts + incidents visible in logs.html & dashboard status pill goes RED during the window.

5.3 Replay Attack

Red: POST /sim/replay reads /tmp/replay.json (earlier captured order) and resends via curl.

Blue: App verifies nonce/replay token; rejects duplicates → raises alert “replay detected”.

Auto-Response: optional block; at minimum log incident.

UX: Timeline shows “Replay rejected; order integrity maintained”.

5.4 MITM (Optional, local proxy)

Red: Proxy traffic through mitmproxy or local replay.

Blue: Because of signatures, tampering invalidates signature → order rejected; alert raised.

UX: Show failed signature verify in logs.html with diff of hash.

6) Observability & “How They See What’s Happening”

Status Pill (global): SAFE (no alerts 5m), UNDER ATTACK (alert in last 60s), MITIGATING (incident in last 60s).

Live Timeline (redblue.html): poll /logs?tail=N to render recent events.

IDS Alerts Page (logs.html): table w/ filters (type/ip/time).

Incident Pagelet: actions taken (blocklist results).

Merkle Proof Viewer: enter order id → show leaf, path, root; compare to latest root.

App Logs: /logs?app=true returns last N structured JSON log lines for <pre> display.

Server-Sent Events (optional): /events stream; client-side EventSource to append to timeline.

7) Tailwind Setup (No React)

Option A (fastest): Use Tailwind CDN in base.html (ok for lab).

Option B (local build):

Always show details
npm i -D tailwindcss
npx tailwindcss init
npx tailwindcss -i ./frontend/static/css/input.css -o ./frontend/static/css/tailwind.css --watch


Use utility classes only; minimal JS for polling.

8) Scripts (scripts/manage.py)

init_db → create tables

seed → create demo user + sample stocks + a few orders

start_ids → launch Suricata with local rules, write eve.json

ids_lite → start app-level detector (regex + rate limit)

run_all → init_db && seed && start_ids||ids_lite && uvicorn app.main:app --reload

9) Minimal Accept/Smoke Tests

Auth: cannot login with wrong pwd > 5 times in 60s (locks + alert)

Order: place order → decrypt shows correct values; signature verifies; merkle leaf updates; checkpoint every 10.

SQLi Sim: run → alert appears; blocklist updated; subsequent requests from attacker IP are 403.

Replay: resend saved order → rejected; alert + incident recorded.

Analytics: /analytics/vwap.png returns a PNG (single plot).

10) Build/Run Checklist
Always show details
python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install fastapi uvicorn jinja2 cryptography pycryptodome bcrypt matplotlib
# optional: phe (Paillier), suricata installed via OS package manager

python scripts/manage.py init_db
python scripts/manage.py seed
python scripts/manage.py start_ids   # or: python scripts/manage.py ids_lite
uvicorn app.main:app --reload
# Open: http://localhost:8000


Demo flow: Login → Trade (place order) → Sim (run SQLi) → Logs (see alert & incident) → Dashboard status pill flips → Verify Merkle for your order.

11) Security Notes (MVP vs Real)

Private keys in DB = lab only.

Vulnerable routes gated by ENABLE_VULNS and a big red banner.

Blocklist is app-level; for system-level use iptables (not required for MVP).

HE is stubbed; wire in Paillier later if required by lab rubric.

12) Out-of-the-Box Custom Suricata Rules (example)

scripts/rules/suricata.rules minimal examples:

Always show details
alert http any any -> $HOME_NET any (msg:"SQLi keyword"; content:"UNION SELECT"; nocase; sid:100001; rev:1;)
alert http any any -> $HOME_NET any (msg:"Login brute-force pattern"; threshold:type both, track by_src, count 5, seconds 60; content:"/auth/login"; http_uri; sid:100002; rev:1;)
alert http any any -> $HOME_NET any (msg:"Replay token reuse"; content:"X-Nonce:"; within:0; sid:100003; rev:1;)


(If Suricata unavailable, IDS-lite emits equivalent alerts from app logs.)

13) Hand-off to Agentic AI

Scaffold folders & files per layout.

Implement DB schema via database.py migration.

Implement crypto primitives; wire into POST /orders.

Build Jinja templates w/ Tailwind; add polling JS on dashboard/logs/sim pages.

Implement IDS service (Suricata tail or IDS-lite) + incident automation + middleware block.

Implement Red Team subprocess calls in /sim\* handlers.

Ship charts endpoint producing PNG images (Matplotlib, one plot per figure).

Provide scripts/manage.py to orchestrate whole flow.
