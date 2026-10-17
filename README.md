# AEGIS SENTINEL

**A real network intrusion-detection system for Linux, with an LLM-backed AI analyst.**

No simulation. No demo data. No fake alerts. If the agent is not running, the UI shows **AGENT OFFLINE** and displays nothing. If nothing malicious crosses your network, the alerts tab stays empty.

---

## Table of Contents

1. [What it does](#what-it-does)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation (with Python venv)](#installation-with-python-venv)
5. [Free API keys](#free-api-keys)
6. [Running the agent](#running-the-agent)
7. [Using the UI](#using-the-ui)
8. [The AI assistant](#the-ai-assistant)
9. [Detection rules](#detection-rules)
10. [Running as a systemd service](#running-as-a-systemd-service)
11. [Remote access (secure)](#remote-access-secure)
12. [File layout](#file-layout)
13. [Troubleshooting](#troubleshooting)
14. [Security model](#security-model)
15. [Legal](#legal)

---

## What it does

Aegis Sentinel watches the packets flowing through your Linux machine's network interface and tells you when something malicious is happening. It runs 10 real detection rules, enriches every alert with real threat-intelligence from public APIs, saves the triggering packet for forensic analysis, and — optionally — blocks the attacker's IP with `iptables`.

You get a browser dashboard with:

- **Live alerts** — severity, source, MITRE ATT&CK mapping, AbuseIPDB reputation, one-click block
- **Live packets** — every frame the agent actually captured
- **WiFi scan** — real nearby networks scored for encryption risk
- **Blocked IPs** — real `ipset` entries with countdown timers
- **AI assistant** — an LLM that reasons over your real alert data, and refuses to answer when it can't ground a claim in real evidence

---

## Architecture







┌──────────────────────────────────────────────────────────────┐
│ sentinel.py (runs as root, captures + blocks) │
│ │
│ Scapy AsyncSniffer ──► Detector (10 rules) │
│ │ │ │
│ ▼ ▼ │
│ PacketView Alert + PCAP saved │
│ │ │ │
│ │ ▼ │
│ │ IntelClient (async) │
│ │ ├─ AbuseIPDB │
│ │ ├─ URLhaus │
│ │ ├─ PhishTank │
│ │ └─ HIBP │
│ │ │ │
│ │ ▼ │
│ │ Firewall (ipset + iptables) │
│ │ │ │
│ ▼ ▼ │
│ ┌────────────────────────────────┐ │
│ │ aiohttp WebSocket server │ │
│ │ ws://127.0.0.1:8765/ws │◄──── ai_engine ───┐│
│ └────────────────────────────────┘ ││
└──────────────────────────┬───────────────────────────────────┘│
│ WebSocket (localhost only) │
▼ │
┌──────────────────────────────────────────────────────────────┤
│ ui.html (browser) │
│ Alerts · Packets · WiFi · Blocked · AI │
│ │
│ ai_engine.py ──► Ollama / OpenAI-compatible endpoint │
└──────────────────────────────────────────────────────────────┘




The agent is the source of truth. The UI is a thin renderer. The AI receives only a **sanitised context bundle** — truncated payload previews, alert metadata, intel verdicts — never raw packet bytes.

---

## Requirements

### Operating system

- **Ubuntu 22.04 / 24.04** (tested)
- **Debian 12** (tested)
- Any modern Linux with NetworkManager, `iptables`, and `ipset`

macOS and Windows are **not supported**.

### Privileges

- The Python agent **must run as root** for raw packet capture (`CAP_NET_RAW`) and firewall changes (`CAP_NET_ADMIN`).

### Python

- **Python 3.10+**
- Python packages: `scapy`, `aiohttp`, `openai`

### For the AI assistant (pick one)

- **Ollama** (local, free, private) — `llama3.1:8b` needs ~5 GB VRAM/RAM
- **OpenAI-compatible endpoint** — OpenAI, OpenRouter, local vLLM, etc.

---

## Installation (with Python venv)

Using a Python virtual environment keeps Aegis Sentinel's dependencies isolated from your system Python. **This is the recommended install method.**

### 1. System packages

```bash
sudo apt update
sudo apt install -y \
    python3-venv \
    python3-pip \
    ipset \
    iptables \
    network-manager \
    libpcap-dev



#2. Clone the repository
git clone https://github.com/Albinbasiljacob/sentinal.git
cd sentinal

#Create and activate the virtual environment
# Create the venv inside the project directory
python3 -m venv venv

# Activate it
source venv/bin/activate

# Verify — your prompt should now show (venv)
which python    # → /path/to/sentinal/venv/bin/python

Install Python dependencies inside the venv
# Must be run with the venv active
pip install --upgrade pip
pip install -r requirements.txt

Free API keys

All keys are free. Without them, the agent runs but alerts won't be enriched.
Service	URL	Free tier
URLhaus (abuse.ch)	https://auth.abuse.ch/	Unlimited with Auth-Key
AbuseIPDB	https://www.abuseipdb.com/account/api	1,000/day
PhishTank (optional)	https://www.phishtank.com/api_register.php	Free with app key
URLhaus (Auth-Key required as of 30 June 2025)

    Register at https://auth.abuse.ch/

    Connect GitHub / X / Google

    Dashboard → Optional → Generate Auth-Key

    Copy the key (starts with rh...)

Set environment variables
bash

export URLHAUS_AUTH_KEY="your_urlhaus_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export PHISHTANK_APP_KEY="your_phishtank_key"      # optional

# Persist across shells
cat >> ~/.bashrc << 'EOF'
export URLHAUS_AUTH_KEY="your_urlhaus_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
EOF
source ~/.bashrc

    Critical: always launch with sudo -E. The -E flag preserves your environment variables (including the venv's PATH) through sudo. Without it, the agent won't see the API keys.

Running the agent
Key venv + sudo gotcha

sudo normally drops the environment — including venv activation. This means sudo python3 sentinel.py will use system Python, not the venv, and import scapy will fail.

Two solutions:

Option A — use sudo -E with venv active (recommended)
bash

source venv/bin/activate
sudo -E venv/bin/python sentinel.py --iface eth0 --autoblock

sudo -E preserves the environment. Explicitly pointing at venv/bin/python guarantees the venv interpreter is used.

Option B — use the venv's python binary directly (no activation needed)
bash

sudo venv/bin/python sentinel.py --iface eth0 --autoblock

This works from any shell — no source venv/bin/activate required. Use this for systemd.
Steps

1. Find your interface
bash

python sentinel.py --list          # with venv active

Output looks like:
text

Available interfaces:
  lo
  eth0
  wlan0

Use eth0 for wired. On wlan0 in managed mode, the kernel only delivers frames addressed to your machine — see the note below.

2. Start the agent
bash

# Observe only
sudo venv/bin/python sentinel.py --iface eth0

# With auto-block
sudo -E venv/bin/python sentinel.py --iface eth0 --autoblock

You should see:
text

2025-01-15 14:32:01 [INFO] Intel client ready (urlhaus=True abuseipdb=True phishtank=False)
2025-01-15 14:32:01 [INFO] AI engine ready — llama3.1:8b via http://localhost:11434/v1
2025-01-15 14:32:01 [INFO] Sniffer starting on eth0
2025-01-15 14:32:02 [INFO] UI:      http://127.0.0.1:8765
2025-01-15 14:32:02 [INFO] Iface:   eth0
2025-01-15 14:32:02 [INFO] Auto-block: ON

If you see AI engine not ready, that's fine — the detection pipeline still works. Check the AI troubleshooting section.

    Why wlan0 shows less traffic: in managed mode, the Wi-Fi driver drops frames not addressed to your MAC. Full visibility requires monitor mode (via airmon-ng), which changes the NIC's operating behaviour and is out of scope. Use eth0 for network-wide visibility.

Command-line options
Flag	Default	Description
--iface	eth0	Capture interface (see --list)
--port	8765	WebSocket UI port
--bind	127.0.0.1	Bind address (keep localhost)
--autoblock	off	Auto-block HIGH/CRITICAL sources
--list	—	List interfaces and exit
--ui	ui.html	Path to the UI file
Using the UI

Open http://127.0.0.1:8765 in your browser.
Alerts tab

Every detection, sorted newest-first. Each alert shows:

    Severity badge (critical / high / medium / low)

    Rule name + MITRE ATT&CK ID

    Source → Destination:Port

    Summary

    AbuseIPDB reputation (if enriched)

    Block IP button

    PCAP path — where the raw packet was saved

    Ask AI about this — jumps to AI tab with source/rule pre-filled

Packets tab

Live ring buffer of the last 500 captured packets — timestamp, protocol, source, destination, ports, length, flags, Scapy summary.
WiFi tab

Click Scan now to run a real nmcli device wifi list. Each network is scored by encryption:
Security	Risk
OPEN / empty	CRITICAL
WEP	CRITICAL
WPA (no 2/3)	HIGH
WPA2 (no 3)	LOW
WPA3	INFO
Blocked tab

All current ipset entries with rule, timestamp, and time-to-expiry. One-click unblock.
AI tab

See the next section.
The AI assistant

The AI is a real LLM (Ollama or OpenAI-compatible) with a strict system prompt that forbids fabrication. It receives only a sanitised context bundle from the agent — alerts, packet summaries, intel verdicts — and is required to say "I don't have data on that" when the context lacks the answer.
Setting up Ollama (local, free)
bash

# Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (one-time, ~5 GB)
ollama pull llama3.1:8b
# or, for lower VRAM:
ollama pull llama3.2:3b

# Ollama serves itself on :11434 — no extra command needed

Then run the agent:
bash

export AEGIS_AI_BACKEND=ollama
export AEGIS_AI_MODEL=llama3.1:8b
sudo -E venv/bin/python sentinel.py --iface eth0 --autoblock

VRAM guide:
VRAM	Model
CPU only	llama3.2:3b
8 GB	llama3.1:8b, dolphin-llama3
10–12 GB	qwen2.5:14b-instruct-q4_K_M
16–24 GB	qwen2.5:32b-instruct-q4_K_M
Setting up a cloud backend
bash

export AEGIS_AI_BACKEND=openai
export AEGIS_AI_MODEL=gpt-4o-mini
export AEGIS_AI_BASE_URL=https://api.openai.com/v1
export OPENAI_API_KEY=sk-...
sudo -E venv/bin/python sentinel.py --iface eth0 --autoblock

Privacy warning: in this mode, alert metadata (source IPs, packet summaries, intel verdicts) is sent to the provider. Do not use on networks carrying regulated data unless cleared with compliance.
What the AI can and cannot do

Can:

    Explain the last alert in context

    Distinguish a scanner from a real attacker (weights AbuseIPDB score + port spread + payload)

    Recommend next actions with reasoning

    Summarise patterns across recent alerts

    Explain a payload signature in plain language

Cannot / will not:

    Invent IPs, CVEs, malware names, or threat actors

    Answer off-topic questions (weather, sports, etc.)

    Explain how to weaponise a payload

    Suggest attacking systems the operator doesn't own

When it doesn't have data, it says so:
text

you › what's the weather?
bot › I only answer questions grounded in the current agent context
      (alerts, packets, intel). Ask about an alert, a source IP, or
      the agent state.

That refusal is what makes the other answers trustworthy.
Detection rules
Rule	Trigger	Severity	MITRE
SYN_FLOOD	≥100 SYN/sec from one source	HIGH	T1498.001
PORT_SCAN	≥15 distinct ports in 10s	MEDIUM	T1046
DNS_TUNNEL	≥50 DNS queries in 5s, or TXT > 100 bytes	HIGH	T1071.004
ARP_SPOOF	Same IP announced by ≥2 MACs	HIGH	T1557.002
BRUTE_FORCE	≥10 auth attempts to 22/3389/5900/5985 in 30s	HIGH	T1110
MALICIOUS_PAYLOAD	SQLi, XSS, path traversal, Log4Shell, cmd injection, reverse shell, SSRF-metadata	CRITICAL	T1190
SUSPICIOUS_UA	sqlmap, nikto, masscan, nuclei, gobuster, …	MEDIUM	T1595
CLEARTEXT_CREDS	password=/api_key=/cvv= on port 80	CRITICAL	T1040
DATA_EXFIL	≥5 MB private → public in 60s	HIGH	T1041
URLHAUS_HIT	Observed URL matches URLhaus cache	CRITICAL	T1071

Every alert saves the triggering packet to captures/{alert_id}.pcap. Inspect with Wireshark:
bash

wireshark captures/a3f9c2e1d4b8.pcap

Treat captures/ as sensitive — PCAPs contain real traffic:
bash

sudo chmod 700 captures/
sudo chmod 600 captures/*.pcap
find captures/ -name '*.pcap' -mtime +7 -delete

Running as a systemd service

Using the venv's Python binary directly avoids sudo -E and any activation issues.
1. Create the unit file
bash

sudo nano /etc/systemd/system/aegis-sentinel.service

2. Paste (replace YOURUSER and eth0)
ini

[Unit]
Description=Aegis Sentinel Network IDS
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="URLHAUS_AUTH_KEY=your_urlhaus_key"
Environment="ABUSEIPDB_API_KEY=your_abuseipdb_key"
Environment="AEGIS_AI_BACKEND=ollama"
Environment="AEGIS_AI_MODEL=llama3.1:8b"
Environment="AEGIS_AI_BASE_URL=http://localhost:11434/v1"

# Use the venv's python binary — no activation needed
ExecStart=/home/YOURUSER/sentinal/venv/bin/python /home/YOURUSER/sentinal/sentinel.py --iface eth0 --autoblock
WorkingDirectory=/home/YOURUSER/sentinal

Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

3. Enable and start
bash

sudo systemctl daemon-reload
sudo systemctl enable --now aegis-sentinel
sudo systemctl status aegis-sentinel

4. Logs
bash

journalctl -u aegis-sentinel -f

Look for Intel client ready (urlhaus=True ...) and AI engine ready on startup. If either shows False or not ready, the environment variables in the unit file are wrong.
Remote access (secure)

    ⚠️ The agent runs as root and can block IPs. Never bind to 0.0.0.0 without an authenticated TLS proxy.

Option A — SSH port forwarding (recommended)

On your local machine:
bash

ssh -L 8765:127.0.0.1:8765 user@server-ip

Keep the session open, then open http://127.0.0.1:8765 in your browser. End-to-end encrypted by SSH. Agent stays bound to localhost.
Option B — Nginx + TLS + Basic Auth

Only if you need browser-only access from a remote device.
bash

sudo apt install -y nginx certbot python3-certbot-nginx apache2-utils
sudo htpasswd -c /etc/nginx/.aegis-htpasswd yourusername
sudo nano /etc/nginx/sites-available/aegis-sentinel

nginx

server {
    listen 443 ssl;
    server_name sentinel.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/sentinel.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinel.yourdomain.com/privkey.pem;

    auth_basic           "Aegis Sentinel";
    auth_basic_user_file /etc/nginx/.aegis-htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
    }
}

bash

sudo ln -s /etc/nginx/sites-available/aegis-sentinel /etc/nginx/sites-enabled/
sudo certbot --nginx -d sentinel.yourdomain.com
sudo systemctl reload nginx

# Rebind the agent
sudo -E venv/bin/python sentinel.py --iface eth0 --bind 0.0.0.0

Bind to 0.0.0.0 only after Nginx is working.
File layout
text

sentinal/
├── venv/                     ← Python virtual environment (created by you)
├── sentinel.py               ← agent (root, captures + blocks)
├── ai_engine.py              ← LLM wrapper
├── ui.html                   ← UI (browser, no data of its own)
├── requirements.txt          ← Python dependencies
├── README.md                 ← this file
├── captures/                 ← PCAPs, one per alert (auto-created)
│   ├── a3f9c2e1d4b8.pcap
│   └── ...
└── sentinel.log              ← agent log (auto-created)

captures/ and sentinel.log are created on first run. venv/ is created by you during install.
Troubleshooting
ModuleNotFoundError: No module named 'scapy'

You installed dependencies in system Python, but are running under sudo without the venv.

Fix:
bash

source venv/bin/activate
sudo -E venv/bin/python sentinel.py --iface eth0
# or
sudo venv/bin/python sentinel.py --iface eth0

Never use bare sudo python3 after installing in a venv — that uses system Python.
command not found: python3-venv during install
bash

sudo apt install -y python3-venv python3-full

On some distros you need python3-full.
PermissionError: [Errno 1] Operation not permitted

You're not running as root. Use sudo -E venv/bin/python ... (or sudo venv/bin/python ...).
Intel client ready (urlhaus=False abuseipdb=False)

Either you didn't export the keys, or you used sudo without -E.
bash

echo $URLHAUS_AUTH_KEY
echo $ABUSEIPDB_API_KEY

If they're set in your shell but the agent doesn't see them, use sudo -E.
AI engine not ready

If using Ollama:
bash

# Is Ollama running?
curl http://localhost:11434/api/tags

# Have you pulled the model?
ollama pull llama3.1:8b

If using OpenAI: check OPENAI_API_KEY and AEGIS_AI_BACKEND=openai.

The detection pipeline continues to work even when the AI is down. The AI is a layer on top.
Cannot find interface eth0
bash

python sentinel.py --list

Use the correct name (enp3s0, wlp2s0, etc.).
ipset: command not found
bash

sudo apt install ipset

Without ipset, blocking falls back to per-IP iptables rules — slower but functional.
UI shows AGENT OFFLINE

    Agent not running: systemctl status aegis-sentinel or ps aux | grep sentinel

    Wrong port: check sentinel.log for UI: http://...

    Port blocked locally: sudo ss -tlnp | grep 8765

    You opened ui.html directly from disk — the WebSocket will fail. Always load from http://127.0.0.1:8765 (the agent serves the UI itself).

URLhaus sync failed: HTTP 401

Your URLHAUS_AUTH_KEY is invalid or expired. Regenerate at https://auth.abuse.ch/.
AbuseIPDB: rate limit

Free tier is 1,000/day. Results are cached for 10 minutes. Wait 24 hours or upgrade.
wlan0 shows almost no packets

Expected. Managed-mode WiFi drops frames not addressed to your MAC. Use eth0 for network-wide capture.
iptables: permission denied

Not root, or iptables locked by Docker/ufw. Check:
bash

sudo iptables -L INPUT -n | head

Alerts appear but no PCAPs
bash

ls -ld captures
mkdir -p captures

Security model
Agent can

    Read every frame on the capture interface (root)

    Add/remove its own iptables/ipset rules

    Call external APIs (URLhaus, AbuseIPDB, PhishTank, HIBP)

    Call the configured LLM endpoint

    Write to captures/ and sentinel.log

Agent cannot

    Modify existing firewall rules

    Flush iptables or ipset

    Execute shell commands from packet contents

    Write files outside captures/ and sentinel.log

UI can

    Read packets, alerts, blocked list, stats

    Trigger WiFi scan

    Block/unblock IPs

    Send AI queries

UI cannot

    Run shell commands

    Read files on the host

    Reach the network beyond the WebSocket

    Authenticate as anyone (bind to localhost, or add auth proxy for remote)

Data leaving your machine
Data	Destination	When
SHA-1 prefix (5 hex chars)	api.pwnedpasswords.com	Only when a password is submitted
Alert source IPs	api.abuseipdb.com	Only when ABUSEIPDB_API_KEY is set and an alert fires
URLs in payloads	urlhaus-api.abuse.ch, checkurl.phishtank.com	Only when the corresponding keys are set
Sanitised context bundle	Ollama (localhost) or your chosen LLM provider	Only when you ask the AI a question
Nothing else	—	—

No telemetry. No analytics. No phone-home. The AI's privacy profile depends entirely on your backend choice — Ollama keeps everything local; cloud providers receive alert metadata.
Legal

Aegis Sentinel captures network traffic and modifies firewall rules. Run it only on networks you own or have explicit written authorisation to monitor.

Unauthorised interception may violate:

    US: Computer Fraud and Abuse Act (18 U.S.C. § 1030), Wiretap Act (18 U.S.C. § 2511)

    UK: Computer Misuse Act 1990, Regulation of Investigatory Powers Act 2000

    EU: Directive 2013/40/EU, GDPR (traffic may contain personal data)

    India: Information Technology Act 2000, § 66, § 69

Every block the agent performs is timestamped in sentinel.log for audit.
Credits

    Scapy — packet capture

    aiohttp — async HTTP + WebSocket

    URLhaus — malware URL intelligence

    AbuseIPDB — IP reputation

    PhishTank — phishing database

    Have I Been Pwned — Pwned Passwords

    MITRE ATT&CK — technique taxonomy

    Ollama — local LLM runtime

License

MIT. See LICENSE for details.
