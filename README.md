# sentinal
# AEGIS SENTINEL

**A real network intrusion-detection system for Linux.**

No simulation. No demo data. No fake alerts.

![Status](https://img.shields.io/badge/status-stable-green)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## What it does

Aegis Sentinel watches the packets flowing through your Linux machine's network interface and tells you when something malicious is happening. It runs 10 real detection rules, enriches every alert with real threat-intelligence from public APIs, saves the triggering packet for forensic analysis, and — optionally — blocks the attacker's IP with `iptables`.

You get a browser dashboard that shows:
- **Live alerts** with severity, source, MITRE ATT&CK mapping, and AbuseIPDB reputation
- **Live packets** — every frame the agent actually captured
- **WiFi scan** — real nearby networks scored for encryption risk
- **Blocked IPs** — real `ipset` entries with countdown timers
- **AI assistant** — answers questions using only real packets, real alerts, and real API calls

If nothing malicious crosses your network, the alerts tab stays empty. That empty tab is the whole point — this tool earns trust by refusing to guess.

---

## Why this exists

Most "cybersecurity dashboards" you find online are fake. They show invented packets, simulated attacks, and pre-recorded "alerts" that mean nothing. They look impressive and teach nothing.

Aegis Sentinel is the opposite. Every packet on screen was captured by the kernel. Every alert fired on a real rule triggered by a real packet. Every IP reputation score came from a real API call. Every blocked IP is a real `iptables` rule.

If a browser-based tool claims to do packet capture or firewall blocking, it is lying. Browsers cannot open raw sockets or modify kernel state. That's why this project has a Python agent — it's the only way to do it honestly.

---

## Features

### Detection (10 real rules)

| Rule | What fires it | Severity | MITRE |
|---|---|---|---|
| `SYN_FLOOD` | ≥100 SYN packets/sec from one source | HIGH | T1498.001 |
| `PORT_SCAN` | ≥15 distinct destination ports in 10s | MEDIUM | T1046 |
| `DNS_TUNNEL` | ≥50 DNS queries in 5s, or TXT > 100 bytes | HIGH | T1071.004 |
| `ARP_SPOOF` | Same IP announced by ≥2 MACs | HIGH | T1557.002 |
| `BRUTE_FORCE` | ≥10 auth attempts to 22/3389/5900/5985 in 30s | HIGH | T1110 |
| `MALICIOUS_PAYLOAD` | SQLi, XSS, path traversal, Log4Shell, cmd injection, reverse shell, SSRF-to-metadata | CRITICAL | T1190 |
| `SUSPICIOUS_UA` | sqlmap, nikto, masscan, nuclei, gobuster, hydra, … | MEDIUM | T1595 |
| `CLEARTEXT_CREDS` | `password=`/`api_key=`/`cvv=` on port 80 | CRITICAL | T1040 |
| `DATA_EXFIL` | ≥5 MB private → public in 60s | HIGH | T1041 |
| `URLHAUS_HIT` | Observed URL matches URLhaus blocklist | CRITICAL | T1071 |

### Enrichment (real APIs)

- **AbuseIPDB** — IP reputation, report count, ISP, country
- **URLhaus** (abuse.ch) — malware URL blocklist
- **PhishTank** — verified phishing URLs
- **HIBP Pwned Passwords** — password breach check (k-anonymity)

### Response

- **PCAP saving** — every alert saves the exact packet to `captures/{id}.pcap`
- **Auto-block** — real `ipset` + `iptables` DROP rules for HIGH/CRITICAL sources
- **Manual block** — one-click from the UI
- **Time-limited** — blocks expire after 1 hour by default

### AI assistant (grounded, not hallucinating)

- `what was the last alert?` → returns real alert from agent state
- `is 45.148.10.5 malicious?` → calls AbuseIPDB, returns real verdict
- `check https://example.com` → calls URLhaus + PhishTank, returns real verdict
- `stats` → uptime, packet count, alert count, block count
- **Refuses to answer** anything it cannot ground in real data

---

## Requirements

- **Linux** — Ubuntu 22.04/24.04 or Debian 12 (tested)
- **Python 3.10+**
- **Root** — for packet capture (`CAP_NET_RAW`) and firewall (`CAP_NET_ADMIN`)
- **NetworkManager** — for WiFi scanning
- **iptables + ipset** — for blocking

macOS and Windows are **not supported**.

---

## Quick start

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y python3-scapy ipset iptables network-manager python3-pip
pip install aiohttp

# 2. Set free API keys (see below)
export URLHAUS_AUTH_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"

# 3. Find your interface
sudo python3 sentinel.py --list

# 4. Run the agent
sudo -E python3 sentinel.py --iface eth0 --autoblock

# 5. Open the UI
# http://127.0.0.1:8765
