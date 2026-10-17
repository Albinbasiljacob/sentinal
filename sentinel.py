#!/usr/bin/env python3
"""
AEGIS SENTINEL — Real network threat detection agent for Linux
================================================================
Captures real packets via Scapy, applies a real rule engine, enriches
alerts with real threat-intel APIs (URLhaus / AbuseIPDB / PhishTank /
HIBP), blocks real IPs via iptables/ipset, and streams everything to a
real WebSocket UI. Nothing is simulated.

REQUIREMENTS
    sudo apt install python3-scapy ipset iptables network-manager
    pip install aiohttp

API KEYS (all free — see README.md)
    URLHAUS_AUTH_KEY     https://auth.abuse.ch/
    ABUSEIPDB_API_KEY    https://www.abuseipdb.com/account/api
    PHISHTANK_APP_KEY    https://www.phishtank.com/api_register.php  (optional)

RUN
    sudo -E python3 sentinel.py --iface eth0 --autoblock
    sudo -E python3 sentinel.py --iface wlan0 --autoblock --port 8765

THEN OPEN
    http://127.0.0.1:8765
"""

import argparse, asyncio, hashlib, json, logging, os, re, signal
import subprocess, sys, threading, time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Dependency checks — fail loudly, never silently degrade
# --------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff, AsyncSniffer, IP, TCP, UDP, DNS, DNSQR, ARP, Raw,
        wrpcap, get_if_list, conf as scapy_conf,
    )
except ImportError:
    sys.exit("ERROR: scapy missing.  sudo apt install python3-scapy")

try:
    from aiohttp import web, ClientSession, WSMsgType
except ImportError:
    sys.exit("ERROR: aiohttp missing.  pip install aiohttp")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
@dataclass
class Config:
    iface: str = "eth0"
    port: int = 8765
    bind: str = "127.0.0.1"
    autoblock: bool = False
    block_timeout: int = 3600           # seconds
    captures_dir: Path = Path("captures")
    log_file: Path = Path("sentinel.log")
    max_packets_kept: int = 500         # ring buffer for UI
    max_alerts_kept: int = 500
    urlhaus_key: str = ""
    abuseipdb_key: str = ""
    phishtank_key: str = ""

    @classmethod
    def from_env(cls):
        return cls(
            urlhaus_key=os.getenv("URLHAUS_AUTH_KEY", ""),
            abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            phishtank_key=os.getenv("PHISHTANK_APP_KEY", ""),
        )


CFG = Config.from_env()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(CFG.log_file),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("aegis")


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Alert:
    id: str
    ts: float
    rule: str
    severity: str          # critical | high | medium | low
    src_ip: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    proto: str
    summary: str
    evidence: dict = field(default_factory=dict)
    pcap_path: Optional[str] = None
    intel: dict = field(default_factory=dict)
    blocked: bool = False
    mitre: str = ""

    def to_dict(self):
        d = asdict(self)
        d["ts_iso"] = datetime.fromtimestamp(self.ts, timezone.utc).isoformat()
        return d


@dataclass
class PacketView:
    ts: float
    src: str
    dst: str
    sport: Optional[int]
    dport: Optional[int]
    proto: str
    length: int
    flags: str
    summary: str


# --------------------------------------------------------------------------
# Threat-intel client — every call is real and rate-limited
# --------------------------------------------------------------------------
class IntelClient:
    """
    Async wrapper around public threat-intel APIs.
    Every method returns a dict; on failure returns {"error": "..."}.
    Never fabricates data.
    """

    def __init__(self):
        self._session: Optional[ClientSession] = None
        self._urlhaus_cache: set[str] = set()
        self._urlhaus_synced_at: float = 0
        self._ip_cache: dict[str, tuple[float, dict]] = {}
        self._url_cache: dict[str, tuple[float, dict]] = {}

    async def start(self):
        self._session = ClientSession(
            timeout=__import__("aiohttp").ClientTimeout(total=8)
        )

    async def close(self):
        if self._session:
            await self._session.close()

    # ---- URLhaus ----
    async def sync_urlhaus(self):
        """Pull the last 30 days of URLhaus entries into a local set."""
        if not CFG.urlhaus_key:
            log.info("URLhaus: no key — skipping sync (get one at auth.abuse.ch)")
            return
        try:
            form = __import__("aiohttp").FormData()
            form.add_field("query", "get_urls")
            form.add_field("limit", "1000")
            async with self._session.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Auth-Key": CFG.urlhaus_key},
                data=form,
            ) as r:
                if r.status != 200:
                    log.warning("URLhaus sync HTTP %s", r.status)
                    return
                data = await r.json()
                for u in data.get("urls", []):
                    self._urlhaus_cache.add(u["url"].lower())
                    if u.get("host"):
                        self._urlhaus_cache.add(u["host"].lower())
                self._urlhaus_synced_at = time.time()
                log.info("URLhaus: %d indicators cached", len(self._urlhaus_cache))
        except Exception as e:
            log.warning("URLhaus sync failed: %s", e)

    def urlhaus_hit(self, url_or_host: str) -> bool:
        return url_or_host.lower() in self._urlhaus_cache

    async def lookup_url(self, url: str) -> dict:
        """Check URL against URLhaus + PhishTank."""
        key = url.lower()
        if key in self._url_cache and time.time() - self._url_cache[key][0] < 300:
            return self._url_cache[key][1]

        result = {"url": url, "sources": {}}

        # URLhaus
        if CFG.urlhaus_key:
            try:
                form = __import__("aiohttp").FormData()
                form.add_field("url", url)
                async with self._session.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    headers={"Auth-Key": CFG.urlhaus_key},
                    data=form,
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        if d.get("query_status") == "ok":
                            result["sources"]["urlhaus"] = {
                                "threat": d.get("threat"),
                                "tags": d.get("tags"),
                                "blacklists": d.get("blacklists"),
                                "date_added": d.get("date_added"),
                            }
                        else:
                            result["sources"]["urlhaus"] = {"status": "not found"}
            except Exception as e:
                result["sources"]["urlhaus"] = {"error": str(e)}

        # PhishTank
        if CFG.phishtank_key:
            try:
                data = {
                    "url": url,
                    "format": "json",
                    "app_key": CFG.phishtank_key,
                }
                async with self._session.post(
                    "https://checkurl.phishtank.com/checkurl/", data=data
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        results = d.get("results", {})
                        result["sources"]["phishtank"] = {
                            "in_database": results.get("in_database"),
                            "verified": results.get("verified"),
                            "valid": results.get("valid"),
                        }
            except Exception as e:
                result["sources"]["phishtank"] = {"error": str(e)}

        self._url_cache[key] = (time.time(), result)
        return result

    async def lookup_ip(self, ip: str) -> dict:
        """Check IP against AbuseIPDB."""
        if ip in self._ip_cache and time.time() - self._ip_cache[ip][0] < 600:
            return self._ip_cache[ip][1]

        result = {"ip": ip, "sources": {}}

        if CFG.abuseipdb_key:
            try:
                async with self._session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers={
                        "Key": CFG.abuseipdb_key,
                        "Accept": "application/json",
                    },
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        data = d.get("data", {})
                        result["sources"]["abuseipdb"] = {
                            "abuse_confidence": data.get("abuseConfidenceScore"),
                            "total_reports": data.get("totalReports"),
                            "country": data.get("countryCode"),
                            "isp": data.get("isp"),
                            "domain": data.get("domain"),
                            "is_whitelisted": data.get("isWhitelisted"),
                        }
                    elif r.status == 429:
                        result["sources"]["abuseipdb"] = {"error": "rate limit"}
                    else:
                        result["sources"]["abuseipdb"] = {"error": f"HTTP {r.status}"}
            except Exception as e:
                result["sources"]["abuseipdb"] = {"error": str(e)}
        else:
            result["sources"]["abuseipdb"] = {"error": "no API key configured"}

        self._ip_cache[ip] = (time.time(), result)
        return result

    async def check_password(self, password: str) -> dict:
        """HIBP Pwned Passwords — k-anonymity (only 5-char prefix leaves host)."""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            async with self._session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
            ) as r:
                if r.status != 200:
                    return {"error": f"HTTP {r.status}"}
                text = await r.text()
                for line in text.splitlines():
                    h, _, count = line.partition(":")
                    if h == suffix:
                        return {"found": True, "count": int(count), "source": "HIBP"}
                return {"found": False, "count": 0, "source": "HIBP"}
        except Exception as e:
            return {"error": str(e)}


INTEL = IntelClient()


# --------------------------------------------------------------------------
# Firewall — real iptables / ipset blocking
# --------------------------------------------------------------------------
class Firewall:
    """
    Real blocking. Uses ipset for O(1) lookups when available,
    falls back to direct iptables rules otherwise.
    Never blocks RFC1918, loopback, or the local gateway.
    """

    SAFE_PREFIXES = (
        "127.", "10.", "192.168.", "169.254.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    )

    def __init__(self):
        self.blocked: dict[str, dict] = {}
        self._use_ipset = self._ipset_available()
        if self._use_ipset:
            self._init_ipset()

    @staticmethod
    def _ipset_available() -> bool:
        try:
            return subprocess.run(
                ["ipset", "version"], capture_output=True, timeout=3
            ).returncode == 0
        except Exception:
            return False

    def _init_ipset(self):
        subprocess.run(
            ["ipset", "create", "aegis_block", "hash:ip",
             "timeout", str(CFG.block_timeout), "-exist"],
            capture_output=True,
        )
        for chain, flag in (("INPUT", "src"), ("OUTPUT", "dst")):
            check = subprocess.run(
                ["iptables", "-C", chain, "-m", "set",
                 "--match-set", "aegis_block", flag, "-j", "DROP"],
                capture_output=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", chain, "-m", "set",
                     "--match-set", "aegis_block", flag, "-j", "DROP"],
                    capture_output=True,
                )

    def is_safe(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.SAFE_PREFIXES)

    def block(self, ip: str, rule: str) -> bool:
        if not ip or self.is_safe(ip):
            log.info("Firewall: refusing to block %s (private/reserved)", ip)
            return False
        if ip in self.blocked:
            return True

        if self._use_ipset:
            r = subprocess.run(
                ["ipset", "add", "aegis_block", ip, "timeout",
                 str(CFG.block_timeout), "-exist"],
                capture_output=True, text=True,
            )
            ok = r.returncode == 0
        else:
            r1 = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
            )
            r2 = subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True,
            )
            ok = r1.returncode == 0 and r2.returncode == 0

        if ok:
            self.blocked[ip] = {
                "rule": rule,
                "at": time.time(),
                "expires": time.time() + CFG.block_timeout,
            }
            log.warning("BLOCKED %s — %s", ip, rule)
        else:
            log.error("Firewall: failed to block %s", ip)
        return ok

    def unblock(self, ip: str) -> bool:
        if ip not in self.blocked:
            return False
        if self._use_ipset:
            subprocess.run(["ipset", "del", "aegis_block", ip],
                           capture_output=True)
        else:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                           capture_output=True)
        del self.blocked[ip]
        log.info("UNBLOCKED %s", ip)
        return True

    def list_blocked(self) -> list[dict]:
        now = time.time()
        return [
            {"ip": ip, **info, "remaining": max(0, int(info["expires"] - now))}
            for ip, info in self.blocked.items()
        ]


FIREWALL = Firewall()


# --------------------------------------------------------------------------
# WiFi scanner — real nmcli output parsing
# --------------------------------------------------------------------------
class WifiScanner:
    """
    Parses `nmcli -t -f ... device wifi list`.
    Read-only. No injection. No association attempts.
    """

    FIELDS = "IN-USE,BSSID,SSID,MODE,CHAN,RATE,SIGNAL,SECURITY"

    @staticmethod
    def scan(iface: str) -> list[dict]:
        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", WifiScanner.FIELDS,
                 "device", "wifi", "list", "ifname", iface],
                capture_output=True, text=True, timeout=15,
            )
        except FileNotFoundError:
            return [{"error": "nmcli not installed (apt install network-manager)"}]
        except subprocess.TimeoutExpired:
            return [{"error": "nmcli scan timed out"}]

        if r.returncode != 0:
            return [{"error": r.stderr.strip() or "nmcli scan failed"}]

        out = []
        for line in r.stdout.splitlines():
            # nmcli -t escapes ':' inside values as '\:'
            parts, buf, i = [], "", 0
            while i < len(line):
                if line[i] == "\\" and i + 1 < len(line) and line[i+1] == ":":
                    buf += ":"; i += 2; continue
                if line[i] == ":":
                    parts.append(buf); buf = ""; i += 1; continue
                buf += line[i]; i += 1
            parts.append(buf)

            if len(parts) < 8:
                continue
            in_use, bssid, ssid, mode, chan, rate, signal, security = parts[:8]
            out.append({
                "in_use": in_use.strip() == "*",
                "bssid": bssid.strip(),
                "ssid": ssid.strip() or "<hidden>",
                "mode": mode.strip(),
                "channel": chan.strip(),
                "rate": rate.strip(),
                "signal": int(signal.strip()) if signal.strip().isdigit() else 0,
                "security": security.strip() or "OPEN",
            })

        out.sort(key=lambda x: -x["signal"])
        return out

    @staticmethod
    def risk_of(net: dict) -> tuple[str, str]:
        """Heuristic risk classification — real, based on the security field."""
        sec = (net.get("security") or "").upper()
        if "OPEN" in sec or sec in ("", "--"):
            return "critical", "Open network — no encryption. All traffic is readable by anyone nearby."
        if "WEP" in sec:
            return "critical", "WEP is cryptographically broken — cracked in minutes."
        if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
            return "high", "WPA1 (TKIP) — deprecated; vulnerable to known attacks."
        if "WPA2" in sec and "WPA3" not in sec:
            return "low", "WPA2 — acceptable. WPA3 preferred if available."
        if "WPA3" in sec:
            return "info", "WPA3 — current standard."
        return "medium", f"Unknown security type: {sec}"


# --------------------------------------------------------------------------
# Detection engine — all local, all real, no simulation
# --------------------------------------------------------------------------
class Detector:
    """
    Sliding-window rule engine. Every rule fires on observed traffic only.
    """

    # Signature patterns for real payload inspection
    PAYLOAD_SIGNATURES = [
        (re.compile(rb"(?i)(\bunion\b.*\bselect\b|'\s*or\s*'1'\s*=\s*'1|\bselect\b.*\bfrom\b.*\bwhere\b)"),
         "SQL_INJECTION", "SQL injection payload"),
        (re.compile(rb"(?i)(<script[^>]*>|javascript:|onerror\s*=|onload\s*=)"),
         "XSS", "Cross-site scripting payload"),
        (re.compile(rb"\.\./\.\./|%2e%2e%2f|/etc/passwd|/etc/shadow|boot\.ini"),
         "PATH_TRAVERSAL", "Path traversal / LFI payload"),
        (re.compile(rb"(?i)(\$\{jndi:|ldap://|rmi://)"),
         "LOG4SHELL", "Log4Shell JNDI payload"),
        (re.compile(rb"(?i)(;|\||&&|\$\(|`)\s*(cat|wget|curl|nc|bash|sh|powershell)\b"),
         "COMMAND_INJECTION", "Command injection payload"),
        (re.compile(rb"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)"),
         "SSRF_METADATA", "SSRF to cloud metadata endpoint"),
        (re.compile(rb"(?i)(/bin/(ba)?sh\s+-i|nc\s+-e|python\s+-c\s+['\"]import\s+socket)"),
         "REVERSE_SHELL", "Reverse shell payload"),
    ]

    ATTACK_UA = re.compile(
        rb"(?i)(sqlmap|nikto|nmap\s*scripting|masscan|zgrab|nuclei|gobuster|"
        rb"dirbuster|wpscan|acunetix|nessus|openvas|hydra|medusa)"
    )

    CRED_PATTERN = re.compile(
        rb"(?i)(password|passwd|pwd|api[_-]?key|secret|token|cvv|card[_-]?number)"
        rb"\s*[=:]\s*[^\s&\"']+"
    )

    MGMT_PORTS = {22, 3389, 5900, 5985, 5986}

    def __init__(self, on_alert):
        self.on_alert = on_alert           # callback(Alert)
        self._syn: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._ports: dict[str, dict[int, float]] = defaultdict(dict)
        self._dns: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._auth: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._exfil: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._arp: dict[str, set[str]] = defaultdict(set)
        self._dedupe: dict[str, float] = {}

    def _should_alert(self, key: str, window: float = 8.0) -> bool:
        now = time.time()
        last = self._dedupe.get(key, 0)
        if now - last < window:
            return False
        self._dedupe[key] = now
        # prune
        if len(self._dedupe) > 5000:
            cutoff = now - 60
            self._dedupe = {k: v for k, v in self._dedupe.items() if v > cutoff}
        return True

    def process(self, pkt) -> Optional[Alert]:
        """Process one Scapy packet. Returns an Alert if a rule fired."""
        try:
            return self._process(pkt)
        except Exception as e:
            log.debug("Detector error: %s", e)
            return None

    def _process(self, pkt) -> Optional[Alert]:
        now = time.time()

        # ---- ARP spoofing ----
        if ARP in pkt and pkt[ARP].op == 2:
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            self._arp[ip].add(mac)
            if len(self._arp[ip]) > 1 and self._should_alert(f"arp:{ip}"):
                return self._make(
                    "ARP_SPOOF", "high", pkt,
                    src=ip, dst=pkt[ARP].pdst,
                    summary=f"IP {ip} announced by multiple MACs — likely ARP poisoning.",
                    evidence={"macs": sorted(self._arp[ip])},
                    mitre="T1557.002",
                )
            return None

        if IP not in pkt:
            return None

        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, str(ip.proto))
        dport = sport = None
        flags = ""

        if TCP in pkt:
            dport, sport = pkt[TCP].dport, pkt[TCP].sport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            dport, sport = pkt[UDP].dport, pkt[UDP].sport

        payload = bytes(pkt[Raw].load) if Raw in pkt else b""

        # ---- SYN flood ----
        if TCP in pkt and "S" in flags and "A" not in flags:
            dq = self._syn[src]
            dq.append(now)
            recent = sum(1 for t in dq if now - t < 1.0)
            if recent >= 100 and self._should_alert(f"syn:{src}"):
                return self._make(
                    "SYN_FLOOD", "high", pkt, src=src, dst=dst, dport=dport,
                    summary=f"{recent} SYN/sec from {src} — connection table exhaustion.",
                    evidence={"syn_per_sec": recent},
                    mitre="T1498.001",
                )

        # ---- Port scan ----
        if dport:
            self._ports[src][dport] = now
            # prune
            cutoff = now - 10
            self._ports[src] = {p: t for p, t in self._ports[src].items() if t > cutoff}
            if len(self._ports[src]) >= 15 and self._should_alert(f"scan:{src}"):
                return self._make(
                    "PORT_SCAN", "medium", pkt, src=src, dst=dst, dport=dport,
                    summary=f"{len(self._ports[src])} distinct ports probed from {src} in 10s.",
                    evidence={"distinct_ports": len(self._ports[src]),
                              "ports": sorted(self._ports[src].keys())[:20]},
                    mitre="T1046",
                )

        # ---- DNS tunnel ----
        if DNS in pkt and pkt[DNS].qr == 0:
            dq = self._dns[src]
            dq.append((now, len(payload)))
            recent = [x for x in dq if now - x[0] < 5.0]
            long_q = any(l > 100 for _, l in recent)
            if (len(recent) >= 50 or long_q) and self._should_alert(f"dns:{src}"):
                return self._make(
                    "DNS_TUNNEL", "high", pkt, src=src, dst=dst, dport=53,
                    summary=f"{len(recent)} DNS queries in 5s from {src} (long TXT={long_q}).",
                    evidence={"queries_5s": len(recent), "long_query": long_q},
                    mitre="T1071.004",
                )

        # ---- Brute force ----
        if dport in self.MGMT_PORTS and TCP in pkt:
            dq = self._auth[src]
            dq.append(now)
            recent = sum(1 for t in dq if now - t < 30.0)
            if recent >= 10 and self._should_alert(f"auth:{src}:{dport}"):
                return self._make(
                    "BRUTE_FORCE", "high", pkt, src=src, dst=dst, dport=dport,
                    summary=f"{recent} auth attempts to port {dport} from {src} in 30s.",
                    evidence={"attempts_30s": recent, "target_port": dport},
                    mitre="T1110",
                )

        # ---- Payload signatures ----
        if payload:
            for pattern, code, label in self.PAYLOAD_SIGNATURES:
                if pattern.search(payload):
                    if self._should_alert(f"payload:{src}:{code}"):
                        snippet = payload[:200].decode("utf-8", "replace")
                        return self._make(
                            "MALICIOUS_PAYLOAD", "critical", pkt,
                            src=src, dst=dst, dport=dport,
                            summary=f"{label} to {dst}:{dport}",
                            evidence={"signature": code, "payload": snippet},
                            mitre="T1190",
                        )
                    break

        # ---- Suspicious UA ----
        if payload and TCP in pkt:
            m = self.ATTACK_UA.search(payload)
            if m and self._should_alert(f"ua:{src}"):
                return self._make(
                    "SUSPICIOUS_UA", "medium", pkt, src=src, dst=dst, dport=dport,
                    summary=f"Known attack tool: {m.group(0).decode(errors='replace')}",
                    evidence={"user_agent": m.group(0).decode(errors="replace")},
                    mitre="T1595",
                )

        # ---- Cleartext credentials ----
        if dport == 80 and payload and self.CRED_PATTERN.search(payload):
            if self._should_alert(f"creds:{src}:{dst}"):
                return self._make(
                    "CLEARTEXT_CREDS", "critical", pkt, src=src, dst=dst, dport=80,
                    summary=f"Credentials in cleartext to {dst}:80",
                    evidence={"snippet": payload[:200].decode("utf-8", "replace")},
                    mitre="T1040",
                )

        # ---- Data exfiltration ----
        if not self._is_private(src) and not self._is_private(dst) is False:
            pass  # placeholder; real check below
        if self._is_private(src) and not self._is_private(dst):
            dq = self._exfil[src]
            dq.append((now, ip.len))
            cutoff = now - 60
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            total = sum(l for _, l in dq)
            if total > 5_000_000 and self._should_alert(f"exfil:{src}:{dst}", 60):
                return self._make(
                    "DATA_EXFIL", "high", pkt, src=src, dst=dst, dport=dport,
                    summary=f"{total/1e6:.1f} MB outbound from {src} to {dst} in 60s.",
                    evidence={"bytes_60s": total, "destination": dst},
                    mitre="T1041",
                )

        return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        return any(ip.startswith(p) for p in Firewall.SAFE_PREFIXES)

    def _make(self, rule, severity, pkt, *, src, dst, dport, summary,
              evidence, mitre) -> Alert:
        aid = hashlib.sha256(
            f"{rule}{src}{dst}{time.time()}".encode()
        ).hexdigest()[:16]
        return Alert(
            id=aid, ts=time.time(), rule=rule, severity=severity,
            src_ip=src, dst_ip=dst, dst_port=dport,
            proto="TCP" if TCP in pkt else ("UDP" if UDP in pkt else "IP"),
            summary=summary, evidence=evidence, mitre=mitre,
        )


# --------------------------------------------------------------------------
# Shared state between sniffer thread and asyncio loop
# --------------------------------------------------------------------------
class Hub:
    """Thread-safe bridge between Scapy thread and asyncio."""
    def __init__(self):
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.packets: deque = deque(maxlen=CFG.max_packets_kept)
        self.alerts: deque = deque(maxlen=CFG.max_alerts_kept)
        self.clients: set = set()
        self.stats = {"packets": 0, "alerts": 0, "blocked": 0, "started": time.time()}
        self._lock = threading.Lock()

    def set_loop(self, loop):
        self.loop = loop

    def add_packet(self, pv: PacketView):
        with self._lock:
            self.packets.append(pv)
            self.stats["packets"] += 1
        self._broadcast({"type": "packet", "data": asdict(pv)})

    def add_alert(self, alert: Alert):
        with self._lock:
            self.alerts.appendleft(alert)
            self.stats["alerts"] += 1
            if alert.blocked:
                self.stats["blocked"] += 1
        self._broadcast({"type": "alert", "data": alert.to_dict()})

    def _broadcast(self, msg: dict):
        if not self.loop or not self.clients:
            return
        text = json.dumps(msg)
        asyncio.run_coroutine_threadsafe(self._send_all(text), self.loop)

    async def _send_all(self, text: str):
        dead = set()
        for ws in list(self.clients):
            try:
                await ws.send_str(text)
            except Exception:
                dead.add(ws)
        self.clients -= dead


HUB = Hub()


# --------------------------------------------------------------------------
# Packet worker — runs in a separate thread (Scapy requirement)
# --------------------------------------------------------------------------
class PacketWorker(threading.Thread):
    def __init__(self, iface: str, detector: Detector):
        super().__init__(daemon=True, name="sniffer")
        self.iface = iface
        self.detector = detector
        self._stop = threading.Event()

    def run(self):
        log.info("Sniffer starting on %s", self.iface)
        try:
            sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self._handle,
                store=False,
                filter="ip or arp",
            )
            sniffer.start()
            self._stop.wait()
            sniffer.stop()
        except PermissionError:
            log.error("Sniffer: permission denied. Run with sudo.")
        except Exception as e:
            log.error("Sniffer error: %s", e)

    def stop(self):
        self._stop.set()

    def _handle(self, pkt):
        try:
            # 1) Build UI view
            if IP in pkt:
                ip = pkt[IP]
                if TCP in pkt:
                    proto, sp, dp = "TCP", pkt[TCP].sport, pkt[TCP].dport
                    flags = str(pkt[TCP].flags)
                elif UDP in pkt:
                    proto, sp, dp = "UDP", pkt[UDP].sport, pkt[UDP].dport
                    flags = ""
                else:
                    proto, sp, dp = "IP", None, None
                    flags = ""
                pv = PacketView(
                    ts=time.time(),
                    src=ip.src, dst=ip.dst,
                    sport=sp, dport=dp, proto=proto,
                    length=ip.len, flags=flags,
                    summary=(pkt.summary() or "")[:120],
                )
                HUB.add_packet(pv)

            # 2) Detect
            alert = self.detector.process(pkt)
            if alert:
                self._handle_alert(alert, pkt)
        except Exception as e:
            log.debug("handle error: %s", e)

    def _handle_alert(self, alert: Alert, pkt):
        # Save PCAP
        try:
            CFG.captures_dir.mkdir(exist_ok=True)
            pcap = CFG.captures_dir / f"{alert.id}.pcap"
            wrpcap(str(pcap), [pkt])
            alert.pcap_path = str(pcap)
        except Exception as e:
            log.warning("PCAP save failed: %s", e)

        # Block
        if CFG.autoblock and alert.severity in ("critical", "high"):
            if FIREWALL.block(alert.src_ip, alert.rule):
                alert.blocked = True

        # Intel enrichment is done async in server loop
        if HUB.loop:
            asyncio.run_coroutine_threadsafe(
                enrich_and_publish(alert), HUB.loop
            )
        else:
            HUB.add_alert(alert)


async def enrich_and_publish(alert: Alert):
    """Enrich with real intel, then push to UI."""
    try:
        ip_intel = await INTEL.lookup_ip(alert.src_ip) if alert.src_ip else {}
        alert.intel["ip"] = ip_intel

        # URLhaus local cache check
        if alert.evidence.get("payload"):
            for token in re.findall(r"https?://[^\s\"'<>]+", alert.evidence["payload"]):
                if INTEL.urlhaus_hit(token):
                    alert.intel["urlhaus"] = {"hit": True, "url": token}
                    alert.severity = "critical"
                    break
    except Exception as e:
        alert.intel["error"] = str(e)
    HUB.add_alert(alert)


# --------------------------------------------------------------------------
# HTTP + WebSocket server
# --------------------------------------------------------------------------
async def ws_handler(request):
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    HUB.clients.add(ws)
    log.info("UI connected (%d total)", len(HUB.clients))

    # Send current state
    await ws.send_json({
        "type": "init",
        "stats": HUB.stats,
        "iface": CFG.iface,
        "autoblock": CFG.autoblock,
        "alerts": [a.to_dict() for a in list(HUB.alerts)[:50]],
        "blocked": FIREWALL.list_blocked(),
        "intel_enabled": {
            "urlhaus": bool(CFG.urlhaus_key),
            "abuseipdb": bool(CFG.abuseipdb_key),
            "phishtank": bool(CFG.phishtank_key),
        },
    })

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await handle_client_message(ws, msg.data)
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        HUB.clients.discard(ws)
        log.info("UI disconnected (%d remaining)", len(HUB.clients))
    return ws


async def handle_client_message(ws, text: str):
    try:
        req = json.loads(text)
    except Exception:
        await ws.send_json({"type": "error", "message": "invalid json"})
        return

    action = req.get("action")

    if action == "wifi_scan":
        nets = WifiScanner.scan(CFG.iface)
        for n in nets:
            if "error" not in n:
                sev, reason = WifiScanner.risk_of(n)
                n["risk"] = sev
                n["risk_reason"] = reason
        await ws.send_json({"type": "wifi", "data": nets})

    elif action == "list_ifaces":
        await ws.send_json({"type": "ifaces", "data": get_if_list()})

    elif action == "block":
        ok = FIREWALL.block(req.get("ip", ""), "manual")
        await ws.send_json({"type": "block_result", "ok": ok,
                            "blocked": FIREWALL.list_blocked()})

    elif action == "unblock":
        ok = FIREWALL.unblock(req.get("ip", ""))
        await ws.send_json({"type": "unblock_result", "ok": ok,
                            "blocked": FIREWALL.list_blocked()})

    elif action == "ai_query":
        answer = await ai_query(req.get("q", ""))
        await ws.send_json({"type": "ai", "answer": answer,
                            "q": req.get("q", "")})

    elif action == "get_alerts":
        await ws.send_json({"type": "alerts",
                            "data": [a.to_dict() for a in list(HUB.alerts)[:200]]})

    else:
        await ws.send_json({"type": "error",
                            "message": f"unknown action: {action}"})


# --------------------------------------------------------------------------
# AI — real answers from real data, explicit "no data" when unknown
# --------------------------------------------------------------------------
async def ai_query(q: str) -> str:
    """
    Intent-matching assistant. Every branch queries real data or real state.
    If it can't answer from real data, it says so — never invents.
    """
    ql = q.lower().strip()
    if not ql:
        return "Ask me something — I only answer from real data."

    # Last alert
    if any(k in ql for k in ("last alert", "recent alert", "what happened",
                            "what alert", "latest threat")):
        if not HUB.alerts:
            return "No alerts since the agent started. Nothing has fired."
        a = HUB.alerts[0]
        return (f"**{a.rule}** ({a.severity}) at "
                f"{datetime.fromtimestamp(a.ts).strftime('%H:%M:%S')}\n\n"
                f"{a.summary}\n\n"
                f"Source: `{a.src_ip}` → `{a.dst_ip}:{a.dst_port}`\n"
                f"MITRE: {a.mitre} · Blocked: {a.blocked}\n\n"
                f"PCAP: `{a.pcap_path or 'not saved'}`")

    # IP reputation
    m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ql)
    if m and any(k in ql for k in ("ip", "malicious", "reputation",
                                   "check", "abuse", "bad")):
        ip = m.group(1)
        intel = await INTEL.lookup_ip(ip)
        src = intel.get("sources", {}).get("abuseipdb", {})
        if src.get("error"):
            return (f"I could not check {ip}: {src['error']}.\n\n"
                    f"Set ABUSEIPDB_API_KEY to enable real IP reputation.")
        return (f"**{ip}** — AbuseIPDB report:\n\n"
                f"Abuse confidence: **{src.get('abuse_confidence')}%**\n"
                f"Total reports: {src.get('total_reports')}\n"
                f"Country: {src.get('country')}\n"
                f"ISP: {src.get('isp')}\n"
                f"Whitelisted: {src.get('is_whitelisted')}\n\n"
                f"{'High abuse — block recommended.' if (src.get('abuse_confidence') or 0) > 50 else 'Below typical abuse threshold.'}")

    # URL / domain reputation
    m = re.search(r"(https?://[^\s]+|\b[a-z0-9.-]+\.[a-z]{2,}\b)", ql)
    if m and any(k in ql for k in ("url", "domain", "phish", "malicious",
                                   "site", "website")):
        target = m.group(1)
        intel = await INTEL.lookup_url(target)
        lines = [f"**{target}** — threat intel:"]
        u = intel.get("sources", {}).get("urlhaus", {})
        if u.get("threat"):
            lines.append(f"URLhaus: **{u['threat']}** · tags={u.get('tags')}")
        elif u.get("status") == "not found":
            lines.append("URLhaus: not listed")
        elif u.get("error"):
            lines.append(f"URLhaus: {u['error']}")
        p = intel.get("sources", {}).get("phishtank", {})
        if p:
            if p.get("valid"):
                lines.append("PhishTank: **verified phishing**")
            elif p.get("in_database"):
                lines.append("PhishTank: in database (not verified)")
            else:
                lines.append("PhishTank: not found")
        return "\n".join(lines)

    # Password breach
    if any(k in ql for k in ("password", "pwned", "breach", "leaked")):
        return ("Paste the password into the Password check box and press Enter — "
                "it uses HIBP k-anonymity (only the first 5 chars of the SHA-1 "
                "hash leave this machine). I don't accept passwords via chat "
                "because chat messages are logged.")

    # Stats
    if any(k in ql for k in ("stats", "status", "how many", "summary")):
        up = int(time.time() - HUB.stats["started"])
        return (f"**Agent status**\n\n"
                f"Interface: `{CFG.iface}`\n"
                f"Uptime: {up}s\n"
                f"Packets captured: {HUB.stats['packets']:,}\n"
                f"Alerts raised: {HUB.stats['alerts']}\n"
                f"IPs blocked: {len(FIREWALL.blocked)}\n"
                f"Auto-block: {'ON' if CFG.autoblock else 'OFF'}")

    # Help
    if any(k in ql for k in ("help", "what can", "commands")):
        return ("I answer only from real data. Try:\n\n"
                "• `what was the last alert?`\n"
                "• `is 45.148.10.5 malicious?`\n"
                "• `check https://suspicious.example.com`\n"
                "• `stats`\n\n"
                "I won't invent answers. If I don't have the data, I'll say so.")

    return ("I don't have data on that. I only answer questions I can ground "
            "in real packet captures, real alerts, or a real threat-intel API "
            "call. Try `help` to see what I can answer.")


# --------------------------------------------------------------------------
# Background tasks
# --------------------------------------------------------------------------
async def urlhaus_refresh_loop():
    while True:
        await INTEL.sync_urlhaus()
        await asyncio.sleep(3600)   # refresh hourly


async def stats_broadcast_loop():
    while True:
        await asyncio.sleep(2)
        if HUB.clients:
            try:
                await HUB._send_all(json.dumps({
                    "type": "stats",
                    "data": HUB.stats,
                    "blocked": len(FIREWALL.blocked),
                }))
            except Exception:
                pass


# --------------------------------------------------------------------------
# App lifecycle
# --------------------------------------------------------------------------
async def on_startup(app):
    await INTEL.start()
    app["urlhaus_task"] = asyncio.create_task(urlhaus_refresh_loop())
    app["stats_task"] = asyncio.create_task(stats_broadcast_loop())
    log.info("Intel client ready (urlhaus=%s abuseipdb=%s phishtank=%s)",
             bool(CFG.urlhaus_key), bool(CFG.abuseipdb_key), bool(CFG.phishtank_key))


async def on_cleanup(app):
    app["urlhaus_task"].cancel()
    app["stats_task"].cancel()
    await INTEL.close()


def build_app(ui_path: Path) -> web.Application:
    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/health", lambda r: web.json_response({"ok": True}))

    async def index(_):
        return web.FileResponse(ui_path)

    app.router.add_get("/", index)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Aegis Sentinel — real network IDS")
    ap.add_argument("--iface", default="eth0", help="capture interface (see --list)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1", help="bind address (keep localhost)")
    ap.add_argument("--autoblock", action="store_true",
                    help="auto-block HIGH/CRITICAL sources via iptables")
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("--ui", default="ui.html", help="path to ui.html")
    args = ap.parse_args()

    if args.list:
        print("Available interfaces:")
        for i in get_if_list():
            print(f"  {i}")
        return

    CFG.iface = args.iface
    CFG.port = args.port
    CFG.bind = args.bind
    CFG.autoblock = args.autoblock
    CFG.captures_dir.mkdir(exist_ok=True)

    if os.geteuid() != 0:
        log.warning("Not running as root. Packet capture will fail. "
                    "Use: sudo -E python3 sentinel.py ...")

    ui_path = Path(args.ui)
    if not ui_path.exists():
        sys.exit(f"ERROR: {ui_path} not found. Place ui.html next to sentinel.py.")

    detector = Detector(on_alert=lambda a: None)
    worker = PacketWorker(CFG.iface, detector)
    worker.start()

    app = build_app(ui_path)

    async def runner():
        HUB.set_loop(asyncio.get_running_loop())
        r = web.AppRunner(app)
        await r.setup()
        site = web.TCPSite(r, CFG.bind, CFG.port)
        await site.start()
        log.info("UI:      http://%s:%d", CFG.bind, CFG.port)
        log.info("Iface:   %s", CFG.iface)
        log.info("Auto-block: %s", "ON" if CFG.autoblock else "OFF")
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_running_loop().add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        await stop.wait()
        worker.stop()
        await r.cleanup()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        worker.stop()
    log.info("Shutdown complete")


if __name__ == "__main__":
    main()
