#!/usr/bin/env python3
"""AEGIS SENTINEL — real network IDS with LLM-backed AI analyst.

Captures real packets with Scapy, applies a rule engine, enriches with
threat-intel APIs, blocks offending IPs via iptables/ipset, streams live
state to a browser UI, and answers analyst questions via a real LLM.

Run:
    sudo -E python3 sentinel.py --iface eth0 --autoblock
Then open http://127.0.0.1:8765
"""

import argparse, asyncio, hashlib, json, logging, os, re
import signal, subprocess, sys, threading, time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from scapy.all import (
        sniff, AsyncSniffer, IP, TCP, UDP, DNS, ARP, Raw,
        wrpcap, get_if_list,
    )
except ImportError:
    sys.exit("ERROR: scapy missing.  pip install scapy")

try:
    from aiohttp import web, ClientSession, WSMsgType
except ImportError:
    sys.exit("ERROR: aiohttp missing.  pip install aiohttp")

from ai_engine import engine as ai_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("sentinel.log"), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("aegis")


# ===========================================================================
# Config
# ===========================================================================
@dataclass
class Config:
    iface: str = "eth0"
    port: int = 8765
    bind: str = "127.0.0.1"
    autoblock: bool = False
    block_timeout: int = 3600
    captures_dir: Path = Path("captures")
    max_packets_kept: int = 500
    max_alerts_kept: int = 500
    urlhaus_key: str = ""
    abuseipdb_key: str = ""
    phishtank_key: str = ""


CFG = Config(
    urlhaus_key=os.getenv("URLHAUS_AUTH_KEY", ""),
    abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY", ""),
    phishtank_key=os.getenv("PHISHTANK_APP_KEY", ""),
)


# ===========================================================================
# Data models
# ===========================================================================
@dataclass
class Alert:
    id: str
    ts: float
    rule: str
    severity: str
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


# ===========================================================================
# Intel client
# ===========================================================================
class IntelClient:
    def __init__(self):
        self._session: Optional[ClientSession] = None
        self._urlhaus_cache: set = set()
        self._ip_cache: dict = {}
        self._url_cache: dict = {}

    async def start(self):
        self._session = ClientSession(
            timeout=__import__("aiohttp").ClientTimeout(total=8)
        )

    async def close(self):
        if self._session:
            await self._session.close()

    async def sync_urlhaus(self):
        if not CFG.urlhaus_key:
            log.info("URLhaus: no key — skipping sync")
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
                log.info("URLhaus: %d indicators cached", len(self._urlhaus_cache))
        except Exception as e:
            log.warning("URLhaus sync failed: %s", e)

    def urlhaus_hit(self, token: str) -> bool:
        return token.lower() in self._urlhaus_cache

    async def lookup_ip(self, ip: str) -> dict:
        if ip in self._ip_cache and time.time() - self._ip_cache[ip][0] < 600:
            return self._ip_cache[ip][1]
        result = {"ip": ip, "sources": {}}
        if CFG.abuseipdb_key:
            try:
                async with self._session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers={"Key": CFG.abuseipdb_key, "Accept": "application/json"},
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        data = d.get("data", {})
                        result["sources"]["abuseipdb"] = {
                            "abuse_confidence": data.get("abuseConfidenceScore"),
                            "total_reports": data.get("totalReports"),
                            "country": data.get("countryCode"),
                            "isp": data.get("isp"),
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

    async def lookup_url(self, url: str) -> dict:
        key = url.lower()
        if key in self._url_cache and time.time() - self._url_cache[key][0] < 300:
            return self._url_cache[key][1]
        result = {"url": url, "sources": {}}
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
                                "date_added": d.get("date_added"),
                            }
                        else:
                            result["sources"]["urlhaus"] = {"status": "not found"}
            except Exception as e:
                result["sources"]["urlhaus"] = {"error": str(e)}
        if CFG.phishtank_key:
            try:
                async with self._session.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data={"url": url, "format": "json",
                          "app_key": CFG.phishtank_key},
                ) as r:
                    if r.status == 200:
                        d = await r.json()
                        res = d.get("results", {})
                        result["sources"]["phishtank"] = {
                            "in_database": res.get("in_database"),
                            "verified": res.get("verified"),
                            "valid": res.get("valid"),
                        }
            except Exception as e:
                result["sources"]["phishtank"] = {"error": str(e)}
        self._url_cache[key] = (time.time(), result)
        return result


INTEL = IntelClient()


# ===========================================================================
# Firewall
# ===========================================================================
class Firewall:
    SAFE_PREFIXES = (
        "127.", "10.", "192.168.", "169.254.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    )

    def __init__(self):
        self.blocked: dict = {}
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
            self.blocked[ip] = {"rule": rule, "at": time.time(),
                                "expires": time.time() + CFG.block_timeout}
            log.warning("BLOCKED %s — %s", ip, rule)
        return ok

    def unblock(self, ip: str) -> bool:
        if ip not in self.blocked:
            return False
        if self._use_ipset:
            subprocess.run(["ipset", "del", "aegis_block", ip], capture_output=True)
        else:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True)
        del self.blocked[ip]
        log.info("UNBLOCKED %s", ip)
        return True

    def list_blocked(self) -> list:
        now = time.time()
        return [
            {"ip": ip, **info, "remaining": max(0, int(info["expires"] - now))}
            for ip, info in self.blocked.items()
        ]


FIREWALL = Firewall()


# ===========================================================================
# WiFi scanner
# ===========================================================================
class WifiScanner:
    FIELDS = "IN-USE,BSSID,SSID,MODE,CHAN,RATE,SIGNAL,SECURITY"

    @staticmethod
    def scan(iface: str) -> list:
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
    def risk_of(net: dict) -> tuple:
        sec = (net.get("security") or "").upper()
        if "OPEN" in sec or sec in ("", "--"):
            return "critical", "Open network — no encryption."
        if "WEP" in sec:
            return "critical", "WEP is cryptographically broken."
        if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
            return "high", "WPA1 (TKIP) — deprecated."
        if "WPA2" in sec and "WPA3" not in sec:
            return "low", "WPA2 — acceptable."
        if "WPA3" in sec:
            return "info", "WPA3 — current standard."
        return "medium", f"Unknown: {sec}"


# ===========================================================================
# Detector
# ===========================================================================
class Detector:
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
         "SSRF_METADATA", "SSRF to cloud metadata"),
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

    def __init__(self):
        self._syn = defaultdict(lambda: deque(maxlen=500))
        self._ports = defaultdict(dict)
        self._dns = defaultdict(lambda: deque(maxlen=200))
        self._auth = defaultdict(lambda: deque(maxlen=100))
        self._exfil = defaultdict(lambda: deque(maxlen=200))
        self._arp = defaultdict(set)
        self._dedupe = {}

    def _should_alert(self, key, window=8.0):
        now = time.time()
        last = self._dedupe.get(key, 0)
        if now - last < window:
            return False
        self._dedupe[key] = now
        if len(self._dedupe) > 5000:
            cutoff = now - 60
            self._dedupe = {k: v for k, v in self._dedupe.items() if v > cutoff}
        return True

    def process(self, pkt):
        try:
            return self._process(pkt)
        except Exception as e:
            log.debug("Detector error: %s", e)
            return None

    def _process(self, pkt):
        now = time.time()

        if ARP in pkt and pkt[ARP].op == 2:
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            self._arp[ip].add(mac)
            if len(self._arp[ip]) > 1 and self._should_alert(f"arp:{ip}"):
                return self._make("ARP_SPOOF", "high", pkt, src=ip, dst=pkt[ARP].pdst,
                                  dport=None,
                                  summary=f"IP {ip} announced by multiple MACs.",
                                  evidence={"macs": sorted(self._arp[ip])},
                                  mitre="T1557.002")
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

        # SYN flood
        if TCP in pkt and "S" in flags and "A" not in flags:
            dq = self._syn[src]; dq.append(now)
            recent = sum(1 for t in dq if now - t < 1.0)
            if recent >= 100 and self._should_alert(f"syn:{src}"):
                return self._make("SYN_FLOOD", "high", pkt, src=src, dst=dst,
                                  dport=dport,
                                  summary=f"{recent} SYN/sec from {src}.",
                                  evidence={"syn_per_sec": recent},
                                  mitre="T1498.001")

        # Port scan
        if dport:
            self._ports[src][dport] = now
            cutoff = now - 10
            self._ports[src] = {p: t for p, t in self._ports[src].items() if t > cutoff}
            if len(self._ports[src]) >= 15 and self._should_alert(f"scan:{src}"):
                return self._make("PORT_SCAN", "medium", pkt, src=src, dst=dst,
                                  dport=dport,
                                  summary=f"{len(self._ports[src])} distinct ports from {src} in 10s.",
                                  evidence={"distinct_ports": len(self._ports[src]),
                                            "ports": sorted(self._ports[src].keys())[:20]},
                                  mitre="T1046")

        # DNS tunnel
        if DNS in pkt and pkt[DNS].qr == 0:
            dq = self._dns[src]
            dq.append((now, len(payload)))
            recent = [x for x in dq if now - x[0] < 5.0]
            long_q = any(l > 100 for _, l in recent)
            if (len(recent) >= 50 or long_q) and self._should_alert(f"dns:{src}"):
                return self._make("DNS_TUNNEL", "high", pkt, src=src, dst=dst, dport=53,
                                  summary=f"{len(recent)} DNS queries in 5s from {src}.",
                                  evidence={"queries_5s": len(recent), "long_query": long_q},
                                  mitre="T1071.004")

        # Brute force
        if dport in self.MGMT_PORTS and TCP in pkt:
            dq = self._auth[src]; dq.append(now)
            recent = sum(1 for t in dq if now - t < 30.0)
            if recent >= 10 and self._should_alert(f"auth:{src}:{dport}"):
                return self._make("BRUTE_FORCE", "high", pkt, src=src, dst=dst,
                                  dport=dport,
                                  summary=f"{recent} auth attempts to {dport} from {src} in 30s.",
                                  evidence={"attempts_30s": recent},
                                  mitre="T1110")

        # Payload signatures
        if payload:
            for pattern, code, label in self.PAYLOAD_SIGNATURES:
                if pattern.search(payload):
                    if self._should_alert(f"payload:{src}:{code}"):
                        return self._make(
                            "MALICIOUS_PAYLOAD", "critical", pkt,
                            src=src, dst=dst, dport=dport,
                            summary=f"{label} to {dst}:{dport}",
                            evidence={"signature": code,
                                      "payload": payload[:200].decode("utf-8", "replace")},
                            mitre="T1190")
                    break

        # Suspicious UA
        if payload and TCP in pkt:
            m = self.ATTACK_UA.search(payload)
            if m and self._should_alert(f"ua:{src}"):
                return self._make("SUSPICIOUS_UA", "medium", pkt, src=src, dst=dst,
                                  dport=dport,
                                  summary=f"Attack tool: {m.group(0).decode(errors='replace')}",
                                  evidence={"user_agent": m.group(0).decode(errors="replace")},
                                  mitre="T1595")

        # Cleartext credentials
        if dport == 80 and payload and self.CRED_PATTERN.search(payload):
            if self._should_alert(f"creds:{src}:{dst}"):
                return self._make("CLEARTEXT_CREDS", "critical", pkt, src=src, dst=dst,
                                  dport=80,
                                  summary=f"Credentials in cleartext to {dst}:80",
                                  evidence={"snippet": payload[:200].decode("utf-8", "replace")},
                                  mitre="T1040")

        # Data exfiltration
        if self._is_private(src) and not self._is_private(dst):
            dq = self._exfil[src]
            dq.append((now, ip.len))
            cutoff = now - 60
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            total = sum(l for _, l in dq)
            if total > 5_000_000 and self._should_alert(f"exfil:{src}:{dst}", 60):
                return self._make("DATA_EXFIL", "high", pkt, src=src, dst=dst,
                                  dport=dport,
                                  summary=f"{total/1e6:.1f} MB outbound from {src} to {dst} in 60s.",
                                  evidence={"bytes_60s": total, "destination": dst},
                                  mitre="T1041")

        return None

    @staticmethod
    def _is_private(ip):
        return any(ip.startswith(p) for p in Firewall.SAFE_PREFIXES)

    def _make(self, rule, severity, pkt, *, src, dst, dport, summary, evidence, mitre):
        aid = hashlib.sha256(f"{rule}{src}{dst}{time.time()}".encode()).hexdigest()[:16]
        return Alert(
            id=aid, ts=time.time(), rule=rule, severity=severity,
            src_ip=src, dst_ip=dst, dst_port=dport,
            proto="TCP" if TCP in pkt else ("UDP" if UDP in pkt else "IP"),
            summary=summary, evidence=evidence, mitre=mitre,
        )


# ===========================================================================
# Hub (thread-safe bridge between Scapy thread and asyncio)
# ===========================================================================
class Hub:
    def __init__(self):
        self.loop = None
        self.packets = deque(maxlen=CFG.max_packets_kept)
        self.alerts = deque(maxlen=CFG.max_alerts_kept)
        self.clients = set()
        self.stats = {"packets": 0, "alerts": 0, "crit": 0, "blocked": 0,
                      "started": time.time()}
        self._lock = threading.Lock()

    def set_loop(self, loop):
        self.loop = loop

    def add_packet(self, pv):
        with self._lock:
            self.packets.append(pv)
            self.stats["packets"] += 1
        self._broadcast({"type": "packet", "data": asdict(pv)})

    def add_alert(self, alert):
        with self._lock:
            self.alerts.appendleft(alert)
            self.stats["alerts"] += 1
            if alert.severity == "critical":
                self.stats["crit"] += 1
            if alert.blocked:
                self.stats["blocked"] += 1
        self._broadcast({"type": "alert", "data": alert.to_dict()})

    def _broadcast(self, msg):
        if not self.loop or not self.clients:
            return
        text = json.dumps(msg)
        asyncio.run_coroutine_threadsafe(self._send_all(text), self.loop)

    async def _send_all(self, text):
        dead = set()
        for ws in list(self.clients):
            try:
                await ws.send_str(text)
            except Exception:
                dead.add(ws)
        self.clients -= dead


HUB = Hub()


# ===========================================================================
# Packet worker
# ===========================================================================
class PacketWorker(threading.Thread):
    def __init__(self, iface, detector):
        super().__init__(daemon=True, name="sniffer")
        self.iface = iface
        self.detector = detector
        self._stop = threading.Event()

    def run(self):
        log.info("Sniffer starting on %s", self.iface)
        try:
            sniffer = AsyncSniffer(
                iface=self.iface, prn=self._handle, store=False,
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
                    ts=time.time(), src=ip.src, dst=ip.dst,
                    sport=sp, dport=dp, proto=proto,
                    length=ip.len, flags=flags,
                    summary=(pkt.summary() or "")[:120],
                )
                HUB.add_packet(pv)

            alert = self.detector.process(pkt)
            if alert:
                self._handle_alert(alert, pkt)
        except Exception as e:
            log.debug("handle error: %s", e)

    def _handle_alert(self, alert, pkt):
        try:
            CFG.captures_dir.mkdir(exist_ok=True)
            pcap = CFG.captures_dir / f"{alert.id}.pcap"
            wrpcap(str(pcap), [pkt])
            alert.pcap_path = str(pcap)
        except Exception as e:
            log.warning("PCAP save failed: %s", e)

        if CFG.autoblock and alert.severity in ("critical", "high"):
            if FIREWALL.block(alert.src_ip, alert.rule):
                alert.blocked = True

        if HUB.loop:
            asyncio.run_coroutine_threadsafe(enrich_and_publish(alert), HUB.loop)
        else:
            HUB.add_alert(alert)


async def enrich_and_publish(alert):
    try:
        ip_intel = await INTEL.lookup_ip(alert.src_ip) if alert.src_ip else {}
        alert.intel["ip"] = ip_intel
        if alert.evidence.get("payload"):
            for token in re.findall(r"https?://[^\s\"'<>]+", alert.evidence["payload"]):
                if INTEL.urlhaus_hit(token):
                    alert.intel["urlhaus"] = {"hit": True, "url": token}
                    alert.severity = "critical"
                    break
    except Exception as e:
        alert.intel["error"] = str(e)
    HUB.add_alert(alert)


# ===========================================================================
# WebSocket server + HTTP
# ===========================================================================
async def ws_handler(request):
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    HUB.clients.add(ws)
    log.info("UI connected (%d total)", len(HUB.clients))

    await ws.send_json({
        "type": "init",
        "stats": HUB.stats,
        "iface": CFG.iface,
        "autoblock": CFG.autoblock,
        "alerts": [a.to_dict() for a in list(HUB.alerts)[:50]],
        "blocked": FIREWALL.list_blocked(),
        "ai_ready": ai_engine.ready,
        "ai_model": ai_engine.model,
        "ai_backend": ai_engine.backend,
        "ai_error": ai_engine.error,
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


async def handle_client_message(ws, text):
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
        await ws.send_json({"type": "blocked_result", "ok": ok,
                            "blocked": FIREWALL.list_blocked()})

    elif action == "unblock":
        ok = FIREWALL.unblock(req.get("ip", ""))
        await ws.send_json({"type": "unblock_result", "ok": ok,
                            "blocked": FIREWALL.list_blocked()})

    elif action == "get_alerts":
        await ws.send_json({"type": "alerts",
                            "data": [a.to_dict() for a in list(HUB.alerts)[:200]]})

    elif action == "ai_query":
        q = req.get("q", "").strip()
        if not q:
            await ws.send_json({"type": "ai_error", "message": "Empty question"})
            return

        if not ai_engine.ready:
            await ws.send_json({
                "type": "ai_error",
                "message": ai_engine.error or "AI engine not ready",
            })
            return

        # Pre-fetch IP intel if question names one
        intel_snapshot = {}
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", q)
        if ip_match:
            intel_snapshot = await INTEL.lookup_ip(ip_match.group(1))

        await ws.send_json({"type": "ai_start", "q": q})

        try:
            async for token in ai_engine.stream_answer(
                question=q,
                alerts=list(HUB.alerts)[:20],
                packets=list(HUB.packets)[:30],
                blocked_ips=[b["ip"] for b in FIREWALL.list_blocked()],
                iface=CFG.iface,
                autoblock=CFG.autoblock,
                intel_snapshot=intel_snapshot,
            ):
                try:
                    await ws.send_json({"type": "ai_token", "token": token})
                except (ConnectionError, ConnectionResetError):
                    log.info("Client disconnected mid-stream")
                    return
            await ws.send_json({"type": "ai_done"})
        except Exception as e:
            log.error("AI stream error: %s", e)
            try:
                await ws.send_json({"type": "ai_error", "message": str(e)})
            except Exception:
                pass

    else:
        await ws.send_json({"type": "error", "message": f"unknown action: {action}"})


# ===========================================================================
# Background loops
# ===========================================================================
async def urlhaus_refresh_loop():
    while True:
        await INTEL.sync_urlhaus()
        await asyncio.sleep(3600)


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


# ===========================================================================
# App lifecycle
# ===========================================================================
async def on_startup(app):
    await INTEL.start()
    await ai_engine.start()
    app["urlhaus_task"] = asyncio.create_task(urlhaus_refresh_loop())
    app["stats_task"] = asyncio.create_task(stats_broadcast_loop())
    log.info("Intel: urlhaus=%s abuseipdb=%s phishtank=%s",
             bool(CFG.urlhaus_key), bool(CFG.abuseipdb_key), bool(CFG.phishtank_key))
    log.info("AI: %s (%s)", "ready" if ai_engine.ready else "not ready",
             ai_engine.error or ai_engine.model)


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


# ===========================================================================
# Main
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Aegis Sentinel — real network IDS")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--autoblock", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--ui", default="ui.html")
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
        log.warning("Not running as root. Packet capture will fail. Use: sudo -E python3 sentinel.py ...")

    ui_path = Path(args.ui)
    if not ui_path.exists():
        sys.exit(f"ERROR: {ui_path} not found")

    detector = Detector()
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
