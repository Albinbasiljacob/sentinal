#!/usr/bin/env python3
"""AEGIS AI ENGINE — LLM-backed threat analyst for Aegis Sentinel.

Backends (switch via AEGIS_AI_BACKEND env var):
  ollama  (default)  →  http://localhost:11434/v1   free, private, no API key
  openai            →  any OpenAI-compatible endpoint

Env vars:
  AEGIS_AI_BACKEND    ollama | openai
  AEGIS_AI_MODEL      llama3.1:8b  |  dolphin-llama3  |  gpt-4o-mini  | ...
  AEGIS_AI_BASE_URL   override base URL
  OPENAI_API_KEY      required only if backend=openai

The LLM never sees raw packets. It receives a sanitised context bundle:
  - truncated payload previews (credentials redacted)
  - alert metadata (rule, severity, src/dst, MITRE)
  - intel verdicts (AbuseIPDB, URLhaus, PhishTank)
  - agent state (iface, autoblock, blocked IPs)

System prompt forbids fabrication. The model must say
"I don't have data on that" when context lacks the answer.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

log = logging.getLogger("aegis.ai")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BACKEND = os.getenv("AEGIS_AI_BACKEND", "ollama").lower()
MODEL = os.getenv("AEGIS_AI_MODEL", "llama3.1:8b")

if BACKEND == "ollama":
    BASE_URL = os.getenv("AEGIS_AI_BASE_URL", "http://localhost:11434/v1")
    API_KEY = "ollama"
else:
    BASE_URL = os.getenv("AEGIS_AI_BASE_URL", "https://api.openai.com/v1")
    API_KEY = os.getenv("OPENAI_API_KEY", "")

MAX_ALERTS_IN_CONTEXT = 10
MAX_PACKETS_IN_CONTEXT = 15
MAX_PAYLOAD_PREVIEW = 200

# Credentials are replaced before anything is sent to the LLM.
CRED_REDACT = re.compile(
    r"(password|passwd|pwd|api[_-]?key|secret|token|cvv|card[_-]?number)"
    r"(\s*[=:]\s*)([^\s&\"']+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# System prompt — strict, grounded, refuses to guess
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are AEGIS, the threat analyst for a real network intrusion-detection system.

You receive a context block containing REAL data from the running agent:
- alerts that fired on actual captured packets
- packet summaries from the live ring buffer
- threat-intel verdicts from AbuseIPDB, URLhaus, PhishTank

YOUR JOB
Explain what is happening in the network and advise the operator on next steps.

RULES — follow exactly.

1. GROUNDING. Cite only data present in the context. If the answer is not in the context,
   reply: "I don't have data on that in the current context." Do NOT invent IPs, CVEs,
   malware family names, threat-actor attribution, or timestamps.

2. FALSE POSITIVES FIRST. Before calling anything an attack, name the most likely benign
   explanation: an authorized scanner, monitoring agent, backup job, or misconfiguration.
   Only conclude "likely malicious" when evidence supports it.

3. ABUSEIPDB SIGNAL. When an alert has an AbuseIPDB score, use these bands:
   - under 25%: "likely benign" — do not recommend blocking on this alone
   - 25–74%:   "suspicious, verify before blocking"
   - 75%+:     "high confidence malicious" — blocking justified

4. PAYLOAD. If the alert has a payload preview, describe what the signature means
   (SQL injection attempt, path traversal, Log4Shell, etc.) in plain language. Never write
   exploit code. Never explain how to weaponize it.

5. SPECIFIC IP QUERIES. If the question names an IP and the context does not contain intel
   for that IP, say: "No intel for that IP in the current context. Run a lookup in the
   UI first."

6. AGENT STATE. When asked for status or summary, use only the numbers present in the
   context. Do not estimate. If a number is not shown, say so.

7. BREVITY. Two to four short paragraphs is the target unless the user asks for depth.

8. SCOPE. If the question is off-topic (weather, sports, general chit-chat), reply:
   "I only answer questions grounded in the current agent context (alerts, packets,
   intel). Ask about an alert, a source IP, or the agent state."

9. DEFENDER ONLY. You are advising a network defender. Never suggest scanning, exploiting,
   or attacking systems the operator does not own.
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sanitize_payload(text: str) -> str:
    if not text:
        return ""
    text = CRED_REDACT.sub(r"\1\2[REDACTED]", text)
    text = text.replace("\n", " ").replace("\r", " ")
    return text[:MAX_PAYLOAD_PREVIEW]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _get(obj, key, default=None):
    """Works with dataclasses, dicts, or objects."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------
def build_context(
    question: str,
    alerts: list,
    packets: list,
    blocked_ips: list,
    iface: str,
    autoblock: bool,
    intel_snapshot: Optional[dict] = None,
) -> str:
    lines = ["=== AGENT STATE ==="]
    lines.append(f"Interface: {iface}")
    lines.append(f"Auto-block: {'ON' if autoblock else 'OFF'}")
    lines.append(f"Blocked IPs: {', '.join(blocked_ips) if blocked_ips else 'none'}")
    lines.append(f"Packets captured (ring buffer): {len(packets)}")
    lines.append("")

    shown_alerts = alerts[:MAX_ALERTS_IN_CONTEXT]
    lines.append(f"=== RECENT ALERTS (last {len(shown_alerts)}) ===")
    if not shown_alerts:
        lines.append("(no alerts since agent started)")
    else:
        for a in shown_alerts:
            ts = _get(a, "ts", time.time())
            rule = _get(a, "rule", "?")
            sev = _get(a, "severity", "?")
            src = _get(a, "src_ip") or "?"
            dst = _get(a, "dst_ip") or "?"
            port = _get(a, "dst_port") or "?"
            proto = _get(a, "proto", "?")
            mitre = _get(a, "mitre", "")
            summary = _get(a, "summary", "")
            blocked = _get(a, "blocked", False)

            line = (f"[{str(sev).upper()}] {rule} | {_iso(ts)} | "
                    f"{src} -> {dst}:{port} ({proto})")
            if mitre:
                line += f" | MITRE {mitre}"

            intel = _get(a, "intel", {}) or {}
            ip_intel = (intel.get("ip") or {}).get("sources", {}).get("abuseipdb", {})
            if ip_intel and not ip_intel.get("error"):
                ac = ip_intel.get("abuse_confidence")
                tr = ip_intel.get("total_reports")
                if ac is not None:
                    line += f" | AbuseIPDB {ac}%"
                    if tr is not None:
                        line += f" ({tr} reports"
                        cc = ip_intel.get("country")
                        if cc:
                            line += f", {cc}"
                        line += ")"

            evidence = _get(a, "evidence", {}) or {}
            if isinstance(evidence, dict):
                payload = evidence.get("payload") or evidence.get("snippet") or ""
                if payload:
                    line += f"\n  payload: {_sanitize_payload(payload)}"

            if summary:
                line += f"\n  summary: {summary}"
            if blocked:
                line += "\n  status: BLOCKED"

            lines.append(line)
    lines.append("")

    shown_packets = packets[:MAX_PACKETS_IN_CONTEXT]
    lines.append(f"=== RECENT PACKETS (last {len(shown_packets)}) ===")
    if not shown_packets:
        lines.append("(no packets captured yet)")
    else:
        for p in shown_packets:
            ts = _get(p, "ts", time.time())
            src = _get(p, "src", "?")
            dst = _get(p, "dst", "?")
            proto = _get(p, "proto", "?")
            sp = _get(p, "sport") or "*"
            dp = _get(p, "dport") or "*"
            ln = _get(p, "length", 0)
            fl = _get(p, "flags", "") or "-"
            t = datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")
            lines.append(f"{t} {proto} {src}:{sp} -> {dst}:{dp} len={ln} flags={fl}")
    lines.append("")

    if intel_snapshot:
        lines.append("=== INTEL FOR QUESTION TARGET ===")
        try:
            import json as _json
            lines.append(_json.dumps(intel_snapshot, indent=2)[:1500])
        except Exception:
            lines.append(str(intel_snapshot)[:1500])
        lines.append("")

    lines.append("=== QUESTION ===")
    lines.append(question)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class AIEngine:
    def __init__(self):
        self.client = None
        self.ready = False
        self.error: Optional[str] = None
        self.model = MODEL
        self.backend = BACKEND

    async def start(self):
        try:
            from openai import AsyncOpenAI
        except ImportError:
            self.error = "openai package missing — pip install openai"
            log.error(self.error)
            return

        try:
            self.client = AsyncOpenAI(base_url=BASE_URL, api_key=API_KEY)
            # Smoke test — verify the model is present and responsive
            r = await self.client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": "Reply with one word: ready"}],
                max_tokens=5,
                temperature=0,
            )
            _ = (r.choices[0].message.content or "").strip()
            self.ready = True
            log.info("AI engine ready — %s via %s", MODEL, BASE_URL)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
            self.ready = False
            log.error("AI engine failed to start: %s", e)
            log.error("  If using Ollama: run `ollama serve`, then `ollama pull %s`", MODEL)
            log.error("  If using OpenAI: set OPENAI_API_KEY and AEGIS_AI_BACKEND=openai")

    async def stream_answer(
        self,
        question: str,
        alerts: list,
        packets: list,
        blocked_ips: list,
        iface: str,
        autoblock: bool,
        intel_snapshot: Optional[dict] = None,
    ) -> AsyncIterator[str]:
        if not self.ready or self.client is None:
            raise RuntimeError(self.error or "AI engine not initialised")

        context = build_context(
            question=question,
            alerts=alerts,
            packets=packets,
            blocked_ips=blocked_ips,
            iface=iface,
            autoblock=autoblock,
            intel_snapshot=intel_snapshot,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": context},
        ]

        stream = await self.client.chat.completions.create(
            model=MODEL,
            messages=messages,
            stream=True,
            temperature=0.1,
            max_tokens=700,
        )

        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            content = getattr(delta, "content", None)
            if content:
                yield content


# Singleton
engine = AIEngine()
