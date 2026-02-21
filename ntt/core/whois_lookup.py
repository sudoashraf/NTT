"""
Whois lookup — domain / IP ownership information.

Uses Python's ``socket`` whois trick (port 43) for a zero-dependency approach,
with automatic server selection for common TLDs and IP ranges.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional

from ntt.core.utils import Status, TestResult


# ── Well-known whois servers ──────────────────────────────────────────────────

_TLD_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "edu": "whois.educause.edu",
    "gov": "whois.dotgov.gov",
    "uk":  "whois.nic.uk",
    "de":  "whois.denic.de",
    "fr":  "whois.nic.fr",
    "au":  "whois.auda.org.au",
    "in":  "whois.registry.in",
    "jp":  "whois.jprs.jp",
    "cn":  "whois.cnnic.cn",
    "ru":  "whois.tcinet.ru",
}

_IP_WHOIS_SERVER = "whois.arin.net"
_DEFAULT_WHOIS_SERVER = "whois.iana.org"


def _pick_server(target: str) -> str:
    """Choose the best whois server for *target*."""
    # If it's an IP, use ARIN as the starting point (they redirect)
    try:
        ipaddress.ip_address(target)
        return _IP_WHOIS_SERVER
    except ValueError:
        pass

    # Domain — look up TLD
    parts = target.rstrip(".").lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in _TLD_SERVERS:
            return _TLD_SERVERS[tld]

    return _DEFAULT_WHOIS_SERVER


def _raw_whois(target: str, server: str, port: int = 43, timeout: int = 10) -> str:
    """Perform a raw TCP whois query and return the text response."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(f"{target}\r\n".encode())
            chunks: list[bytes] = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as exc:
        return f"(error querying {server}: {exc})"


def _follow_referral(raw: str, target: str) -> Optional[str]:
    """If the response contains a 'Registrar WHOIS Server' or 'refer', follow it."""
    for pattern in (
        r"Registrar WHOIS Server:\s*(\S+)",
        r"refer:\s*(\S+)",
        r"ReferralServer:\s*whois://(\S+)",
    ):
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            referral = m.group(1).strip().rstrip("/")
            if referral and referral != "whois.arin.net":
                return _raw_whois(target, referral)
    return None


def _extract_key_fields(raw: str) -> list[str]:
    """Pull useful fields out of the raw whois blob."""
    fields: list[str] = []
    interesting = (
        "domain name", "registrar", "registrant", "creation date",
        "updated date", "expir", "name server", "status",
        "org", "orgname", "netrange", "cidr", "netname",
        "country", "descr", "admin-c", "tech-c", "abuse",
    )
    seen: set[str] = set()
    for line in raw.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("%") or line_stripped.startswith("#"):
            continue
        low = line_stripped.lower()
        for key in interesting:
            if low.startswith(key):
                # De-duplicate identical lines
                if line_stripped not in seen:
                    seen.add(line_stripped)
                    fields.append(line_stripped)
                break
    return fields


# ── Public API ────────────────────────────────────────────────────────────────


def whois_lookup(target: str) -> TestResult:
    """Perform a whois lookup for a domain or IP address."""
    target = target.strip().lower()
    server = _pick_server(target)

    raw = _raw_whois(target, server)

    # Follow one referral if available
    referral_raw = _follow_referral(raw, target)
    if referral_raw:
        raw = referral_raw

    fields = _extract_key_fields(raw)

    if fields:
        return TestResult(
            title="Whois Lookup",
            status=Status.SUCCESS,
            target=target,
            summary=f"Whois data retrieved via {server} — {len(fields)} field(s).",
            details=fields,
            raw_output=raw.strip(),
        )

    if "(error" in raw:
        return TestResult(
            title="Whois Lookup",
            status=Status.ERROR,
            target=target,
            summary=raw.strip(),
        )

    return TestResult(
        title="Whois Lookup",
        status=Status.FAILURE,
        target=target,
        summary=f"No useful whois data found for '{target}'.",
        raw_output=raw.strip(),
    )
