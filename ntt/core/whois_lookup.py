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
    "eu":  "whois.eu",
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
        "domain name", "domain", "registrar", "registrant",
        "creation date", "created", "updated date", "expir",
        "name server", "status",
        "org", "orgname", "organisation", "organization",
        "netrange", "cidr", "netname",
        "country", "descr", "admin-c", "tech-c", "technical", "abuse",
        "email", "e-mail", "script",
    )
    seen: set[str] = set()
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("%") or line_stripped.startswith("#"):
            i += 1
            continue
        low = line_stripped.lower()
        matched = any(low.startswith(key) for key in interesting)
        if not matched:
            i += 1
            continue

        if line_stripped not in seen:
            seen.add(line_stripped)
            fields.append(line_stripped)

        # If this is a section header (value-less "Key:"), collect the
        # indented continuation lines that belong to it.
        colon_pos = line_stripped.find(":")
        if colon_pos != -1 and not line_stripped[colon_pos + 1:].strip():
            i += 1
            while i < len(lines):
                next_line = lines[i]
                next_stripped = next_line.strip()
                if not next_stripped:
                    break  # blank line ends the section
                if next_line[0] not in (" ", "\t"):
                    break  # non-indented line = new section
                if next_stripped not in seen:
                    seen.add(next_stripped)
                    fields.append(f"  {next_stripped}")
                i += 1
            continue

        i += 1
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
