"""
DNS resolution — forward (A/AAAA/MX/NS/CNAME) and reverse lookups.

Uses Python's ``socket`` module for basic forward/reverse lookups (zero
external dependencies) and shells out to ``nslookup`` / ``dig`` for richer
record-type queries when those tools are available.
"""

from __future__ import annotations

import re
import socket
from typing import List, Optional

from ntt.config import PLATFORM, DEFAULT_DNS_TIMEOUT
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _socket_forward(target: str) -> List[str]:
    """Resolve *target* via :func:`socket.getaddrinfo` (A + AAAA)."""
    try:
        results = socket.getaddrinfo(target, None)
        ips = sorted({r[4][0] for r in results})
        return ips
    except socket.gaierror:
        return []


def _socket_reverse(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _nslookup_query(target: str, record_type: str = "A") -> str:
    """Run ``nslookup -type=<record_type> <target>`` and return raw output."""
    cmd = ["nslookup", f"-type={record_type}", target]
    _, stdout, stderr = run_command(cmd, timeout=DEFAULT_DNS_TIMEOUT + 5)
    return stdout or stderr


def _dig_query(target: str, record_type: str = "A") -> str:
    """Run ``dig <target> <record_type>`` and return raw output."""
    cmd = ["dig", target, record_type, "+noall", "+answer", "+ttlid"]
    _, stdout, stderr = run_command(cmd, timeout=DEFAULT_DNS_TIMEOUT + 5)
    return stdout or stderr


# ── Public API ────────────────────────────────────────────────────────────────


def dns_lookup(target: str, record_type: str = "A") -> TestResult:
    """Perform a DNS lookup for *target* with the requested *record_type*.

    Falls back gracefully:
        dig → nslookup → socket (for A/AAAA only)
    """
    details: list[str] = []
    raw_output = ""

    record_type = record_type.upper()

    # ── Try dig first (usually richest output) ───────────────────────────
    if check_tool_available("dig"):
        raw_output = _dig_query(target, record_type)
        if raw_output.strip():
            for line in raw_output.strip().splitlines():
                line = line.strip()
                if line and not line.startswith(";"):
                    details.append(line)

    # ── Fall back to nslookup ─────────────────────────────────────────────
    if not details and check_tool_available("nslookup"):
        raw_output = _nslookup_query(target, record_type)
        if raw_output.strip():
            capture = False
            for line in raw_output.strip().splitlines():
                line = line.strip()
                # Skip the "Server:" / "Address:" header block
                if re.match(r"^(Name|Address|Aliases|mail\s+exchanger|nameserver)", line, re.IGNORECASE):
                    capture = True
                if capture and line:
                    details.append(line)

    # ── Socket fallback (A / AAAA only) ───────────────────────────────────
    if not details and record_type in ("A", "AAAA", "ANY"):
        ips = _socket_forward(target)
        if ips:
            details = [f"{target} → {ip}" for ip in ips]
            raw_output = "\n".join(ips)

    if details:
        status = Status.SUCCESS
        summary = f"DNS {record_type} lookup succeeded — {len(details)} record(s) found."
    else:
        status = Status.FAILURE
        summary = f"DNS {record_type} lookup failed — no records found for '{target}'."

    return TestResult(
        title=f"DNS Lookup ({record_type})",
        status=status,
        target=target,
        summary=summary,
        details=details,
        raw_output=raw_output.strip(),
    )


def reverse_dns(ip: str) -> TestResult:
    """Perform a reverse DNS lookup on *ip*."""
    hostname = _socket_reverse(ip)
    if hostname:
        return TestResult(
            title="Reverse DNS Lookup",
            status=Status.SUCCESS,
            target=ip,
            summary=f"{ip} resolves to {hostname}",
            details=[f"PTR: {hostname}"],
        )
    return TestResult(
        title="Reverse DNS Lookup",
        status=Status.FAILURE,
        target=ip,
        summary=f"No PTR record found for {ip}.",
    )
