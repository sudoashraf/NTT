"""
ARP table viewer — cross-platform.

Runs ``arp -a`` (Windows / macOS) or ``ip neigh`` (Linux) and parses
the output into structured entries.
"""

from __future__ import annotations

import re
from typing import List

from ntt.config import PLATFORM
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
)


def _parse_arp_windows(output: str) -> List[str]:
    """Parse Windows ``arp -a`` output."""
    entries: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        # Match lines like:  10.0.0.1   00-11-22-33-44-55   dynamic
        m = re.match(r"([\d.]+)\s+([\da-fA-F-]+)\s+(\S+)", line)
        if m:
            ip, mac, arp_type = m.groups()
            entries.append(f"{ip:<18} {mac:<20} {arp_type}")
    return entries


def _parse_ip_neigh(output: str) -> List[str]:
    """Parse Linux ``ip neigh`` output."""
    entries: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # e.g. "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        parts = line.split()
        if len(parts) >= 5:
            ip = parts[0]
            mac = "?"
            state = parts[-1]
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mac = parts[idx + 1]
            entries.append(f"{ip:<18} {mac:<20} {state}")
        else:
            entries.append(line)
    return entries


def _parse_arp_unix(output: str) -> List[str]:
    """Parse macOS / generic ``arp -a`` output."""
    entries: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        # Format: hostname (IP) at MAC on iface ...
        m = re.match(r".*?\(([\d.]+)\)\s+at\s+([\da-fA-F:]+)\s+.*?on\s+(\S+)", line)
        if m:
            ip, mac, iface = m.groups()
            entries.append(f"{ip:<18} {mac:<20} {iface}")
        elif line and not line.startswith("Address"):
            entries.append(line)
    return entries


# ── Public API ────────────────────────────────────────────────────────────────


def arp_table() -> TestResult:
    """Retrieve and parse the local ARP / neighbour table."""
    if PLATFORM.is_linux:
        rc, stdout, stderr = run_command(["ip", "neigh"], timeout=10)
        if rc != 0:
            # Fallback
            rc, stdout, stderr = run_command(["arp", "-a"], timeout=10)
        output = stdout or stderr
        entries = _parse_ip_neigh(output) if "lladdr" in output or "REACHABLE" in output or "STALE" in output else _parse_arp_unix(output)
    else:
        rc, stdout, stderr = run_command(["arp", "-a"], timeout=10)
        output = stdout or stderr
        if PLATFORM.is_windows:
            entries = _parse_arp_windows(output)
        else:
            entries = _parse_arp_unix(output)

    if entries:
        header = f"{'IP Address':<18} {'MAC Address':<20} {'Type/State'}"
        details = [header, "─" * 58] + entries
        return TestResult(
            title="ARP / Neighbour Table",
            status=Status.SUCCESS,
            summary=f"{len(entries)} ARP entries found.",
            details=details,
            raw_output=output.strip(),
        )

    return TestResult(
        title="ARP / Neighbour Table",
        status=Status.FAILURE,
        summary="No ARP entries found or command failed.",
        raw_output=output.strip(),
    )
