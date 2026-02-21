"""
Local network interface / configuration info.

Cross-platform: ipconfig (Windows) vs ip / ifconfig (Linux/macOS), plus
Python's ``socket`` for hostname and default gateway heuristics.
"""

from __future__ import annotations

import re
import socket
from typing import List

from ntt.config import PLATFORM
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
)


def _windows_interfaces() -> List[str]:
    """Parse ``ipconfig /all`` into per-interface summaries."""
    _, stdout, _ = run_command(["ipconfig", "/all"], timeout=10)
    blocks: list[str] = []
    current: list[str] = []
    for line in stdout.splitlines():
        if line and not line[0].isspace() and ":" in line:
            if current:
                blocks.append("\n".join(current))
            current = [line.strip()]
        elif line.strip():
            current.append(line.strip())
    if current:
        blocks.append("\n".join(current))
    return blocks


def _unix_interfaces() -> List[str]:
    """Parse ``ip addr`` (or ``ifconfig``) output."""
    rc, stdout, _ = run_command(["ip", "-br", "addr"], timeout=10)
    if rc == 0 and stdout.strip():
        return [line.strip() for line in stdout.strip().splitlines() if line.strip()]
    # Fallback to ifconfig
    rc, stdout, _ = run_command(["ifconfig"], timeout=10)
    if rc == 0 and stdout.strip():
        blocks: list[str] = []
        current: list[str] = []
        for line in stdout.splitlines():
            if line and not line[0].isspace():
                if current:
                    blocks.append(" | ".join(current))
                current = [line.strip()]
            elif line.strip():
                current.append(line.strip())
        if current:
            blocks.append(" | ".join(current))
        return blocks
    return ["Could not retrieve interface information."]


# ── Public API ────────────────────────────────────────────────────────────────


def network_info() -> TestResult:
    """Gather local network interface and routing information."""
    hostname = socket.gethostname()
    details: list[str] = [f"Hostname: {hostname}"]

    try:
        local_ip = socket.gethostbyname(hostname)
        details.append(f"Primary IP: {local_ip}")
    except socket.gaierror:
        pass

    if PLATFORM.is_windows:
        ifaces = _windows_interfaces()
    else:
        ifaces = _unix_interfaces()

    for iface in ifaces:
        details.append(iface)

    # Default gateway (best-effort)
    if PLATFORM.is_windows:
        _, out, _ = run_command(["powershell", "-Command",
                                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                                timeout=10)
        gw = out.strip()
        if gw:
            details.insert(2, f"Default gateway: {gw}")
    else:
        _, out, _ = run_command(["ip", "route", "show", "default"], timeout=5)
        m = re.search(r"default\s+via\s+([\d.]+)", out)
        if m:
            details.insert(2, f"Default gateway: {m.group(1)}")

    return TestResult(
        title="Network Interface Information",
        status=Status.SUCCESS,
        target=hostname,
        summary=f"Collected info for host '{hostname}'.",
        details=details,
    )
