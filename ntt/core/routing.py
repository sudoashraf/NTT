"""
Routing table viewer — cross-platform.

Runs ``route print`` / ``Get-NetRoute`` (Windows) or ``ip route`` / ``netstat -rn``
(Linux / macOS) and presents the output.
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


def _get_windows_routes() -> tuple[str, List[str]]:
    """Retrieve routing table on Windows."""
    rc, stdout, stderr = run_command(["route", "print"], timeout=15)
    output = stdout or stderr
    entries: list[str] = []

    capture = False
    for line in output.splitlines():
        stripped = line.strip()
        # Start capturing at the IPv4 route table header
        if "Network Destination" in stripped or "Metric" in stripped:
            capture = True
            entries.append(stripped)
            continue
        if capture:
            if not stripped or stripped.startswith("="):
                if entries:
                    capture = False
                continue
            entries.append(stripped)

    return output, entries


def _get_linux_routes() -> tuple[str, List[str]]:
    """Retrieve routing table on Linux."""
    rc, stdout, stderr = run_command(["ip", "route", "show", "table", "all"], timeout=10)
    if rc != 0:
        rc, stdout, stderr = run_command(["netstat", "-rn"], timeout=10)
    output = stdout or stderr
    entries = [line.strip() for line in output.splitlines() if line.strip()]
    return output, entries


def _get_macos_routes() -> tuple[str, List[str]]:
    """Retrieve routing table on macOS."""
    rc, stdout, stderr = run_command(["netstat", "-rn"], timeout=10)
    output = stdout or stderr
    entries = [line.strip() for line in output.splitlines() if line.strip()]
    return output, entries


# ── Public API ────────────────────────────────────────────────────────────────


def routing_table() -> TestResult:
    """Retrieve and display the local routing table."""
    if PLATFORM.is_windows:
        output, entries = _get_windows_routes()
    elif PLATFORM.is_linux:
        output, entries = _get_linux_routes()
    else:
        output, entries = _get_macos_routes()

    if entries:
        return TestResult(
            title="Routing Table",
            status=Status.SUCCESS,
            summary=f"{len(entries)} route entries retrieved.",
            details=entries,
            raw_output=output.strip(),
        )

    return TestResult(
        title="Routing Table",
        status=Status.FAILURE,
        summary="Could not retrieve routing table.",
        raw_output=output.strip(),
    )
