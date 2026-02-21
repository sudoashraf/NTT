"""
Active connections / listening sockets viewer — cross-platform.

Wraps ``netstat`` (Windows / macOS) and ``ss`` / ``netstat`` (Linux).
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


def _get_windows_connections(filter_state: str = "") -> tuple[str, List[str]]:
    """Run ``netstat -ano`` on Windows."""
    rc, stdout, stderr = run_command(["netstat", "-ano"], timeout=15)
    output = stdout or stderr
    entries: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Header or data rows contain "TCP" or "UDP"
        if any(proto in stripped.upper() for proto in ("TCP", "UDP")):
            if filter_state:
                if filter_state.upper() in stripped.upper():
                    entries.append(stripped)
            else:
                entries.append(stripped)

    return output, entries


def _get_linux_connections(filter_state: str = "") -> tuple[str, List[str]]:
    """Run ``ss -tuanp`` (or ``netstat -tuanp``) on Linux."""
    rc, stdout, stderr = run_command(["ss", "-tuanp"], timeout=10)
    if rc != 0:
        rc, stdout, stderr = run_command(["netstat", "-tuanp"], timeout=10)
    output = stdout or stderr
    entries: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(tok in stripped.lower() for tok in ("tcp", "udp", "listen", "estab", "time-wait")):
            if filter_state:
                if filter_state.upper() in stripped.upper():
                    entries.append(stripped)
            else:
                entries.append(stripped)

    return output, entries


def _get_macos_connections(filter_state: str = "") -> tuple[str, List[str]]:
    """Run ``netstat -an`` on macOS."""
    rc, stdout, stderr = run_command(["netstat", "-an"], timeout=15)
    output = stdout or stderr
    entries: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(proto in stripped.lower() for proto in ("tcp", "udp")):
            if filter_state:
                if filter_state.upper() in stripped.upper():
                    entries.append(stripped)
            else:
                entries.append(stripped)

    return output, entries


# ── Public API ────────────────────────────────────────────────────────────────


def connections(filter_state: str = "") -> TestResult:
    """Return active TCP/UDP connections and listeners.

    *filter_state* can be e.g. ``LISTEN``, ``ESTABLISHED``, ``TIME_WAIT``
    to narrow results.
    """
    if PLATFORM.is_windows:
        output, entries = _get_windows_connections(filter_state)
    elif PLATFORM.is_linux:
        output, entries = _get_linux_connections(filter_state)
    else:
        output, entries = _get_macos_connections(filter_state)

    filter_label = f" (filtered: {filter_state.upper()})" if filter_state else ""

    if entries:
        # Limit display to first 100 to avoid wall-of-text
        display = entries[:100]
        extra = f" (showing first 100 of {len(entries)})" if len(entries) > 100 else ""
        return TestResult(
            title="Active Connections",
            status=Status.SUCCESS,
            summary=f"{len(entries)} connection(s) found{filter_label}{extra}.",
            details=display,
            raw_output=output.strip(),
        )

    return TestResult(
        title="Active Connections",
        status=Status.FAILURE,
        summary=f"No connections found{filter_label}.",
        raw_output=output.strip(),
    )
