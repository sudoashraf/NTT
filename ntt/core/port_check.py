"""
TCP port-reachability and port-scanning.

Uses Python's ``socket`` for reliable cross-platform behaviour.
Optionally shells out to ``nmap`` for richer scanning when available.
"""

from __future__ import annotations

import socket
from typing import List, Tuple

from ntt.config import PLATFORM, DEFAULT_PORT_TIMEOUT
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
    tool_missing_result,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _check_port_socket(host: str, port: int, timeout: int) -> bool:
    """Return *True* if a TCP connection to *host:port* succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _grab_banner(host: str, port: int, timeout: int = 3) -> str:
    """Try to read a service banner (best-effort)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\r\n")
            data = s.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


# ── Public API ────────────────────────────────────────────────────────────────


def check_port(host: str, port: int, timeout: int = DEFAULT_PORT_TIMEOUT) -> TestResult:
    """Test TCP reachability of a single *host:port*."""
    reachable = _check_port_socket(host, port, timeout)
    banner = ""
    if reachable:
        banner = _grab_banner(host, port, timeout=2)

    details: list[str] = []
    if banner:
        details.append(f"Banner: {banner[:200]}")

    if reachable:
        return TestResult(
            title="Port Reachability Check",
            status=Status.SUCCESS,
            target=f"{host}:{port}",
            summary=f"Port {port}/tcp is OPEN on {host}.",
            details=details,
        )
    return TestResult(
        title="Port Reachability Check",
        status=Status.FAILURE,
        target=f"{host}:{port}",
        summary=f"Port {port}/tcp is CLOSED or filtered on {host}.",
    )


def scan_ports(
    host: str,
    ports: List[int] | None = None,
    port_range: Tuple[int, int] = (1, 1024),
    timeout: int = DEFAULT_PORT_TIMEOUT,
    use_nmap: bool = False,
) -> TestResult:
    """Scan multiple ports on *host*.

    If *use_nmap* is ``True`` and nmap is available, delegate to nmap for a
    richer SYN scan; otherwise fall back to Python sockets.
    """
    # ── nmap path ─────────────────────────────────────────────────────────
    if use_nmap:
        if not check_tool_available("nmap"):
            return tool_missing_result("nmap", "Port Scan (nmap)")

        if ports:
            port_arg = ",".join(str(p) for p in ports)
        else:
            port_arg = f"{port_range[0]}-{port_range[1]}"

        cmd = ["nmap", "-Pn", "-p", port_arg, "--open", host]
        rc, stdout, stderr = run_command(cmd, timeout=300)
        output = stdout or stderr

        open_ports: list[str] = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line.lower():
                open_ports.append(line.strip())

        if open_ports:
            return TestResult(
                title="Port Scan (nmap)",
                status=Status.SUCCESS,
                target=host,
                summary=f"{len(open_ports)} open port(s) found.",
                details=open_ports,
                raw_output=output.strip(),
            )
        return TestResult(
            title="Port Scan (nmap)",
            status=Status.FAILURE,
            target=host,
            summary="No open ports found in the specified range.",
            raw_output=output.strip(),
        )

    # ── Socket-based scan ─────────────────────────────────────────────────
    if ports is None:
        ports = list(range(port_range[0], port_range[1] + 1))

    open_list: list[str] = []
    closed_count = 0
    for p in ports:
        if _check_port_socket(host, p, timeout):
            open_list.append(f"Port {p}/tcp  OPEN")
        else:
            closed_count += 1

    total = len(ports)
    if open_list:
        return TestResult(
            title="Port Scan (socket)",
            status=Status.SUCCESS,
            target=host,
            summary=f"{len(open_list)} open / {closed_count} closed  (scanned {total} port(s)).",
            details=open_list,
        )
    return TestResult(
        title="Port Scan (socket)",
        status=Status.FAILURE,
        target=host,
        summary=f"All {total} scanned port(s) are closed or filtered.",
    )
