"""
Ping / ICMP reachability check — cross-platform.
"""

from __future__ import annotations

import re
from typing import Optional

from ntt.config import PLATFORM, DEFAULT_PING_COUNT, DEFAULT_PING_TIMEOUT
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
    tool_missing_result,
)


def _build_ping_cmd(target: str, count: int, timeout: int) -> list[str]:
    """Build the correct ``ping`` invocation for the host OS."""
    if PLATFORM.is_windows:
        return ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:
        return ["ping", "-c", str(count), "-W", str(timeout), target]


def _parse_ping_stats(output: str) -> dict:
    """Extract packet-loss percentage and RTT statistics from ping output."""
    stats: dict = {}

    # Packet loss — works on Windows & Unix
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", output, re.IGNORECASE)
    if loss_match:
        stats["packet_loss"] = float(loss_match.group(1))

    # RTT on Unix: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
    rtt_unix = re.search(
        r"rtt\s+min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if rtt_unix:
        stats["min_ms"] = float(rtt_unix.group(1))
        stats["avg_ms"] = float(rtt_unix.group(2))
        stats["max_ms"] = float(rtt_unix.group(3))
        stats["mdev_ms"] = float(rtt_unix.group(4))
        return stats

    # RTT on macOS: round-trip min/avg/max/stddev = …
    rtt_mac = re.search(
        r"round-trip\s+min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if rtt_mac:
        stats["min_ms"] = float(rtt_mac.group(1))
        stats["avg_ms"] = float(rtt_mac.group(2))
        stats["max_ms"] = float(rtt_mac.group(3))
        stats["mdev_ms"] = float(rtt_mac.group(4))
        return stats

    # RTT on Windows: Minimum = 1ms, Maximum = 3ms, Average = 2ms
    rtt_win = re.search(
        r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if rtt_win:
        stats["min_ms"] = float(rtt_win.group(1))
        stats["max_ms"] = float(rtt_win.group(2))
        stats["avg_ms"] = float(rtt_win.group(3))

    return stats


# ── Public API ────────────────────────────────────────────────────────────────


def ping(
    target: str,
    count: int = DEFAULT_PING_COUNT,
    timeout: int = DEFAULT_PING_TIMEOUT,
) -> TestResult:
    """Ping *target* and return a structured :class:`TestResult`."""
    if not check_tool_available("ping"):
        return tool_missing_result("ping", "Ping")

    cmd = _build_ping_cmd(target, count, timeout)
    rc, stdout, stderr = run_command(cmd, timeout=count * timeout + 10)

    output = stdout or stderr
    stats = _parse_ping_stats(output)
    packet_loss = stats.get("packet_loss")

    if rc == 0 and packet_loss is not None and packet_loss == 0:
        status = Status.SUCCESS
    elif rc == 0 and packet_loss is not None and packet_loss < 100:
        status = Status.PARTIAL
    else:
        status = Status.FAILURE

    details = []
    if packet_loss is not None:
        details.append(f"Packet loss: {packet_loss}%")
    if "avg_ms" in stats:
        details.append(f"RTT min/avg/max: {stats.get('min_ms', '?')}/{stats['avg_ms']}/{stats.get('max_ms', '?')} ms")
    if "mdev_ms" in stats:
        details.append(f"Jitter (mdev): {stats['mdev_ms']} ms")

    summary = "Host is reachable." if status in (Status.SUCCESS, Status.PARTIAL) else "Host is unreachable."

    return TestResult(
        title="Ping — Reachability Check",
        status=status,
        target=target,
        summary=summary,
        details=details,
        raw_output=output.strip(),
    )
