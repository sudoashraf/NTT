"""
Latency testing — extended ping with jitter & statistics.
"""

from __future__ import annotations

import statistics
import re
from typing import List

from ntt.config import PLATFORM, DEFAULT_PING_TIMEOUT
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
    tool_missing_result,
)


def _extract_rtts(output: str) -> List[float]:
    """Parse individual RTT values from ping output."""
    rtts: list[float] = []

    if PLATFORM.is_windows:
        # "Reply from … time=12ms" or "time<1ms"
        for m in re.finditer(r"time[<=](\d+)ms", output, re.IGNORECASE):
            rtts.append(float(m.group(1)))
    else:
        # "64 bytes from …: icmp_seq=1 ttl=64 time=1.23 ms"
        for m in re.finditer(r"time[=]([\d.]+)\s*ms", output, re.IGNORECASE):
            rtts.append(float(m.group(1)))

    return rtts


def latency_test(target: str, count: int = 20, timeout: int = DEFAULT_PING_TIMEOUT) -> TestResult:
    """Extended ping-based latency test with jitter & percentile stats."""
    if not check_tool_available("ping"):
        return tool_missing_result("ping", "Latency Test")

    if PLATFORM.is_windows:
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), target]

    rc, stdout, stderr = run_command(cmd, timeout=count * timeout + 30)
    output = stdout or stderr
    rtts = _extract_rtts(output)

    if not rtts:
        return TestResult(
            title="Latency Test",
            status=Status.FAILURE,
            target=target,
            summary="No RTT samples collected — host may be unreachable.",
            raw_output=output.strip(),
        )

    received = len(rtts)
    loss_pct = round((1 - received / count) * 100, 1) if count else 0

    avg = round(statistics.mean(rtts), 2)
    med = round(statistics.median(rtts), 2)
    mn = round(min(rtts), 2)
    mx = round(max(rtts), 2)
    jitter = round(statistics.stdev(rtts), 2) if len(rtts) > 1 else 0.0

    # Percentiles
    sorted_rtts = sorted(rtts)
    p95_idx = int(0.95 * len(sorted_rtts))
    p99_idx = int(0.99 * len(sorted_rtts))
    p95 = round(sorted_rtts[min(p95_idx, len(sorted_rtts) - 1)], 2)
    p99 = round(sorted_rtts[min(p99_idx, len(sorted_rtts) - 1)], 2)

    details = [
        f"Sent: {count}  |  Received: {received}  |  Loss: {loss_pct}%",
        f"Min: {mn} ms  |  Avg: {avg} ms  |  Med: {med} ms  |  Max: {mx} ms",
        f"Jitter (σ): {jitter} ms",
        f"P95: {p95} ms  |  P99: {p99} ms",
    ]

    if loss_pct == 0:
        status = Status.SUCCESS
    elif loss_pct < 100:
        status = Status.PARTIAL
    else:
        status = Status.FAILURE

    summary = f"Avg latency {avg} ms, jitter {jitter} ms, loss {loss_pct}%."

    return TestResult(
        title="Latency Test",
        status=status,
        target=target,
        summary=summary,
        details=details,
        raw_output=output.strip(),
    )
