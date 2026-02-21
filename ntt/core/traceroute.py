"""
Traceroute / tracert — cross-platform path discovery.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ntt.config import PLATFORM, DEFAULT_TRACEROUTE_MAX_HOPS
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
    tool_missing_result,
)


def _build_traceroute_cmd(target: str, max_hops: int) -> list[str]:
    if PLATFORM.is_windows:
        return ["tracert", "-d", "-h", str(max_hops), target]
    else:
        # Prefer traceroute; some minimal Linux images only have tracepath
        return ["traceroute", "-n", "-m", str(max_hops), target]


def _parse_hops(output: str) -> List[Tuple[int, str, str]]:
    """Return a list of *(hop_number, ip_or_star, rtt_string)* tuples."""
    hops: list[Tuple[int, str, str]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Match lines like:  " 1   <1 ms   <1 ms   <1 ms  10.0.0.1"  (Windows)
        # or                  " 1  10.0.0.1  1.234 ms  1.456 ms  1.678 ms"  (Linux)
        m = re.match(r"^\s*(\d{1,3})\s+(.+)", line)
        if m:
            hop_no = int(m.group(1))
            rest = m.group(2).strip()
            # Try to extract an IP address from the rest
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
            ip_addr = ip_match.group(1) if ip_match else "*"
            # Collect all RTT values
            rtts = re.findall(r"([\d.<]+\s*ms)", rest)
            rtt_str = "  ".join(rtts) if rtts else rest
            hops.append((hop_no, ip_addr, rtt_str))

    return hops


# ── Public API ────────────────────────────────────────────────────────────────


def traceroute(target: str, max_hops: int = DEFAULT_TRACEROUTE_MAX_HOPS) -> TestResult:
    """Trace the route to *target* and return a structured result."""
    if not check_tool_available("traceroute"):
        # On Windows the attribute is still 'traceroute' but the binary is 'tracert'
        return tool_missing_result("traceroute/tracert", "Traceroute")

    cmd = _build_traceroute_cmd(target, max_hops)
    rc, stdout, stderr = run_command(cmd, timeout=max_hops * 5 + 30)

    output = stdout or stderr
    hops = _parse_hops(output)

    if rc == 0 and hops:
        status = Status.SUCCESS
        summary = f"Trace completed — {len(hops)} hop(s) recorded."
    elif hops:
        status = Status.PARTIAL
        summary = f"Trace partially completed — {len(hops)} hop(s) recorded."
    else:
        status = Status.FAILURE
        summary = "Traceroute failed — no hops recorded."

    details = [f"Hop {h:>2}  {ip:<16}  {rtt}" for h, ip, rtt in hops]

    return TestResult(
        title="Traceroute — Path Discovery",
        status=status,
        target=target,
        summary=summary,
        details=details,
        raw_output=output.strip(),
    )
