"""
MTU / Path MTU Discovery — cross-platform.

Uses ``ping`` with the Don't Fragment (DF) bit set, binary-searching
for the largest payload that passes without fragmentation.
"""

from __future__ import annotations

from ntt.config import PLATFORM
from ntt.core.utils import (
    Status,
    TestResult,
    run_command,
    check_tool_available,
    tool_missing_result,
)


def _build_df_ping(target: str, size: int, timeout: int = 2) -> list[str]:
    """Build a DF-bit ping for the given payload *size* (bytes)."""
    if PLATFORM.is_windows:
        # -f = don't fragment, -l = payload size, -n 1 = single packet
        return ["ping", "-n", "1", "-f", "-l", str(size), "-w", str(timeout * 1000), target]
    elif PLATFORM.is_macos:
        # -D = DF bit, -s = payload size, -c 1
        return ["ping", "-D", "-s", str(size), "-c", "1", "-W", str(timeout * 1000), target]
    else:
        # Linux: -M do = DF, -s = payload size
        return ["ping", "-M", "do", "-s", str(size), "-c", "1", "-W", str(timeout), target]


def _ping_succeeds(target: str, size: int, timeout: int = 2) -> bool:
    """Return True if a DF-bit ping with *size* payload bytes succeeds."""
    cmd = _build_df_ping(target, size, timeout)
    rc, stdout, stderr = run_command(cmd, timeout=timeout + 5)
    output = (stdout + stderr).lower()
    # Failure indicators across OSes
    for indicator in ("fragmented", "frag needed", "too long", "message too long",
                      "packet needs to be fragmented", "100% loss", "100% packet loss",
                      "request timed out", "destination host unreachable"):
        if indicator in output:
            return False
    return rc == 0


# ── Public API ────────────────────────────────────────────────────────────────


def mtu_discovery(target: str, timeout: int = 2) -> TestResult:
    """Binary-search for the Path MTU to *target*.

    The search ranges from 100 to 1500 payload bytes.  The final MTU is
    the discovered payload size + 28 (IP + ICMP headers).
    """
    if not check_tool_available("ping"):
        return tool_missing_result("ping", "MTU Discovery")

    # Quick reachability check
    if not _ping_succeeds(target, 100, timeout):
        return TestResult(
            title="MTU / Path MTU Discovery",
            status=Status.FAILURE,
            target=target,
            summary="Host unreachable even with a 100-byte payload — cannot test MTU.",
        )

    low, high = 100, 1500
    best = low

    while low <= high:
        mid = (low + high) // 2
        if _ping_succeeds(target, mid, timeout):
            best = mid
            low = mid + 1
        else:
            high = mid - 1

    mtu = best + 28  # 20 IP header + 8 ICMP header

    details = [
        f"Max payload without fragmentation: {best} bytes",
        f"Path MTU (payload + 28-byte header): {mtu} bytes",
    ]

    if mtu >= 1500:
        details.append("Standard Ethernet MTU (1500) is supported.")
        status = Status.SUCCESS
        summary = f"Path MTU is {mtu} bytes — standard Ethernet MTU OK."
    elif mtu >= 1400:
        details.append("Slightly below 1500 — possible tunnel / VPN overhead.")
        status = Status.PARTIAL
        summary = f"Path MTU is {mtu} bytes — minor overhead detected."
    else:
        details.append("Significantly below 1500 — tunnelling, MPLS, or restrictive segment.")
        status = Status.PARTIAL
        summary = f"Path MTU is {mtu} bytes — notable overhead or restriction."

    return TestResult(
        title="MTU / Path MTU Discovery",
        status=status,
        target=target,
        summary=summary,
        details=details,
    )
