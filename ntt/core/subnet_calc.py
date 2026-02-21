"""
IPv4 / IPv6 subnet calculator.

Pure Python — no external tools needed.
"""

from __future__ import annotations

import ipaddress
from typing import Union

from ntt.core.utils import Status, TestResult


def subnet_calc(cidr: str) -> TestResult:
    """Calculate and display subnet details for a CIDR like ``192.168.1.0/24``."""
    try:
        net: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return TestResult(
            title="Subnet Calculator",
            status=Status.ERROR,
            target=cidr,
            summary=f"Invalid CIDR notation: {exc}",
        )

    details: list[str] = [
        f"Network address : {net.network_address}",
        f"Broadcast address: {net.broadcast_address}" if isinstance(net, ipaddress.IPv4Network) else "",
        f"Netmask         : {net.netmask}" if hasattr(net, "netmask") else "",
        f"Host mask       : {net.hostmask}",
        f"Prefix length   : /{net.prefixlen}",
        f"Total addresses : {net.num_addresses}",
    ]

    if isinstance(net, ipaddress.IPv4Network):
        usable = max(net.num_addresses - 2, 0) if net.prefixlen < 31 else net.num_addresses
        details.append(f"Usable hosts    : {usable}")
        hosts = list(net.hosts())
        if hosts:
            details.append(f"First usable    : {hosts[0]}")
            details.append(f"Last usable     : {hosts[-1]}")
        details.append(f"Is private      : {net.is_private}")

    # Filter out empty strings
    details = [d for d in details if d]

    return TestResult(
        title="Subnet Calculator",
        status=Status.SUCCESS,
        target=cidr,
        summary=f"Subnet details for {net.with_prefixlen}",
        details=details,
    )
