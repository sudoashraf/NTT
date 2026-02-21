"""
Centralised runtime configuration and OS-detection helpers.
"""

import platform
import shutil
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class PlatformInfo:
    """Immutable snapshot of the host OS and available external tools."""

    system: str = field(default_factory=lambda: platform.system())  # Windows | Linux | Darwin
    release: str = field(default_factory=platform.release)
    is_windows: bool = field(default=False)
    is_linux: bool = field(default=False)
    is_macos: bool = field(default=False)

    # Paths to external tools (None if not found on PATH)
    ping: Optional[str] = None
    traceroute: Optional[str] = None
    nslookup: Optional[str] = None
    dig: Optional[str] = None
    nmap: Optional[str] = None
    nc: Optional[str] = None
    curl: Optional[str] = None
    telnet: Optional[str] = None

    def __post_init__(self) -> None:  # pragma: no cover — simple wiring
        # Set boolean OS flags
        object.__setattr__(self, "is_windows", self.system == "Windows")
        object.__setattr__(self, "is_linux", self.system == "Linux")
        object.__setattr__(self, "is_macos", self.system == "Darwin")

        # Discover external tools
        for tool_name in (
            "ping",
            "traceroute",
            "nslookup",
            "dig",
            "nmap",
            "nc",
            "curl",
            "telnet",
        ):
            binary = tool_name
            # Windows-specific overrides
            if self.is_windows and tool_name == "traceroute":
                binary = "tracert"
            path = shutil.which(binary)
            object.__setattr__(self, tool_name, path)


# Singleton — instantiated once at import time.
PLATFORM = PlatformInfo()

# Default timeouts (seconds)
DEFAULT_PING_COUNT = 4
DEFAULT_PING_TIMEOUT = 5
DEFAULT_TRACEROUTE_MAX_HOPS = 30
DEFAULT_PORT_TIMEOUT = 3
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_DNS_TIMEOUT = 5
