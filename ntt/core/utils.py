"""
Shared utilities: validated input helpers, subprocess runner, result formatting.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from ntt.config import PLATFORM

console = Console()
err_console = Console(stderr=True)


# ── Result types ──────────────────────────────────────────────────────────────


class Status(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass
class TestResult:
    """Universal container for every troubleshooting test result."""

    title: str
    status: Status
    target: str = ""
    summary: str = ""
    details: List[str] = field(default_factory=list)
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# ── Pretty printing ──────────────────────────────────────────────────────────


_STATUS_CONFIG = {
    Status.SUCCESS: {"icon": "✔", "badge": "PASS", "style": "bold green",  "border": "green",  "bar": "green"},
    Status.FAILURE: {"icon": "✘", "badge": "FAIL", "style": "bold red",    "border": "red",    "bar": "red"},
    Status.PARTIAL: {"icon": "⚠", "badge": "WARN", "style": "bold yellow", "border": "yellow", "bar": "yellow"},
    Status.ERROR:   {"icon": "⊘", "badge": "ERR",  "style": "bold red",    "border": "red",    "bar": "red"},
}


def print_result(result: TestResult, show_raw: bool = False) -> None:
    """Render a *TestResult* to the terminal via Rich and log it."""
    # Auto-log to session logger (lazy import to avoid circular deps)
    try:
        from ntt.core.session_log import SessionLogger
        SessionLogger.get().log(result)
    except Exception:
        pass  # never crash presentation for a logging failure

    cfg = _STATUS_CONFIG.get(result.status, {"icon": "?", "badge": "????", "style": "white", "border": "white", "bar": "white"})
    console.print()

    # ── Title bar ─────────────────────────────────────────────────────
    title_text = Text()
    title_text.append(f"  {cfg['icon']}  ", style=cfg["style"])
    title_text.append(result.title, style="bold white")
    if result.target:
        title_text.append("  ➜  ", style="dim")
        title_text.append(result.target, style="bold cyan")

    status_tag = Text(f" {cfg['badge']} ", style=f"bold white on {cfg['bar']}")

    # ── Body ──────────────────────────────────────────────────────────
    body = Text()
    if result.summary:
        body.append("  ")
        body.append(result.summary, style=cfg["style"])
        body.append("\n")

    if result.details:
        body.append("\n")
        for d in result.details:
            body.append("    ")
            body.append("› ", style=f"dim {cfg['bar']}")
            body.append(f"{d}\n")

    if not result.summary and not result.details:
        body.append("  (no details)\n", style="dim")

    # ── Compose panel ─────────────────────────────────────────────────
    header = Text()
    header.append_text(status_tag)
    header.append("  ")
    header.append_text(title_text)

    console.print(
        Panel(
            body,
            title=header,
            title_align="left",
            subtitle=f"[dim italic]⏱  {result.timestamp}[/dim italic]",
            subtitle_align="right",
            border_style=cfg["border"],
            box=box.ROUNDED,
            expand=True,
            padding=(0, 1),
        )
    )

    if show_raw and result.raw_output:
        console.print(
            Panel(
                result.raw_output,
                title="[dim italic]📋 Raw Output[/dim italic]",
                title_align="left",
                border_style="bright_black",
                box=box.SIMPLE,
                expand=True,
                padding=(0, 2),
            )
        )


def print_section(title: str) -> None:
    """Print a visually distinct section divider."""
    console.print()
    console.print(Rule(f"[bold bright_cyan] ◆  {title}  ◆ [/bold bright_cyan]", style="bright_cyan", characters="─"))
    console.print()


# ── Input helpers ─────────────────────────────────────────────────────────────


def prompt(label: str, default: str = "") -> str:
    """Prompt the user for input with an optional default."""
    suffix = f" [dim bright_cyan]({default})[/dim bright_cyan]" if default else ""
    try:
        value = console.input(f"  [bold bright_yellow]❯[/bold bright_yellow] [bold]{label}{suffix}[/bold]: ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return default
    return value or default


def prompt_int(label: str, default: int = 0, min_val: int = 0, max_val: int = 65535) -> int:
    raw = prompt(label, str(default))
    try:
        val = int(raw)
        if min_val <= val <= max_val:
            return val
    except ValueError:
        pass
    console.print(f"  [bold red]✘[/bold red] [red]Invalid input — using default ({default})[/red]")
    return default


def validate_target(target: str) -> Tuple[bool, str]:
    """Return *(True, cleaned_target)* if *target* looks like a valid IP / hostname."""
    target = target.strip()
    if not target:
        return False, "Target cannot be empty."
    # Quick IP check
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass
    # Basic hostname regex
    if re.match(r"^(?!-)[A-Za-z0-9\-\.]{1,253}(?<!-)$", target):
        return True, target
    return False, f"'{target}' is not a valid IP address or hostname."


def resolve_hostname(target: str) -> Optional[str]:
    """Resolve *target* to an IPv4 address, or return None."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ── Subprocess wrapper ────────────────────────────────────────────────────────


def run_command(
    cmd: list[str],
    timeout: int = 60,
    capture: bool = True,
) -> Tuple[int, str, str]:
    """Run an external command and return *(returncode, stdout, stderr)*.

    On Windows many network utilities output to the OEM codepage (e.g. cp437/cp850).
    We decode leniently so non-ASCII characters never crash the tool.
    """
    # Build platform-specific kwargs
    kwargs: dict = dict(
        timeout=timeout,
    )

    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    if PLATFORM.is_windows:
        # Hide the console window that some tools try to spawn
        si = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
        kwargs["startupinfo"] = si

    try:
        proc = subprocess.run(cmd, **kwargs)
        stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
        return proc.returncode, stdout, stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return -3, "", str(exc)


def check_tool_available(tool_attr: str) -> bool:
    """Return *True* if the platform tool is available."""
    return getattr(PLATFORM, tool_attr, None) is not None


def tool_missing_result(tool_name: str, action: str) -> TestResult:
    """Return a standardised error result for a missing external tool."""
    return TestResult(
        title=action,
        status=Status.ERROR,
        summary=f"Required tool '{tool_name}' was not found on PATH.",
        details=["Install the tool and ensure it is available in your system PATH."],
    )
