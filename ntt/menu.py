"""
Interactive menu system for the Network Troubleshooting Toolkit.

Presents a numbered menu, collects user input, dispatches to the
appropriate core module, and displays results — all in a loop until
the user chooses to exit.
"""

from __future__ import annotations

import ipaddress
import sys
from typing import Callable, List, Tuple

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from ntt import __app_name__, __version__
from ntt.config import PLATFORM
from ntt.core.utils import (
    console,
    prompt,
    prompt_int,
    validate_target,
    print_result,
    print_section,
)
from ntt.core.ping import ping
from ntt.core.traceroute import traceroute
from ntt.core.dns_lookup import dns_lookup, reverse_dns
from ntt.core.port_check import check_port, scan_ports
from ntt.core.latency import latency_test
from ntt.core.http_check import http_check
from ntt.core.net_info import network_info
from ntt.core.subnet_calc import subnet_calc
from ntt.core.mtu import mtu_discovery
from ntt.core.whois_lookup import whois_lookup
from ntt.core.arp_table import arp_table
from ntt.core.routing import routing_table
from ntt.core.connections import connections
from ntt.core.bulk_ping import bulk_ping
from ntt.core.export import export_results
from ntt.core.session_log import SessionLogger


# ── Menu definition (with categories & icons) ─────────────────────────────


MENU_ITEMS: List[Tuple[str, str, str, Callable[[], None]]] = []
# (icon, label, description, handler)

MENU_CATEGORIES: List[Tuple[str, List[int]]] = []
# (category_name, [item_indices])


def _register(icon: str, label: str, desc: str, handler: Callable[[], None]) -> None:
    MENU_ITEMS.append((icon, label, desc, handler))


# ── Handlers (thin wrappers that prompt for input, then call core) ────────────


def _handle_ping() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return
    count = prompt_int("Number of pings", default=4, min_val=1, max_val=100)
    result = ping(target, count=count)
    print_result(result, show_raw=True)


def _handle_traceroute() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return
    max_hops = prompt_int("Max hops", default=30, min_val=1, max_val=255)
    result = traceroute(target, max_hops=max_hops)
    print_result(result, show_raw=True)


def _handle_dns() -> None:
    target = prompt("Enter hostname or IP")
    if not target:
        console.print("  [red]Target cannot be empty.[/red]")
        return
    rec_type = prompt("Record type (A, AAAA, MX, NS, CNAME, PTR, ANY)", default="A").upper()

    if rec_type == "PTR":
        result = reverse_dns(target)
    else:
        result = dns_lookup(target, record_type=rec_type)
    print_result(result, show_raw=True)


def _handle_port_check() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return
    port = prompt_int("Port number", default=80, min_val=1, max_val=65535)
    timeout = prompt_int("Timeout (seconds)", default=3, min_val=1, max_val=30)
    result = check_port(target, port, timeout=timeout)
    print_result(result)


def _handle_port_scan() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return

    mode = prompt("Scan mode: (1) Common ports  (2) Custom range  (3) nmap", default="1")

    if mode == "1":
        common = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
        console.print(f"  [dim]Scanning {len(common)} common ports …[/dim]")
        result = scan_ports(target, ports=common, timeout=2)
    elif mode == "2":
        start = prompt_int("Start port", default=1, min_val=1, max_val=65534)
        end = prompt_int("End port", default=1024, min_val=start, max_val=65535)
        console.print(f"  [dim]Scanning ports {start}–{end} …[/dim]")
        result = scan_ports(target, port_range=(start, end), timeout=1)
    else:
        result = scan_ports(target, use_nmap=True)

    print_result(result, show_raw=True)


def _handle_latency() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return
    count = prompt_int("Number of pings", default=20, min_val=5, max_val=200)
    console.print(f"  [dim]Running {count}-ping latency test — please wait …[/dim]")
    result = latency_test(target, count=count)
    print_result(result, show_raw=False)


def _handle_http() -> None:
    target = prompt("Enter URL or hostname (e.g. example.com)")
    if not target:
        console.print("  [red]Target cannot be empty.[/red]")
        return
    result = http_check(target)
    print_result(result)


def _handle_netinfo() -> None:
    console.print("  [dim]Gathering local network information …[/dim]")
    result = network_info()
    print_result(result)


def _handle_subnet() -> None:
    cidr = prompt("Enter CIDR notation (e.g. 192.168.1.0/24)")
    if not cidr:
        console.print("  [red]Input cannot be empty.[/red]")
        return
    result = subnet_calc(cidr)
    print_result(result)


def _handle_full_diag() -> None:
    """Run ping + traceroute + DNS + HTTP against a single target."""
    target = prompt("Enter target host/IP")
    ok, cleaned = validate_target(target)
    if not ok:
        console.print(f"  [red]{cleaned}[/red]")
        return

    print_section(f"Full Diagnostics — {cleaned}")

    console.print("  [dim][1/4] Ping …[/dim]")
    print_result(ping(cleaned))

    console.print("  [dim][2/4] DNS Lookup …[/dim]")
    print_result(dns_lookup(cleaned))

    console.print("  [dim][3/4] Traceroute …[/dim]")
    print_result(traceroute(cleaned))

    # Attempt HTTP if it looks like a hostname (not raw IP)
    try:
        ipaddress.ip_address(cleaned)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip:
        console.print("  [dim][4/4] HTTP(S) Check …[/dim]")
        print_result(http_check(cleaned))
    else:
        console.print("  [dim][4/4] Skipping HTTP check for raw IP.[/dim]")


def _handle_mtu() -> None:
    target = prompt("Enter target host/IP")
    ok, target = validate_target(target)
    if not ok:
        console.print(f"  [red]{target}[/red]")
        return
    console.print("  [dim]Binary-searching for Path MTU — this may take a moment …[/dim]")
    result = mtu_discovery(target)
    print_result(result)


def _handle_whois() -> None:
    target = prompt("Enter domain or IP address")
    if not target:
        console.print("  [red]Target cannot be empty.[/red]")
        return
    console.print("  [dim]Querying whois …[/dim]")
    result = whois_lookup(target)
    print_result(result, show_raw=True)


def _handle_arp() -> None:
    console.print("  [dim]Reading ARP / neighbour table …[/dim]")
    result = arp_table()
    print_result(result)


def _handle_routing() -> None:
    console.print("  [dim]Reading routing table …[/dim]")
    result = routing_table()
    print_result(result, show_raw=True)


def _handle_connections() -> None:
    filt = prompt("Filter by state (LISTEN, ESTABLISHED, TIME_WAIT, or blank for all)", default="")
    console.print("  [dim]Retrieving active connections …[/dim]")
    result = connections(filter_state=filt)
    print_result(result)


def _handle_bulk_ping() -> None:
    mode = prompt("(1) Enter hosts manually  (2) Load from file", default="1")
    if mode == "2":
        path = prompt("Path to hosts file")
        if not path:
            console.print("  [red]Path cannot be empty.[/red]")
            return
        count = prompt_int("Pings per host", default=4, min_val=1, max_val=20)
        console.print("  [dim]Bulk pinging from file — please wait …[/dim]")
        result = bulk_ping(file_path=path, count=count)
    else:
        raw = prompt("Enter hosts separated by commas")
        if not raw:
            console.print("  [red]No hosts provided.[/red]")
            return
        targets = [t.strip() for t in raw.split(",") if t.strip()]
        count = prompt_int("Pings per host", default=4, min_val=1, max_val=20)
        console.print(f"  [dim]Bulk pinging {len(targets)} host(s) — please wait …[/dim]")
        result = bulk_ping(targets=targets, count=count)
    print_result(result)


def _handle_export() -> None:
    logger = SessionLogger.get()
    results = logger.results
    if not results:
        console.print("  [yellow]No test results in this session to export.[/yellow]")
        return
    fmt = prompt("Export format: (1) JSON  (2) CSV  (3) HTML", default="1")
    fmt_map = {"1": "json", "2": "csv", "3": "html"}
    chosen = fmt_map.get(fmt, fmt.lower())
    try:
        path = export_results(results, fmt=chosen)
        console.print(f"  [bold green]Exported {len(results)} result(s) to:[/bold green] {path}")
    except Exception as exc:
        console.print(f"  [bold red]Export failed:[/bold red] {exc}")


def _handle_session_info() -> None:
    logger = SessionLogger.get()
    console.print(f"  {logger.summary()}")


# ── Register all menu items ───────────────────────────────────────────────────

# 🌐  Connectivity & Reachability
_register("🏓", "Ping",              "Check host reachability (ICMP)",                      _handle_ping)
_register("🔀", "Traceroute",        "Discover network path to a host",                     _handle_traceroute)
_register("📡", "DNS Lookup",        "Resolve DNS records (A, AAAA, MX, NS, PTR …)",       _handle_dns)
_register("🚪", "Port Check",        "Test TCP connectivity to a single port",              _handle_port_check)
_register("🔍", "Port Scan",         "Scan multiple ports (socket / nmap)",                 _handle_port_scan)

# ⚡  Performance & Monitoring
_register("⏱️", "Latency Test",      "Extended ping with jitter & percentile stats",        _handle_latency)
_register("🌍", "HTTP(S) Check",     "Check HTTP endpoint status & TLS certificate",        _handle_http)
_register("📏", "MTU Discovery",     "Find path MTU (DF-bit binary search)",                _handle_mtu)

# 🔎  Lookup & Intelligence
_register("📋", "Whois Lookup",      "Domain / IP ownership & registration info",           _handle_whois)
_register("🗂️", "ARP Table",         "View local ARP / neighbour cache",                    _handle_arp)
_register("🗺️", "Routing Table",     "View local routing / forwarding table",               _handle_routing)

# 🖥️  Local System
_register("🔗", "Connections",       "Active TCP/UDP connections & listeners",               _handle_connections)
_register("📌", "Bulk Ping",         "Ping multiple hosts concurrently",                    _handle_bulk_ping)
_register("🖧",  "Network Info",      "Show local interfaces, IPs, gateway",                 _handle_netinfo)
_register("🧮", "Subnet Calculator", "Calculate subnet details from CIDR",                  _handle_subnet)

# 🛠️  Tools & Reports
_register("🩺", "Full Diagnostics",  "Run ping + DNS + traceroute + HTTP on one target",    _handle_full_diag)
_register("💾", "Export Results",     "Save session results to JSON / CSV / HTML",           _handle_export)
_register("📝", "Session Info",      "View session summary & log file location",            _handle_session_info)


# ── Populate categories (1-based indices into MENU_ITEMS) ─────────────────────

MENU_CATEGORIES.extend([
    ("🌐  Connectivity & Reachability",  [1, 2, 3, 4, 5]),
    ("⚡  Performance & Monitoring",      [6, 7, 8]),
    ("🔎  Lookup & Intelligence",         [9, 10, 11]),
    ("🖥️  Local System",                  [12, 13, 14, 15]),
    ("🛠️  Tools & Reports",               [16, 17, 18]),
])


# ── Banner & menu loop ────────────────────────────────────────────────────────


def _print_banner() -> None:
    LOGO = (
        "[bold bright_cyan]"
        "  ███╗   ██╗ ████████╗ ████████╗\n"
        "  ████╗  ██║ ╚══██╔══╝ ╚══██╔══╝\n"
        "  ██╔██╗ ██║    ██║       ██║   \n"
        "  ██║╚██╗██║    ██║       ██║   \n"
        "  ██║ ╚████║    ██║       ██║   \n"
        "  ╚═╝  ╚═══╝    ╚═╝       ╚═╝   \n"
        "[/bold bright_cyan]"
    )

    os_label = f"{PLATFORM.system} {PLATFORM.release}"
    tools_available = []
    for tool in ("ping", "traceroute", "nslookup", "dig", "nmap", "nc", "curl", "telnet"):
        path = getattr(PLATFORM, tool, None)
        if path:
            tools_available.append(f"[green]✔ {tool}[/green]")
        else:
            tools_available.append(f"[dim]✘ {tool}[/dim]")
    tools_str = "  ".join(tools_available)

    logger = SessionLogger.get()

    info_lines = (
        f"{LOGO}\n"
        f"  [bold white]{__app_name__}[/bold white]  [dim]v{__version__}[/dim]\n"
        f"  [dim]───────────────────────────────────────────────────────[/dim]\n"
        f"  [bold]💻 OS:[/bold]  {os_label}\n"
        f"  [bold]🔧 Tools:[/bold]  {tools_str}\n"
        f"  [bold]📝 Log:[/bold]  [dim]{logger.log_path}[/dim]"
    )

    console.print()
    console.print(Panel(
        info_lines,
        border_style="bright_cyan",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(1, 2),
    ))


def _print_menu() -> None:
    console.print()

    for cat_name, indices in MENU_CATEGORIES:
        # Category header
        console.print(f"  [bold bright_white]{cat_name}[/bold bright_white]")

        table = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
            pad_edge=False,
        )
        table.add_column("No.",  style="bold cyan",   width=6,  justify="right")
        table.add_column("Icon", width=3)
        table.add_column("Name", style="bold white",   min_width=20)
        table.add_column("Desc", style="dim")

        for idx in indices:
            icon, label, desc, _ = MENU_ITEMS[idx - 1]
            table.add_row(f"[{idx}]", icon, label, desc)

        console.print(table)
        console.print()  # spacing between categories

    # Exit option
    exit_icon = "❌" if sys.platform != "win32" else "🚪"
    console.print(f"  [bold bright_white]{exit_icon}  Exit[/bold bright_white]")
    exit_table = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
    exit_table.add_column("No.",  style="bold cyan", width=6, justify="right")
    exit_table.add_column("Icon", width=3)
    exit_table.add_column("Name", style="bold white", min_width=20)
    exit_table.add_column("Desc", style="dim")
    exit_table.add_row("[0]", exit_icon, "Exit", "Quit the toolkit")
    console.print(exit_table)
    console.print()


def run_menu() -> None:
    """Main interactive loop."""
    _print_banner()

    while True:
        _print_menu()
        choice = prompt("Select an option")

        if choice in ("0", "q", "quit", "exit"):
            console.print()
            console.print(Panel(
                "[bold green]  ✔  Thanks for using NTT. Goodbye!  [/bold green]",
                border_style="green",
                box=box.ROUNDED,
                expand=False,
                padding=(0, 2),
            ))
            console.print()
            break

        try:
            idx = int(choice)
        except ValueError:
            console.print("  [bold red]✘ Please enter a valid number.[/bold red]")
            continue

        if 1 <= idx <= len(MENU_ITEMS):
            icon, label, _, handler = MENU_ITEMS[idx - 1]
            print_section(f"{icon}  {label}")
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n  [yellow]⚠ Operation cancelled.[/yellow]")
            except Exception as exc:
                console.print(f"  [bold red]✘ Error:[/bold red] {exc}")
        else:
            console.print("  [bold red]✘ Invalid option — please try again.[/bold red]")
