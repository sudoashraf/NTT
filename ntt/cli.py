"""
CLI entry-point for the Network Troubleshooting Toolkit.

Supports two modes:
  • **Interactive** (default) — ``ntt`` / ``python -m ntt``
  • **Direct command** — ``ntt ping 8.8.8.8``, ``ntt dns example.com`` etc.
"""

from __future__ import annotations

import argparse
import sys

from ntt import __app_name__, __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ntt",
        description=f"{__app_name__} — a cross-platform network troubleshooting CLI.",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command", help="Run a specific test directly (skip the interactive menu).")

    # ── ping ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("ping", help="ICMP ping reachability check")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("-c", "--count", type=int, default=4, help="Number of pings (default: 4)")
    sp.add_argument("-t", "--timeout", type=int, default=5, help="Timeout per ping in seconds (default: 5)")

    # ── traceroute ────────────────────────────────────────────────────────
    sp = sub.add_parser("trace", aliases=["traceroute"], help="Trace network path")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum hops (default: 30)")

    # ── dns ───────────────────────────────────────────────────────────────
    sp = sub.add_parser("dns", help="DNS lookup")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("-r", "--record", default="A", help="Record type (A, AAAA, MX, NS, PTR …)")

    # ── port ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("port", help="TCP port check")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("port_number", type=int, help="Port number")
    sp.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds (default: 3)")

    # ── scan ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Port scan")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("-p", "--ports", help="Comma-separated ports or range (e.g. 22,80,443 or 1-1024)")
    sp.add_argument("--nmap", action="store_true", help="Use nmap instead of socket scan")

    # ── latency ───────────────────────────────────────────────────────────
    sp = sub.add_parser("latency", help="Extended latency test")
    sp.add_argument("target", help="Hostname or IP address")
    sp.add_argument("-c", "--count", type=int, default=20, help="Number of pings (default: 20)")

    # ── http ──────────────────────────────────────────────────────────────
    sp = sub.add_parser("http", help="HTTP(S) endpoint health check")
    sp.add_argument("target", help="URL or hostname")

    # ── info ──────────────────────────────────────────────────────────────
    sub.add_parser("info", help="Show local network interfaces & config")

    # ── subnet ────────────────────────────────────────────────────────────
    sp = sub.add_parser("subnet", help="Subnet calculator")
    sp.add_argument("cidr", help="CIDR notation (e.g. 192.168.1.0/24)")

    # ── mtu ───────────────────────────────────────────────────────────────
    sp = sub.add_parser("mtu", help="Path MTU discovery (DF-bit binary search)")
    sp.add_argument("target", help="Hostname or IP address")

    # ── whois ─────────────────────────────────────────────────────────────
    sp = sub.add_parser("whois", help="Whois lookup for domain or IP")
    sp.add_argument("target", help="Domain name or IP address")

    # ── arp ───────────────────────────────────────────────────────────────
    sub.add_parser("arp", help="View local ARP / neighbour table")

    # ── routes ────────────────────────────────────────────────────────────
    sub.add_parser("routes", aliases=["route"], help="View local routing table")

    # ── connections ───────────────────────────────────────────────────────
    sp = sub.add_parser("conns", aliases=["connections"], help="Active TCP/UDP connections")
    sp.add_argument("-f", "--filter", default="", dest="state_filter",
                    help="Filter by state (e.g. LISTEN, ESTABLISHED, TIME_WAIT)")

    # ── bulk ping ─────────────────────────────────────────────────────────
    sp = sub.add_parser("bulkping", help="Ping multiple hosts concurrently")
    sp.add_argument("targets", nargs="*", help="Hostnames or IPs (space-separated)")
    sp.add_argument("-f", "--file", dest="hosts_file", help="File with one host per line")
    sp.add_argument("-c", "--count", type=int, default=4, help="Pings per host (default: 4)")

    # ── export ────────────────────────────────────────────────────────────
    sp = sub.add_parser("export", help="Export session results to file")
    sp.add_argument("format", choices=["json", "csv", "html"], help="Output format")
    sp.add_argument("-o", "--output", default="", help="Output file path (auto-generated if omitted)")

    return p


def _dispatch(args: argparse.Namespace) -> None:
    """Import the relevant core module and run the requested test."""
    from ntt.core.utils import print_result  # noqa: local import for speed

    cmd = args.command

    if cmd == "ping":
        from ntt.core.ping import ping
        print_result(ping(args.target, count=args.count, timeout=args.timeout), show_raw=True)

    elif cmd in ("trace", "traceroute"):
        from ntt.core.traceroute import traceroute
        print_result(traceroute(args.target, max_hops=args.max_hops), show_raw=True)

    elif cmd == "dns":
        from ntt.core.dns_lookup import dns_lookup, reverse_dns
        rec = args.record.upper()
        if rec == "PTR":
            print_result(reverse_dns(args.target), show_raw=True)
        else:
            print_result(dns_lookup(args.target, record_type=rec), show_raw=True)

    elif cmd == "port":
        from ntt.core.port_check import check_port
        print_result(check_port(args.target, args.port_number, timeout=args.timeout))

    elif cmd == "scan":
        from ntt.core.port_check import scan_ports
        ports = None
        port_range = (1, 1024)
        if args.ports:
            if "-" in args.ports and "," not in args.ports:
                start, end = args.ports.split("-", 1)
                port_range = (int(start), int(end))
            else:
                ports = [int(p.strip()) for p in args.ports.split(",")]
        print_result(scan_ports(args.target, ports=ports, port_range=port_range, use_nmap=args.nmap), show_raw=True)

    elif cmd == "latency":
        from ntt.core.latency import latency_test
        print_result(latency_test(args.target, count=args.count))

    elif cmd == "http":
        from ntt.core.http_check import http_check
        print_result(http_check(args.target))

    elif cmd == "info":
        from ntt.core.net_info import network_info
        print_result(network_info())

    elif cmd == "subnet":
        from ntt.core.subnet_calc import subnet_calc
        print_result(subnet_calc(args.cidr))

    elif cmd == "mtu":
        from ntt.core.mtu import mtu_discovery
        print_result(mtu_discovery(args.target))

    elif cmd == "whois":
        from ntt.core.whois_lookup import whois_lookup
        print_result(whois_lookup(args.target), show_raw=True)

    elif cmd == "arp":
        from ntt.core.arp_table import arp_table
        print_result(arp_table())

    elif cmd in ("routes", "route"):
        from ntt.core.routing import routing_table
        print_result(routing_table(), show_raw=True)

    elif cmd in ("conns", "connections"):
        from ntt.core.connections import connections
        print_result(connections(filter_state=args.state_filter))

    elif cmd == "bulkping":
        from ntt.core.bulk_ping import bulk_ping
        if args.hosts_file:
            print_result(bulk_ping(file_path=args.hosts_file, count=args.count))
        elif args.targets:
            print_result(bulk_ping(targets=args.targets, count=args.count))
        else:
            print("Error: provide targets as arguments or use -f/--file.")
            sys.exit(1)

    elif cmd == "export":
        from ntt.core.session_log import SessionLogger
        from ntt.core.export import export_results
        logger = SessionLogger.get()
        results = logger.results
        if not results:
            print("No test results in this session to export.")
            sys.exit(1)
        path = export_results(results, fmt=args.format, path=args.output)
        print(f"Exported {len(results)} result(s) to: {path}")


def main() -> None:
    """Main entry-point called by the ``ntt`` console script or ``python -m ntt``."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command:
        # Direct command mode
        try:
            _dispatch(args)
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(130)
    else:
        # Interactive menu mode
        from ntt.menu import run_menu
        try:
            run_menu()
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(130)


if __name__ == "__main__":
    main()
