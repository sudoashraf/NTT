# NTT — Network Troubleshooting Toolkit

A **production-ready, cross-platform CLI tool** for network engineers. NTT provides an interactive menu and direct-command interface for everyday network troubleshooting tasks.

Supports **Windows**, **Linux**, and **macOS**.

---

## Demo

<!-- To play locally: asciinema play demo.cast -->
<!-- To upload & get an embed link: asciinema upload demo.cast -->
[![asciicast](https://asciinema.org/a/RECORDING_ID.svg)](https://asciinema.org/a/RECORDING_ID)

> **Tip:** You can also play the recording locally:
> ```bash
> # Install asciinema if you haven't already
> pip install asciinema
>
> # Play the demo
> asciinema play demo.cast
> ```

---

## Features

### 🌐 Connectivity & Reachability

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Ping** | ICMP reachability check with packet-loss & RTT stats |
| 2 | **Traceroute** | Path discovery (`tracert` on Windows, `traceroute` on Unix) |
| 3 | **DNS Lookup** | Forward & reverse lookups (A, AAAA, MX, NS, CNAME, PTR) via `dig` / `nslookup` / `socket` |
| 4 | **Port Check** | TCP connectivity test to a single port with banner grab |
| 5 | **Port Scan** | Scan multiple ports via Python sockets or `nmap` |

### ⚡ Performance & Monitoring

| # | Feature | Description |
|---|---------|-------------|
| 6 | **Latency Test** | Extended ping with jitter, percentile (P95/P99) statistics |
| 7 | **HTTP(S) Check** | Endpoint health, response time, TLS certificate expiry |
| 8 | **MTU Discovery** | Find path MTU using DF-bit binary search |

### 🔎 Lookup & Intelligence

| # | Feature | Description |
|---|---------|-------------|
| 9 | **Whois Lookup** | Domain / IP ownership & registration info |
| 10 | **ARP Table** | View local ARP / neighbour cache |
| 11 | **Routing Table** | View local routing / forwarding table |

### 🖥️ Local System

| # | Feature | Description |
|---|---------|-------------|
| 12 | **Connections** | Active TCP/UDP connections & listeners (filter by state) |
| 13 | **Bulk Ping** | Ping multiple hosts concurrently (manual entry or from file) |
| 14 | **Network Info** | Local interfaces, IPs, default gateway |
| 15 | **Subnet Calculator** | CIDR → network, broadcast, usable host range, etc. |

### 🛠️ Tools & Reports

| # | Feature | Description |
|---|---------|-------------|
| 16 | **Full Diagnostics** | Combined ping + DNS + traceroute + HTTP against one target |
| 17 | **Export Results** | Save session results to JSON, CSV, or HTML |
| 18 | **Session Info** | View session summary & log file location |

---

## Requirements

- **Python 3.8+**
- **rich** (installed automatically)

Optional external tools (detected at runtime):
`ping`, `traceroute`/`tracert`, `nslookup`, `dig`, `nmap`, `nc`, `curl`, `telnet`

---

## Installation

```bash
# Clone / copy the project, then:
cd NTT
pip install -e .
```

Or without installing:

```bash
pip install rich
python -m ntt
```

---

## Usage

### Interactive mode (default)

```bash
ntt
# or
python -m ntt
```

This launches a numbered menu — pick an option, enter the target, and see formatted results.

### Direct command mode

```bash
# Ping
ntt ping 8.8.8.8
ntt ping google.com -c 10

# Traceroute
ntt trace 8.8.8.8
ntt traceroute cloudflare.com -m 20

# DNS
ntt dns example.com
ntt dns example.com -r MX
ntt dns 8.8.8.8 -r PTR

# Port check
ntt port google.com 443

# Port scan
ntt scan 192.168.1.1 -p 22,80,443
ntt scan 10.0.0.1 -p 1-1024
ntt scan target.host --nmap

# Latency test
ntt latency 1.1.1.1 -c 50

# HTTP(S) check
ntt http https://example.com

# MTU discovery
ntt mtu 8.8.8.8

# Whois lookup
ntt whois example.com
ntt whois 8.8.8.8

# ARP table
ntt arp

# Routing table
ntt routes

# Active connections
ntt conns
ntt conns -f LISTEN

# Bulk ping
ntt bulkping 8.8.8.8 1.1.1.1 google.com
ntt bulkping -f hosts.txt -c 10

# Local network info
ntt info

# Subnet calculator
ntt subnet 192.168.1.0/24
ntt subnet 10.0.0.0/8

# Export session results
ntt export json
ntt export html
ntt export csv -o report.csv
```

---

## Session Logging

Every test result is automatically logged to a JSON-lines file in the `ntt_logs/` directory. Each interactive session creates a new timestamped log file. Use **Export Results** (option 17) or the `ntt export` command to save results as JSON, CSV, or HTML reports to the `ntt_reports/` directory.

---

## Project Structure

```
NTT/
├── pyproject.toml          # Build & packaging config
├── requirements.txt
├── README.md
├── ntt_logs/               # Auto-generated session logs (JSONL)
├── ntt_reports/            # Exported reports (JSON / CSV / HTML)
└── ntt/
    ├── __init__.py         # Version & metadata
    ├── __main__.py         # python -m ntt entry
    ├── cli.py              # Argument parser & dispatch
    ├── config.py           # OS detection & tool discovery
    ├── menu.py             # Interactive menu loop
    └── core/
        ├── __init__.py
        ├── utils.py        # Subprocess runner, result types, I/O helpers
        ├── ping.py         # ICMP ping
        ├── traceroute.py   # Path discovery
        ├── dns_lookup.py   # DNS forward & reverse
        ├── port_check.py   # Single port & range scan
        ├── latency.py      # Extended latency statistics
        ├── http_check.py   # HTTP(S) health & TLS cert
        ├── mtu.py          # Path MTU discovery
        ├── whois_lookup.py # Whois lookup
        ├── arp_table.py    # ARP / neighbour cache
        ├── routing.py      # Routing table
        ├── connections.py  # Active TCP/UDP connections
        ├── bulk_ping.py    # Concurrent multi-host ping
        ├── net_info.py     # Local interface info
        ├── subnet_calc.py  # CIDR calculator
        ├── export.py       # JSON / CSV / HTML export
        └── session_log.py  # Session logger (JSONL)
```

---

## License

MIT
