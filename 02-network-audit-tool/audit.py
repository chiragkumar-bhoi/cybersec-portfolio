#!/usr/bin/env python3
"""
Home Network Security Audit Tool

Discovers live hosts on a local subnet, scans common ports, and flags
well-known risky/legacy services.

IMPORTANT: only scan networks you own or have explicit permission to scan.
"""

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "smb",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-alt",
}

RISKY_PORTS = {
    21: "FTP — unencrypted credentials/data. Prefer SFTP/FTPS.",
    23: "Telnet — fully unencrypted remote access. Use SSH instead.",
    139: "SMB — historically exploited (e.g. WannaCry via SMBv1). Disable if unused.",
    445: "SMB — historically exploited (e.g. WannaCry via SMBv1). Disable if unused.",
    3389: "RDP — common brute-force/ransomware target if exposed to the internet.",
    5900: "VNC — often unauthenticated by default. Ensure a strong password/tunnel is used.",
}


@dataclass
class HostResult:
    ip: str
    open_ports: list = field(default_factory=list)  # list of (port, service)

    @property
    def risky_ports(self):
        return [(p, s) for p, s in self.open_ports if p in RISKY_PORTS]


def guess_local_subnet() -> str:
    """Best-effort guess of the local /24 subnet based on the default route interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def is_host_alive(ip: str, timeout: float = 0.5) -> bool:
    """Cheap liveness check: try a fast TCP connect to a couple of common ports."""
    for port in (80, 443, 22, 445):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def scan_host_ports(ip: str, ports: dict, timeout: float = 0.3) -> HostResult:
    result = HostResult(ip=ip)
    for port, service in ports.items():
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                result.open_ports.append((port, service))
        except OSError:
            continue
    return result


def discover_hosts(subnet: str, max_workers: int = 64) -> list:
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    live = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(is_host_alive, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    live.append(ip)
            except Exception:
                continue
    return sorted(live, key=lambda x: ipaddress.ip_address(x))


def audit_network(subnet: str) -> list:
    print(f"Scanning {subnet} ...")
    live_hosts = discover_hosts(subnet)
    print(f"Found {len(live_hosts)} live hosts.\n")

    results = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(scan_host_ports, ip, COMMON_PORTS): ip for ip in live_hosts
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
    return results


def print_report(results: list):
    flagged_count = 0
    for host in results:
        if not host.open_ports:
            continue
        print(f"{host.ip}")
        port_summary = ", ".join(f"{p} ({s})" for p, s in sorted(host.open_ports))
        print(f"  Open ports: {port_summary}")
        for port, reason in host.risky_ports:
            print(f"  ⚠  Port {port} is open — {reason}")
        if host.risky_ports:
            flagged_count += 1
        print()

    scanned = len(results)
    print(f"Summary: {flagged_count} host(s) flagged with risky open ports out of {scanned} scanned.")


def export_json(results: list, path: str):
    data = [
        {
            "ip": host.ip,
            "open_ports": [{"port": p, "service": s} for p, s in host.open_ports],
            "risky_ports": [{"port": p, "reason": r} for p, r in host.risky_ports],
        }
        for host in results
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\nReport written to {path}")


def main():
    parser = argparse.ArgumentParser(description="Audit a local network for open ports and risky services.")
    parser.add_argument(
        "--subnet",
        help="Subnet to scan in CIDR notation (default: auto-detect your local /24). "
        "Only scan networks you own or have permission to scan.",
    )
    parser.add_argument("--output", help="Write a JSON report to this path")
    args = parser.parse_args()

    subnet = args.subnet or guess_local_subnet()

    confirm = input(f"About to scan {subnet}. Do you own or have permission to scan this network? [y/N] ")
    if confirm.strip().lower() != "y":
        print("Aborted.")
        sys.exit(0)

    results = audit_network(subnet)
    print_report(results)

    if args.output:
        export_json(results, args.output)


if __name__ == "__main__":
    main()
