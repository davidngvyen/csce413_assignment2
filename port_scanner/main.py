#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# Well-known port-to-service mapping for service fingerprinting
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 2222: "SSH (alt)", 3306: "MySQL",
    3389: "RDP", 5000: "HTTP (Flask)", 5001: "HTTP (Flask)",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB",
}


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # TODO: Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: Set timeout
        s.settimeout(timeout)
        # TODO: Try to connect to target:port
        result = s.connect_ex((target, port))
        # TODO: Close the socket
        s.close()
        # TODO: Return True if connection successful
        return result == 0

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(target, port, timeout=2.0):
    """
    Attempt to grab a service banner from an open port.
    Connects and reads whatever the service sends back,
    then falls back to an HTTP probe if nothing is received.

    Args:
        target (str): IP address or hostname
        port (int): Open port number
        timeout (float): Read timeout in seconds

    Returns:
        str: Banner string, or empty string if nothing received
    """
    banner = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        # Try reading a spontaneous banner (SSH, FTP, SMTP, etc.)
        try:
            data = s.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        # If nothing received, send an HTTP GET probe
        if not banner:
            try:
                s.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                data = s.recv(4096)
                banner = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass

        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return banner


def identify_service(port, banner):
    """
    Identify the service running on a port using the port number
    and banner content.

    Args:
        port (int): Port number
        banner (str): Banner string from the service

    Returns:
        str: Identified service name
    """
    service = KNOWN_SERVICES.get(port, "Unknown")

    if banner:
        bl = banner.lower()
        if "ssh" in bl:
            service = "SSH"
        elif "http" in bl or "html" in bl:
            service = "HTTP"
        elif "mysql" in bl:
            service = "MySQL"
        elif "redis" in bl:
            service = "Redis"
        elif "ftp" in bl:
            service = "FTP"
        elif "smtp" in bl:
            service = "SMTP"

    return service


def scan_range(target, start_port, end_port, threads=100, timeout=1.0):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): Number of concurrent threads
        timeout (float): Connection timeout in seconds

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance

    total = end_port - start_port + 1
    done = 0

    # 1. Multi-threading for faster scans using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            done += 1

            # 7. Progress indicator
            if done % 500 == 0:
                print(f"  [{done}/{total}] ports scanned...")

            # TODO: Scan this port
            is_open = future.result()

            # TODO: If open, add to open_ports list
            if is_open:
                # 2. Banner grabbing to detect services
                banner = grab_banner(target, port)
                # 8. Service fingerprinting
                service = identify_service(port, banner)

                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner[:200],
                })

                # TODO: Print progress (optional)
                print(f"  [+] Port {port} OPEN - {service}")

    return sorted(open_ports, key=lambda x: x["port"])


def resolve_targets(target_str):
    """
    Resolve a target string into a list of IP addresses.
    Supports single IP, CIDR notation, or hostname.

    Args:
        target_str (str): Target specification

    Returns:
        list: List of IP address strings
    """
    # 3. Support for CIDR notation (e.g., 192.168.1.0/24)
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass

    # Single IP
    try:
        ipaddress.ip_address(target_str)
        return [target_str]
    except ValueError:
        pass

    # Hostname — resolve via DNS
    try:
        ip = socket.gethostbyname(target_str)
        return [ip]
    except socket.gaierror:
        print(f"[!] Cannot resolve hostname: {target_str}")
        sys.exit(1)


def parse_ports(port_str):
    """
    Parse a port specification string into a (start, end) tuple.
    Supports range format like '1-10000'.

    Args:
        port_str (str): Port range string

    Returns:
        tuple: (start_port, end_port)
    """
    if "-" in port_str:
        parts = port_str.split("-", 1)
        return int(parts[0]), int(parts[1])
    else:
        p = int(port_str)
        return p, p


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Port Scanner — Network Security Assignment 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 port_scanner/main.py --target 172.20.0.0/24 --ports 1-10000\n"
            "  python3 port_scanner/main.py --target webapp --ports 1-65535 --threads 100\n"
        ),
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target IP, hostname, or CIDR range")
    parser.add_argument("--ports", "-p", default="1-10000",
                        help="Port range (default: 1-10000)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")

    args = parser.parse_args()

    # TODO: Validate inputs
    targets = resolve_targets(args.target)
    start_port, end_port = parse_ports(args.ports)

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("[!] Invalid port range. Must be between 1 and 65535.")
        sys.exit(1)

    print(f"[*] Port Scanner — Network Security Assignment 2")
    print(f"[*] Targets : {len(targets)} host(s)")
    print(f"[*] Ports   : {start_port}-{end_port}")
    print(f"[*] Threads : {args.threads}")
    print(f"[*] Timeout : {args.timeout}s")
    print(f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    scan_start = time.time()

    # TODO: Call scan_range()
    for target in targets:
        print(f"[*] Starting port scan on {target}")

        open_ports = scan_range(target, start_port, end_port,
                                threads=args.threads, timeout=args.timeout)

        # TODO: Display results
        print(f"\n[+] Scan complete!")
        print(f"[+] Found {len(open_ports)} open ports:")

        if open_ports:
            print(f"\n  {'PORT':<10} {'SERVICE':<15} BANNER")
            print(f"  {'-'*60}")
        for entry in open_ports:
            banner_short = entry["banner"][:50].replace("\n", " ") if entry["banner"] else ""
            print(f"  {entry['port']:<10} {entry['service']:<15} {banner_short}")

        print()

    elapsed = time.time() - scan_start
    print(f"[*] Total scan time: {elapsed:.2f}s")


if __name__ == "__main__":
    main()