#!/usr/bin/env python3
"""
MITM Traffic Interceptor — Network Security Assignment 2

Usage:
  sudo python3 mitm/sniffer.py -i br-<network_id>
"""

import argparse
import os
import re
import subprocess
import sys
import time

try:
    from scapy.all import sniff, TCP, Raw, wrpcap
except ImportError:
    print("scapy is required. Install with: pip install scapy")
    sys.exit(1)

MYSQL_PORT = 3306
FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")
SQL_PATTERN = re.compile(r"(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|GRANT|SHOW)\s", re.IGNORECASE)


class MITMCapture:

    def __init__(self, interface, output_pcap=None):
        self.interface = interface
        self.output_pcap = output_pcap
        self.packets = []
        self.flags_found = set()
        self.sql_queries = []

    def packet_handler(self, packet):
        self.packets.append(packet)

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return

        tcp = packet[TCP]
        if tcp.dport != MYSQL_PORT and tcp.sport != MYSQL_PORT:
            return

        text = bytes(packet[Raw].load).decode("utf-8", errors="replace")
        if not text.strip():
            return

        direction = "webapp -> db" if tcp.dport == MYSQL_PORT else "db -> webapp"

        sql_match = SQL_PATTERN.search(text)
        if sql_match:
            query = re.sub(r"[\x00-\x1f]", " ", text[sql_match.start():].split("\x00")[0]).strip()
            if query:
                self.sql_queries.append(query)
                print(f"[SQL] {direction}: {query[:200]}")

        for flag in FLAG_PATTERN.findall(text):
            if flag not in self.flags_found:
                self.flags_found.add(flag)
                print(f"[FLAG] {flag}")

    def find_interface(self):
        try:
            result = subprocess.run(
                ["docker", "network", "ls", "--filter", "name=vulnerable_network",
                 "--format", "{{.ID}}"],
                capture_output=True, text=True, timeout=5,
            )
            net_id = result.stdout.strip().split("\n")[0][:12]
            if net_id:
                return f"br-{net_id}"
        except Exception:
            pass
        return "docker0"

    def run(self, count=0):
        if not self.interface:
            self.interface = self.find_interface()

        print(f"Capturing on {self.interface} | Ctrl+C to stop")

        try:
            sniff(
                iface=self.interface,
                filter=f"tcp port {MYSQL_PORT}",
                prn=self.packet_handler,
                count=count,
                store=True,
            )
        except KeyboardInterrupt:
            pass

        if self.output_pcap and self.packets:
            wrpcap(self.output_pcap, self.packets)

        print(f"\nPackets: {len(self.packets)}")
        print(f"Queries: {len(self.sql_queries)}")
        print(f"Flags: {len(self.flags_found)}")
        for f in sorted(self.flags_found):
            print(f"{f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-c", "--count", type=int, default=0)
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run with sudo.")
        sys.exit(1)

    capture = MITMCapture(interface=args.interface, output_pcap=args.output)
    capture.run(count=args.count)


if __name__ == "__main__":
    main()