#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import subprocess
import threading
import time
from collections import defaultdict

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_ACCESS_DURATION = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def run_iptables(args_list):
    try:
        result = subprocess.run(["iptables"] + args_list, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def init_firewall(protected_port):
    run_iptables(["-D", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])
    run_iptables(["-A", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])
    logging.info("Port %d BLOCKED by default", protected_port)


def open_protected_port(protected_port, client_ip, access_duration):
    """Open the protected port using firewall rules."""
    success = run_iptables(["-I", "INPUT", "1", "-p", "tcp", "-s", client_ip,
                            "--dport", str(protected_port), "-j", "ACCEPT"])
    if success:
        logging.info("OPENED port %d for %s", protected_port, client_ip)

        def auto_close():
            time.sleep(access_duration)
            close_protected_port(protected_port, client_ip)

        threading.Thread(target=auto_close, daemon=True).start()


def close_protected_port(protected_port, client_ip=None):
    """Close the protected port using firewall rules."""
    if client_ip:
        run_iptables(["-D", "INPUT", "-p", "tcp", "-s", client_ip,
                      "--dport", str(protected_port), "-j", "ACCEPT"])
        logging.info("CLOSED port %d for %s", protected_port, client_ip)
    else:
        run_iptables(["-D", "INPUT", "-p", "tcp", "--dport",
                      str(protected_port), "-j", "DROP"])


class KnockTracker:
    def __init__(self, sequence, window_seconds):
        self.sequence = sequence
        self.window = window_seconds
        self.lock = threading.Lock()
        self.progress = defaultdict(lambda: {"step": 0, "start_time": 0.0})

    def register_knock(self, client_ip, knock_port):
        with self.lock:
            state = self.progress[client_ip]
            now = time.time()

            if state["step"] > 0 and (now - state["start_time"]) > self.window:
                state["step"] = 0
                state["start_time"] = 0.0

            expected_port = self.sequence[state["step"]]

            if knock_port == expected_port:
                if state["step"] == 0:
                    state["start_time"] = now
                state["step"] += 1
                logging.info("Knock %d/%d from %s on port %d",
                             state["step"], len(self.sequence), client_ip, knock_port)

                if state["step"] >= len(self.sequence):
                    state["step"] = 0
                    state["start_time"] = 0.0
                    return True
            else:
                state["step"] = 0
                state["start_time"] = 0.0

        return False


def listen_on_port(port, tracker, protected_port, access_duration):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)

    while True:
        try:
            client_sock, client_addr = server.accept()
            client_ip = client_addr[0]
            client_sock.close()

            if tracker.register_knock(client_ip, port):
                open_protected_port(protected_port, client_ip, access_duration)
        except Exception as e:
            logging.error("Error on port %d: %s", port, e)


def listen_for_knocks(sequence, window_seconds, protected_port, access_duration):
    logger = logging.getLogger("KnockServer")
    logger.info("Knock sequence: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    init_firewall(protected_port)
    tracker = KnockTracker(sequence, window_seconds)

    for port in sequence:
        threading.Thread(
            target=listen_on_port,
            args=(port, tracker, protected_port, access_duration),
            daemon=True,
        ).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        close_protected_port(protected_port)
        logger.info("Shutdown")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence", 
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports")
    parser.add_argument(
        "--protected-port", 
        type=int, default=DEFAULT_PROTECTED_PORT,
        help="Protected service port")
    parser.add_argument(
        "--window", type=float, default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence")
    parser.add_argument(
        "--access-duration", type=float, default=DEFAULT_ACCESS_DURATION,
        help="Seconds the port stays open")
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.access_duration)


if __name__ == "__main__":
    main()