"""Logging helpers for the honeypot."""

import json
import logging
import os
import threading
from collections import defaultdict
from datetime import datetime


def create_logger(log_dir="/app/logs"):
    return HoneypotLogger(log_dir)


class HoneypotLogger:

    BRUTE_FORCE_THRESHOLD = 5

    def __init__(self, log_dir="/app/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._auth_counts = defaultdict(int)

        self._logger = logging.getLogger("Honeypot")
        self._logger.setLevel(logging.INFO)
        self._logger.handlers.clear()

        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        self._logger.addHandler(logging.FileHandler(os.path.join(log_dir, "honeypot.log")))
        self._logger.addHandler(logging.StreamHandler())
        for h in self._logger.handlers:
            h.setFormatter(fmt)

    def _append_jsonl(self, filename, data):
        filepath = os.path.join(self.log_dir, filename)
        line = json.dumps(data, default=str)
        with self._lock:
            with open(filepath, "a") as f:
                f.write(line + "\n")

    def log_connection(self, client_ip, client_port):
        self._append_jsonl("connections.jsonl", {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "connection",
            "client_ip": client_ip,
            "client_port": client_port,
        })
        self._logger.info("Connection from %s:%d", client_ip, client_port)

    def log_disconnect(self, client_ip, duration_seconds):
        self._append_jsonl("connections.jsonl", {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "disconnect",
            "client_ip": client_ip,
            "duration_seconds": round(duration_seconds, 2),
        })
        self._logger.info("Disconnect from %s (%.1fs)", client_ip, duration_seconds)

    def log_auth_attempt(self, client_ip, username, password):
        self._append_jsonl("auth_attempts.jsonl", {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "auth_attempt",
            "client_ip": client_ip,
            "username": username,
            "password": password,
        })
        self._logger.warning("Auth from %s: user=%s pass=%s", client_ip, username, password)

        with self._lock:
            self._auth_counts[client_ip] += 1
            count = self._auth_counts[client_ip]
        if count == self.BRUTE_FORCE_THRESHOLD:
            self.log_alert(client_ip, "brute_force_detected",
                           f"{count} attempts from {client_ip}")

    def log_command(self, client_ip, username, command):
        self._append_jsonl("commands.jsonl", {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "command",
            "client_ip": client_ip,
            "username": username,
            "command": command,
        })
        self._logger.info("Command from %s (%s): %s", client_ip, username, command)

    def log_alert(self, client_ip, alert_type, details):
        self._append_jsonl("alerts.jsonl", {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "alert",
            "alert_type": alert_type,
            "client_ip": client_ip,
            "details": details,
        })
        self._logger.critical("ALERT [%s] %s: %s", alert_type, client_ip, details)

    def log_event(self, event_type, data=None):
        entry = {"timestamp": datetime.utcnow().isoformat(), "event": event_type}
        if data:
            entry.update(data)
        self._append_jsonl("connections.jsonl", entry)