#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("paramiko is required: pip install paramiko")
    sys.exit(1)

from logger import create_logger

LOG_PATH = "/app/logs/honeypot.log"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", 22))
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

FAKE_FS = {
    "/": ["bin", "etc", "home", "root", "tmp", "usr", "var"],
    "/home": ["admin", "user"],
    "/home/admin": [".bashrc", ".ssh", "documents"],
    "/home/admin/documents": ["budget.xlsx", "passwords.txt", "notes.md"],
    "/etc": ["passwd", "shadow", "hosts", "ssh"],
    "/root": [".bashrc", ".ssh"],
    "/tmp": [],
}

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
    "user:x:1001:1001:Regular User:/home/user:/bin/bash\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


class SSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip, hp_logger):
        self.client_ip = client_ip
        self.hp_logger = hp_logger
        self.username = None
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.hp_logger.log_auth_attempt(self.client_ip, username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True

    def get_allowed_auths(self, username):
        return "password,publickey"


class FakeShell:

    def __init__(self, channel, username, client_ip, hp_logger):
        self.channel = channel
        self.username = username or "admin"
        self.client_ip = client_ip
        self.hp_logger = hp_logger
        self.cwd = f"/home/{self.username}" if self.username != "root" else "/root"
        self.hostname = "web-server-01"

    def get_prompt(self):
        sym = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{self.cwd}{sym} "

    def handle_command(self, cmd):
        cmd = cmd.strip()
        if not cmd:
            return ""

        self.hp_logger.log_command(self.client_ip, self.username, cmd)
        parts = cmd.split()
        base = parts[0]

        if base in ("exit", "logout", "quit"):
            return None

        if base == "ls":
            target = parts[1] if len(parts) > 1 else self.cwd
            if target in FAKE_FS:
                return "  ".join(FAKE_FS[target]) + "\n" if FAKE_FS[target] else "\n"
            return f"ls: cannot access '{target}': No such file or directory\n"

        if base == "pwd":
            return self.cwd + "\n"

        if base == "whoami":
            return self.username + "\n"

        if base == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n"
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n"

        if base == "uname":
            if "-a" in parts:
                return "Linux web-server-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
            return "Linux\n"

        if base == "hostname":
            return self.hostname + "\n"

        if base == "cat":
            if len(parts) < 2:
                return "cat: missing operand\n"
            if "passwd" in parts[1]:
                return FAKE_PASSWD
            if "shadow" in parts[1]:
                return "Permission denied\n"
            if "passwords" in parts[1]:
                return "admin:P@ssw0rd123!\nroot:toor\nbackup:backup2024\n"
            return f"cat: {parts[1]}: No such file or directory\n"

        if base == "cd":
            target = parts[1] if len(parts) > 1 else f"/home/{self.username}"
            if target in FAKE_FS or target == "..":
                if target == "..":
                    self.cwd = "/".join(self.cwd.rstrip("/").split("/")[:-1]) or "/"
                else:
                    self.cwd = target
                return ""
            return f"bash: cd: {target}: No such file or directory\n"

        if base in ("wget", "curl"):
            self.hp_logger.log_alert(self.client_ip, "download_attempt", cmd)
            return f"bash: {base}: command not found\n"

        if base in ("python", "python3", "perl", "ruby", "gcc", "cc"):
            self.hp_logger.log_alert(self.client_ip, "code_execution_attempt", cmd)
            return f"bash: {base}: command not found\n"

        if base in ("rm", "dd", "mkfs", "shutdown", "reboot"):
            self.hp_logger.log_alert(self.client_ip, "destructive_command", cmd)
            return f"bash: {base}: permission denied\n"

        if base == "ifconfig" or (base == "ip" and len(parts) > 1):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 172.20.0.30  netmask 255.255.0.0\n")

        if base == "ps":
            return ("  PID TTY          TIME CMD\n"
                    "    1 ?        00:00:01 sshd\n"
                    " 1234 pts/0    00:00:00 bash\n")

        if base == "env" or base == "printenv":
            return (f"USER={self.username}\nHOME=/home/{self.username}\n"
                    f"SHELL=/bin/bash\nHOSTNAME={self.hostname}\n")

        if base == "echo":
            return " ".join(parts[1:]) + "\n"

        return f"bash: {base}: command not found\n"

    def run(self):
        welcome = (
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            "Last login: Mon Jan  6 14:22:01 2026 from 10.0.0.5\r\n"
        )
        try:
            self.channel.sendall(welcome.encode())
            self.channel.sendall(self.get_prompt().encode())
        except Exception:
            return

        buf = ""
        try:
            while True:
                data = self.channel.recv(1024)
                if not data:
                    break
                for byte in data:
                    if chr(byte) in ("\r", "\n"):
                        self.channel.sendall(b"\r\n")
                        output = self.handle_command(buf)
                        if output is None:
                            self.channel.sendall(b"logout\r\n")
                            return
                        if output:
                            self.channel.sendall(output.encode())
                        self.channel.sendall(self.get_prompt().encode())
                        buf = ""
                    elif byte == 127 and buf:
                        buf = buf[:-1]
                        self.channel.sendall(b"\b \b")
                    elif byte == 3:
                        self.channel.sendall(b"^C\r\n")
                        self.channel.sendall(self.get_prompt().encode())
                        buf = ""
                    elif byte == 4:
                        return
                    elif 32 <= byte < 127:
                        buf += chr(byte)
                        self.channel.sendall(bytes([byte]))
        except (EOFError, OSError):
            pass


def handle_client(client_socket, client_addr, hp_logger, host_key):
    client_ip = client_addr[0]
    connect_time = datetime.utcnow()
    hp_logger.log_connection(client_ip, client_addr[1])

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(host_key)

        server = SSHServer(client_ip, hp_logger)
        transport.start_server(server=server)

        channel = transport.accept(timeout=30)
        if channel is None:
            return

        server.event.wait(10)
        FakeShell(channel, server.username, client_ip, hp_logger).run()
        channel.close()

    except Exception:
        pass
    finally:
        duration = (datetime.utcnow() - connect_time).total_seconds()
        hp_logger.log_disconnect(client_ip, duration)
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    hp_logger = create_logger()

    key_path = os.path.join("/app/logs", "honeypot_rsa.key")
    if os.path.exists(key_path):
        host_key = paramiko.RSAKey.from_private_key_file(key_path)
    else:
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(key_path)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(50)

    logger.info("Honeypot listening on %s:%d", LISTEN_HOST, LISTEN_PORT)

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr, hp_logger, host_key),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        server_socket.close()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()