## Honeypot Starter Template

This directory is a starter template for the honeypot portion of the assignment.

### What you need to implement
- Choose a protocol (SSH, HTTP, or multi-protocol).
- Simulate a convincing service banner and responses.
- Log connection metadata, authentication attempts, and attacker actions.
- Store logs under `logs/` and include an `analysis.md` summary.
- Update `honeypot.py` and `logger.py` (and add modules as needed) to implement the honeypot.

### Getting started
1. Implement your honeypot logic in `honeypot.py`.
2. Wire logging in `logger.py` and record results in `logs/`.
3. Summarize your findings in `analysis.md`.
4. Run from the repo root with `docker-compose up honeypot`.

## Design
An SSH honeypot built with Python and paramiko that simulates a real Ubuntu SSH server. It accepts all login attempts and drops attackers into a fake shell to observe their behavior.

## How It Works
1. Listens on port 22 and presents an OpenSSH 8.9 banner
2. Accepts any username/password combination and logs credentials
3. Provides a fake shell with commands: ls, cat, whoami, id, pwd, cd, uname, hostname, ps, env, echo
4. Simulates a fake filesystem with enticing files like `passwords.txt`
5. Logs everything to structured JSON files

## Logging
All logs are stored in `/app/logs/`:

- `auth_attempts.jsonl` — every username/password tried
- `commands.jsonl` — every command executed in the fake shell
- `alerts.jsonl` — suspicious activity (download attempts, destructive commands, brute-force)
- `connections.jsonl` — connection/disconnection events with duration
- `honeypot.log` — human-readable combined log

## Alerts
The honeypot detects and alerts on:

- Brute-force attempts (5+ auth failures from same IP)
- Download attempts (wget, curl)
- Destructive commands (rm, dd, mkfs)
- Code execution attempts (python, perl, gcc)

## Usage
```bash
docker-compose up honeypot
ssh root@localhost -p 2222
```