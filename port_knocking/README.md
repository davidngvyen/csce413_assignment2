## Port Knocking Starter Template

This directory is a starter template for the port knocking portion of the assignment.

### What you need to implement
- Pick a protected service/port (default is 2222).
- Define a knock sequence (e.g., 1234, 5678, 9012).
- Implement a server that listens for knocks and validates the sequence.
- Open the protected port only after a valid sequence.
- Add timing constraints and reset on incorrect sequences.
- Implement a client to send the knock sequence.

### Getting started
1. Implement your server logic in `knock_server.py`.
2. Implement your client logic in `knock_client.py`.
3. Update `demo.sh` to demonstrate your flow.
4. Run from the repo root with `docker compose up port_knocking`.

### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```

## Design
A port knocking system that hides services from port scanners. The protected port is blocked by default via iptables and only opens when the correct sequence of TCP connections is received within a timing window.

## How It Works
1. Server listens on knock ports (default: 1234, 5678, 9012)
2. Client sends TCP connections to each port in order
3. Server tracks per-IP progress through the sequence
4. On correct sequence within 10s window, iptables ACCEPT rule is added for that IP
5. Port auto-closes after 30 seconds

## Files
- `knock_server.py` — Server with iptables integration and per-IP tracking
- `knock_client.py` — Client that sends the knock sequence
- `demo.sh` — Automated demo script

## Usage

# Server (runs inside Docker with NET_ADMIN capability)
python3 knock_server.py --sequence 1234,5678,9012 --protected-port 2222

# Client
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012

# Demo (from repo root)
bash port_knocking/demo.sh 172.20.0.40