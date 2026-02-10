#!/usr/bin/env bash
set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
CONTAINER="2_network_webapp"
KNOCK_CONTAINER="2_network_port_knocking"

# Copy client into the Docker network
docker cp knock_client.py "$CONTAINER":/tmp/ 2>/dev/null || true

echo "[1/3] Before knocking — verify port is blocked"
docker exec "$CONTAINER" python3 /tmp/knock_client.py --target "$TARGET_IP" --check

echo ""
echo "[2/3] Sending knock sequence: $SEQUENCE"
docker exec "$CONTAINER" python3 /tmp/knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE"

echo ""
echo "[3/3] Server logs — verify knocks received and port opened"
sleep 1
docker logs "$KNOCK_CONTAINER" --tail 10