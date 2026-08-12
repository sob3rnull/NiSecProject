#!/usr/bin/env bash
# Bring up DVWA and wait for it to answer. Run on the monitored server.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not installed. Run provision/monitored-server.sh first." >&2
  exit 1
fi

# Support both `docker compose` (v2) and legacy `docker-compose`.
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

echo "[dvwa] starting container..."
sudo $DC up -d

echo "[dvwa] waiting for http://localhost/ ..."
for i in {1..30}; do
  if curl -s -o /dev/null -w '%{http_code}' http://localhost/ | grep -q '200\|302'; then
    echo "[dvwa] up! Browse to http://192.168.56.20/  (login: admin / password)"
    echo "[dvwa] First time: click 'Create / Reset Database' on the setup page."
    exit 0
  fi
  sleep 3
done
echo "[dvwa] did not become ready in time — check: sudo $DC logs" >&2
exit 1
