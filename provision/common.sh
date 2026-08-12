#!/usr/bin/env bash
# common.sh — runs on EVERY VM before its role-specific script. Idempotent.
set -euo pipefail

echo "[common] provisioning ${NODE_NAME:-unknown} (zone: ${SECURITY_ZONE:-n/a})"

# --- record the security zone so it's visible on the box + in logs --------
echo "${SECURITY_ZONE:-unassigned}" | sudo tee /etc/nisec-zone >/dev/null

# --- /etc/hosts so nodes can talk by name ---------------------------------
add_host() {
  local ip="$1" name="$2"
  grep -q "[[:space:]]${name}\$" /etc/hosts || echo "${ip} ${name}" | sudo tee -a /etc/hosts >/dev/null
}
add_host "${WAZUH_SERVER_IP:-192.168.56.40}" wazuh-server
add_host "${MONITORED_IP:-192.168.56.20}"    monitored
add_host "${CLIENT_IP:-192.168.56.30}"       client
add_host "${KALI_IP:-192.168.56.10}"         kali

# --- base tooling (kali's own script handles its apt work) ----------------
if ! grep -qi kali /etc/os-release; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y curl gnupg apt-transport-https ca-certificates \
                          net-tools iputils-ping jq
fi

echo "[common] done"
