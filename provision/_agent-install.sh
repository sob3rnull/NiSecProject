#!/usr/bin/env bash
# _agent-install.sh — shared helper: install + register a Wazuh agent.
# Sourced by monitored-server.sh and client.sh.
set -euo pipefail

# Official Wazuh signing key fingerprint. Verifying this matters: without it we
# would trust whatever bytes the URL happened to return, which is exactly the
# supply-chain weakness a security-monitoring project should not model badly.
# Cross-check at https://documentation.wazuh.com (GPG key section).
WAZUH_GPG_FPR="0DCFCA5547B19D2A6099506096B3EE5F29111145"

install_agent() {
  local server_ip="$1" agent_name="$2"

  # `dpkg -l` also succeeds for a removed-but-not-purged package (state 'rc'),
  # which would make us skip the install and then fail on systemctl. Query the
  # actual status instead.
  if [ "$(dpkg-query -W -f='${db:Status-Status}' wazuh-agent 2>/dev/null || true)" = "installed" ]; then
    echo "[agent] wazuh-agent already installed."
  else
    echo "[agent] adding Wazuh apt repo..."
    local keyring=/usr/share/keyrings/wazuh.gpg
    # -f so an HTTP error page is never piped into gpg as if it were a key.
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | sudo gpg --no-default-keyring --keyring "gnupg-ring:${keyring}" --import
    sudo chmod 644 "$keyring"

    # --- verify the imported key matches the expected fingerprint ---
    local actual
    actual="$(gpg --no-default-keyring --keyring "$keyring" --list-keys \
              --with-colons 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
    if [ "$actual" = "$WAZUH_GPG_FPR" ]; then
      echo "[agent] GPG fingerprint verified: ${actual}"
    else
      echo "[agent] WARNING: Wazuh GPG fingerprint mismatch!" >&2
      echo "[agent]   expected: ${WAZUH_GPG_FPR}" >&2
      echo "[agent]   actual  : ${actual:-<none>}" >&2
      echo "[agent] Continuing (lab only). In production, STOP HERE." >&2
    fi

    echo "deb [signed-by=${keyring}] https://packages.wazuh.com/4.x/apt/ stable main" \
      | sudo tee /etc/apt/sources.list.d/wazuh.list
    sudo apt-get update -y
    echo "[agent] installing agent (server=${server_ip}, name=${agent_name})..."
    sudo WAZUH_MANAGER="${server_ip}" WAZUH_AGENT_NAME="${agent_name}" \
      apt-get install -y wazuh-agent
  fi

  sudo systemctl daemon-reload
  sudo systemctl enable wazuh-agent
  sudo systemctl restart wazuh-agent
  echo "[agent] ${agent_name} registered to ${server_ip}."
}
