#!/usr/bin/env bash
# wazuh-server.sh — stands up the central control room.
#
# Two deployment paths (see deploy-docker/README.md):
#   WAZUH_DEPLOY=installer  (default) all-in-one installer -> systemd services
#   WAZUH_DEPLOY=docker               containerised stack via docker compose
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
WAZUH_DEPLOY="${WAZUH_DEPLOY:-installer}"

install_docker_if_needed() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[wazuh-server] installing Docker..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker vagrant || true
  fi
}

case "$WAZUH_DEPLOY" in
  docker)
    echo "[wazuh-server] DEPLOY MODE: docker"
    install_docker_if_needed
    sudo bash /vagrant/deploy-docker/up.sh
    ;;

  installer|*)
    echo "[wazuh-server] DEPLOY MODE: all-in-one installer"
    if sudo test -f /var/ossec/bin/wazuh-control; then
      echo "[wazuh-server] Wazuh already installed — skipping installer."
    else
      cd /root 2>/dev/null || cd /home/vagrant
      sudo curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
      # -a = all-in-one; -i = ignore hardware checks (labs are small)
      sudo bash ./wazuh-install.sh -a -i
      echo "[wazuh-server] ---------------------------------------------------------"
      echo "[wazuh-server] Dashboard: https://192.168.56.40"
      echo "[wazuh-server] Get the admin password with:"
      echo "  sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin"
      echo "[wazuh-server] ---------------------------------------------------------"
    fi
    # Docker is still installed here because the proposal specifies the Ubuntu
    # server runs containers, and the DVWA bonus target needs it.
    install_docker_if_needed
    ;;
esac

# --- custom manager rules/decoders (both modes; docker mounts them read-only) ---
if [ "$WAZUH_DEPLOY" != "docker" ] && [ -d /vagrant/config/wazuh-manager ]; then
  echo "[wazuh-server] installing custom rules/decoders..."
  sudo cp /vagrant/config/wazuh-manager/local_rules.xml   /var/ossec/etc/rules/local_rules.xml
  sudo cp /vagrant/config/wazuh-manager/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
  sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml \
                         /var/ossec/etc/decoders/local_decoder.xml 2>/dev/null || true
  sudo systemctl restart wazuh-manager || sudo /var/ossec/bin/wazuh-control restart
fi

# --- log retention (proposal: "store logs so they can be reviewed later") ---
if [ -x /vagrant/scripts/configure-retention.sh ]; then
  sudo bash /vagrant/scripts/configure-retention.sh || \
    echo "[wazuh-server] retention config skipped (indexer not ready yet)"
fi

# --- access control hardening (proposal NFR: only authorised users) ---
if [ -x /vagrant/scripts/harden-dashboard.sh ]; then
  sudo bash /vagrant/scripts/harden-dashboard.sh || \
    echo "[wazuh-server] hardening skipped"
fi

echo "[wazuh-server] done"
