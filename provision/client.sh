#!/usr/bin/env bash
# client.sh — an ordinary monitored endpoint (Client Zone).
# Wazuh agent + File Integrity Monitoring. No Suricata here: this machine
# demonstrates that the system monitors MULTIPLE devices at once, which is a
# stated non-functional requirement in the proposal.
set -euo pipefail

source /vagrant/provision/_agent-install.sh
source /vagrant/provision/_ossec-merge.sh

install_agent "${WAZUH_SERVER_IP:-192.168.56.40}" "client"

sudo mkdir -p /var/www/monitored
merge_ossec_snippet /vagrant/config/wazuh-agent/fim.conf.snippet "/var/www/monitored"
sudo systemctl restart wazuh-agent

echo "[client] done"
