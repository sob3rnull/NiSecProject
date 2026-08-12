#!/usr/bin/env bash
# enable-active-response.sh — turn on automatic blocking (step 7 of the alert
# lifecycle). Run ON the Wazuh server:  make active-response
#
# Deliberately a separate, manual step rather than part of provisioning: this
# control writes firewall DROP rules in response to log events, and you want
# that switched on when you choose, not while you are demonstrating something
# else. Capture your detection evidence first.
set -euo pipefail

SNIPPET=/vagrant/config/wazuh-manager/active-response.xml.snippet
CONF=/var/ossec/etc/ossec.conf

if ! sudo test -f "$CONF"; then
  echo "[active-response] $CONF not found — is this the Wazuh server?" >&2
  exit 1
fi
if ! [ -f "$SNIPPET" ]; then
  echo "[active-response] $SNIPPET not found — is /vagrant mounted?" >&2
  exit 1
fi

# shellcheck disable=SC1091
source /vagrant/provision/_ossec-merge.sh

if merge_ossec_snippet "$SNIPPET" "nisec-firewall-drop"; then
  echo "[active-response] restarting the manager..."
  sudo systemctl restart wazuh-manager || sudo /var/ossec/bin/wazuh-control restart
  echo
  echo "[active-response] ENABLED."
  echo "  Blocks on : rule 5712 (SSH brute force), rule 100101 (high-severity Suricata)"
  echo "  Duration  : 180s, self-lifting"
  echo "  Never     : 127.0.0.1, 192.168.56.1 (your host), 192.168.56.40"
  echo
  echo "  Verify after triggering a brute-force test:"
  echo "    sudo tail -20 /var/ossec/logs/active-responses.log"
  echo "    vagrant ssh monitored -c 'sudo iptables -L INPUT -n | head'"
  echo
  echo "  To measure what it bought you, compare \`make measure\` before/after."
  echo "  To disable: remove the nisec-firewall-drop block from ${CONF} and restart."
fi
