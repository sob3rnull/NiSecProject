#!/usr/bin/env bash
# monitored-server.sh — the protected target (Monitoring Zone).
# Installs: Wazuh agent, Suricata (IDS), tshark/Wireshark, Docker,
# FIM/rootcheck, and wires the agent to read Suricata's eve.json.
set -euo pipefail

WSIP="${WAZUH_SERVER_IP:-192.168.56.40}"
export DEBIAN_FRONTEND=noninteractive

# --- 1. Wazuh agent -------------------------------------------------------
source /vagrant/provision/_agent-install.sh
source /vagrant/provision/_ossec-merge.sh
install_agent "${WSIP}" "monitored"

# --- 2. Suricata (IDS mode) ----------------------------------------------
if ! command -v suricata >/dev/null 2>&1; then
  echo "[monitored] installing Suricata..."
  sudo add-apt-repository -y ppa:oisf/suricata-stable
  sudo apt-get update -y
  sudo apt-get install -y suricata
fi

IFACE="$(ip -o -4 addr show | awk '/192\.168\.56\./{print $2; exit}')"
IFACE="${IFACE:-eth1}"
echo "[monitored] Suricata will listen on ${IFACE}"

# Back up the genuinely-original yaml ONCE. Re-provisioning used to drop a new
# timestamped ".orig" every run, each a copy of the already-patched file.
if ! sudo test -f /etc/suricata/suricata.yaml.nisec-orig; then
  sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.nisec-orig 2>/dev/null || true
fi

# HOME_NET: the PROTECTED hosts only — deliberately NOT the whole 192.168.56.0/24.
# Stock suricata.yaml defines EXTERNAL_NET as "!$HOME_NET". Every attack in this
# lab originates from Kali (192.168.56.10), so if HOME_NET covered the whole /24
# then Kali would be "internal", EXTERNAL_NET would exclude it, and every rule
# written as `$EXTERNAL_NET -> $HOME_NET` — our SIDs 9000001-9000003 AND most of
# the ET Open ruleset — could never match. Listing just the assets we defend
# keeps the attacker external and the zone model honest.
HOME_NET="[${MONITORED_IP:-192.168.56.20},${CLIENT_IP:-192.168.56.30},${WAZUH_SERVER_IP:-192.168.56.40}]"
echo "[monitored] Suricata HOME_NET = ${HOME_NET} (attacker zone stays EXTERNAL)"
sudo sed -i "s#^\( *HOME_NET:\).*#\1 \"${HOME_NET}\"#" /etc/suricata/suricata.yaml || true

# Interface: only rewrite the FIRST '- interface:' occurrence, which belongs to
# the af-packet block. suricata.yaml also has '- interface:' under pcap/netmap/
# af-xdp; a global replace would rewrite those too (harmless but confusing).
sudo sed -i "0,/^\( *- interface:\).*/s//\1 ${IFACE}/" /etc/suricata/suricata.yaml || true

# --- 2a. Custom rules: register with suricata-update ----------------------
# CRITICAL: stock suricata.yaml lists ONLY 'suricata.rules' under rule-files,
# and suricata-update regenerates /var/lib/suricata/rules/. Simply copying a
# local.rules file there does NOTHING — it is never loaded.
# The supported mechanism is `suricata-update --local`, which MERGES our rules
# into the generated suricata.rules. That is what makes SIDs 9000001-9000003
# (our ping-flood and port-scan thresholds) actually fire.
LOCAL_RULES=/etc/suricata/rules/nisec-local.rules
if [ -f /vagrant/config/suricata/local.rules ]; then
  sudo mkdir -p /etc/suricata/rules
  sudo cp /vagrant/config/suricata/local.rules "$LOCAL_RULES"
  echo "[monitored] registered custom rules at ${LOCAL_RULES}"
fi

echo "[monitored] updating rulesets (ET Open + our local rules)..."
if [ -f "$LOCAL_RULES" ]; then
  sudo suricata-update --local "$LOCAL_RULES" \
    || echo "[monitored] suricata-update failed (offline?) — continuing"
else
  sudo suricata-update || echo "[monitored] suricata-update failed — continuing"
fi

# --- 2b. VERIFY the custom rules actually loaded -------------------------
# Silent failure here is the worst outcome: the demo runs, no alert appears,
# and nothing explains why. So we check explicitly and shout if it went wrong.
echo "[monitored] verifying custom SIDs are present in the compiled ruleset..."
MERGED=/var/lib/suricata/rules/suricata.rules
if sudo test -f "$MERGED" && sudo grep -q "sid:900000" "$MERGED"; then
  FOUND="$(sudo grep -c 'sid:900000' "$MERGED")"
  echo "[monitored] OK — ${FOUND} custom NISec signatures merged into the ruleset."
else
  cat >&2 <<'WARN'
[monitored] ############################################################
[monitored] WARNING: custom NISec signatures (SID 9000001-9000003) were
[monitored] NOT found in /var/lib/suricata/rules/suricata.rules.
[monitored] Your ping-flood / port-scan threshold rules will NOT fire.
[monitored] Fix with:
[monitored]   sudo suricata-update --local /etc/suricata/rules/nisec-local.rules
[monitored]   sudo systemctl restart suricata
[monitored] ############################################################
WARN
fi

# Config test before restart — catches a broken yaml before it takes the
# service down, which is much easier to debug now than mid-demo.
sudo suricata -T -c /etc/suricata/suricata.yaml -i "$IFACE" >/dev/null 2>&1 \
  && echo "[monitored] suricata config test passed" \
  || echo "[monitored] WARNING: suricata config test failed — check /etc/suricata/suricata.yaml"

sudo systemctl enable suricata
sudo systemctl restart suricata

# --- 3. Wireshark / tshark (packet-level evidence) ------------------------
if ! command -v tshark >/dev/null 2>&1; then
  echo "[monitored] installing tshark (headless Wireshark)..."
  echo "wireshark-common wireshark-common/install-setuid boolean true" \
    | sudo debconf-set-selections
  sudo apt-get install -y tshark
  sudo usermod -aG wireshark vagrant 2>/dev/null || true
fi

# --- 4. Agent reads eve.json (THE integration) ---------------------------
merge_ossec_snippet /vagrant/config/wazuh-agent/ossec.conf.snippet "suricata/eve.json"

# --- 5. FIM + rootcheck (malware / tampering coverage) -------------------
sudo mkdir -p /var/www/monitored
merge_ossec_snippet /vagrant/config/wazuh-agent/fim.conf.snippet "/var/www/monitored"

sudo systemctl restart wazuh-agent

# --- 6. Docker (for the DVWA bonus target) -------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "[monitored] installing Docker..."
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker vagrant || true
fi

echo "[monitored] done."
echo "[monitored]   capture packets : sudo bash /vagrant/capture/capture.sh 60"
echo "[monitored]   malware test    : sudo bash /vagrant/attacks/05_malware_fim_test.sh"
echo "[monitored]   DVWA (bonus)    : cd /vagrant/dvwa && ./up.sh"
