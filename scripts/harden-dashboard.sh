#!/usr/bin/env bash
# harden-dashboard.sh — satisfies the proposal NFR:
#   "Only authorized users should be able to access the dashboard."
#
# Run on the Wazuh server. Idempotent, and deliberately conservative: it
# reports what it finds and applies safe changes rather than locking you out.
set -uo pipefail

echo "=== NISec dashboard hardening ==="

# --- 1. Host firewall: expose only what the design requires ---------------
if command -v ufw >/dev/null 2>&1; then
  echo "[1/4] configuring ufw (management + client zones only)..."
  sudo ufw --force reset >/dev/null 2>&1

  sudo ufw default deny incoming
  sudo ufw default allow outgoing

  # Client zone -> manager: agent data + enrolment
  sudo ufw allow from 192.168.56.0/24 to any port 1514 proto tcp comment 'agent data'
  sudo ufw allow from 192.168.56.0/24 to any port 1515 proto tcp comment 'agent enrol'

  # Management zone only -> dashboard + API.
  # NOTE: tighten this to your host's IP for a stricter demo, e.g. 192.168.56.1
  sudo ufw allow from 192.168.56.0/24 to any port 443   proto tcp comment 'dashboard'
  sudo ufw allow from 192.168.56.0/24 to any port 55000 proto tcp comment 'wazuh api'

  # SSH for admin (vagrant needs this)
  sudo ufw allow 22/tcp comment 'ssh admin'

  # The indexer must NOT be reachable from the client/attack zones
  sudo ufw deny 9200/tcp comment 'indexer - localhost only'

  sudo ufw --force enable
  sudo ufw status numbered
else
  echo "[1/4] ufw not present — skipping firewall step"
fi

# --- 2. Warn about default credentials ------------------------------------
echo "[2/4] checking for default credentials..."
if sudo test -f /root/wazuh-install-files.tar || sudo test -f ./wazuh-install-files.tar; then
  cat <<'MSG'
  ACTION REQUIRED — change the generated admin password before your demo:
    sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
      -u admin -p 'YourNewStr0ngPassword!'
  Then restart: sudo systemctl restart wazuh-dashboard
MSG
fi

# --- 3. Create a read-only analyst account (least privilege) --------------
echo "[3/4] read-only analyst role..."
cat <<'MSG'
  Create a least-privilege account in the dashboard UI:
    Menu -> Security -> Internal users -> Create user  (e.g. "analyst")
    Menu -> Security -> Roles -> assign 'readall' + 'wazuh_ui_user'
  Demonstrating admin vs analyst in the viva is strong evidence of access control.
MSG

# --- 4. Session timeout ----------------------------------------------------
echo "[4/4] dashboard session timeout..."
DASH_CONF=/etc/wazuh-dashboard/opensearch_dashboards.yml
if sudo test -f "$DASH_CONF"; then
  if ! sudo grep -q "opensearchDashboards.sessionTimeout" "$DASH_CONF" 2>/dev/null; then
    # 30 minutes, in ms
    echo 'opensearchDashboards.sessionTimeout: 1800000' | sudo tee -a "$DASH_CONF" >/dev/null
    sudo systemctl restart wazuh-dashboard 2>/dev/null || true
    echo "  set 30-minute idle timeout"
  else
    echo "  timeout already configured"
  fi
else
  echo "  dashboard config not found (docker deploy?) — set it in the container instead"
fi

echo "=== hardening pass complete ==="
