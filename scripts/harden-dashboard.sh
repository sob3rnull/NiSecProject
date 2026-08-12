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

  # Dashboard + API. NOTE: this is the whole lab subnet, INCLUDING the attack
  # zone — deliberately, because 06_unauthorized_access_test.sh has to reach
  # these ports to prove they answer 401. That means the firewall is not by
  # itself the zone boundary here; authentication is. Tighten to the management
  # host (e.g. 192.168.56.1) for a stricter demo, at the cost of that test
  # hanging on a dropped packet instead of returning 401.
  sudo ufw allow from 192.168.56.0/24 to any port 443   proto tcp comment 'dashboard'
  sudo ufw allow from 192.168.56.0/24 to any port 55000 proto tcp comment 'wazuh api'

  # SSH for admin (vagrant needs this)
  sudo ufw allow 22/tcp comment 'ssh admin'

  # The indexer must NOT be reachable from the client/attack zones.
  # CAVEAT: this only covers the installer deployment. Docker publishes ports
  # via its own iptables chain, which ufw does not filter — the compose file
  # therefore binds 9200 to 127.0.0.1 rather than relying on this rule.
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
# The session lifetime lives in the security plugin's namespace. There is no
# `opensearchDashboards.sessionTimeout` key — OpenSearch Dashboards validates
# its config strictly and refuses to start on an unknown key, so writing the
# wrong name here takes the dashboard down instead of hardening it.
TIMEOUT_KEY="opensearch_security.session.ttl"
if sudo test -f "$DASH_CONF"; then
  # Earlier versions of this script appended a key that does not exist. Strip
  # it, or the dashboard stays broken no matter what we add below.
  if sudo grep -q "^opensearchDashboards.sessionTimeout" "$DASH_CONF" 2>/dev/null; then
    echo "  removing invalid opensearchDashboards.sessionTimeout left by an earlier run"
    sudo sed -i '/^opensearchDashboards.sessionTimeout/d' "$DASH_CONF"
    sudo systemctl restart wazuh-dashboard >/dev/null 2>&1 || true
  fi
  if ! sudo grep -q "^${TIMEOUT_KEY}" "$DASH_CONF" 2>/dev/null; then
    sudo cp "$DASH_CONF" "${DASH_CONF}.nisec-bak"
    # 30 minutes, in ms. Leading newline in case the file lacks a trailing one.
    printf '\n%s: 1800000\nopensearch_security.cookie.ttl: 1800000\n' "$TIMEOUT_KEY" \
      | sudo tee -a "$DASH_CONF" >/dev/null

    # Verify rather than assume: a config the dashboard rejects is worse than
    # no timeout at all, so roll back if the service does not come back up.
    sudo systemctl restart wazuh-dashboard >/dev/null 2>&1 || true
    sleep 5
    if sudo systemctl is-active --quiet wazuh-dashboard; then
      echo "  set 30-minute idle timeout"
      sudo rm -f "${DASH_CONF}.nisec-bak"
    else
      echo "  WARNING: dashboard did not come back up — reverting the timeout" >&2
      sudo mv "${DASH_CONF}.nisec-bak" "$DASH_CONF"
      sudo systemctl restart wazuh-dashboard >/dev/null 2>&1 || true
      echo "  reverted. Check: sudo journalctl -u wazuh-dashboard -n 50" >&2
    fi
  else
    echo "  timeout already configured"
  fi
else
  echo "  dashboard config not found (docker deploy?) — set it in the container instead"
fi

echo "=== hardening pass complete ==="
