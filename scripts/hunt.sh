#!/usr/bin/env bash
# hunt.sh — Automated Threat Hunt Report
#
# After `make attacks && make measure`, this script reads the live alerts.json
# from the Wazuh manager and produces a structured Threat Hunt Report in
# evidence/. The report includes:
#
#   • Executive summary  (alert count, time window, unique rules fired)
#   • Chronological event timeline  (first 30 events, all fields)
#   • MITRE ATT&CK technique mapping  for every rule ID that fired
#   • Per-technique remediation advice
#   • Rule frequency breakdown  (which rule dominated the attack noise)
#   • SHA-256 self-hash  (included at the end for the evidence chain)
#
# Usage:
#   make hunt                              # last 2 hours of alerts
#   HUNT_HOURS=6 make hunt                 # wider time window
#   bash scripts/hunt.sh --since 1726400000  # explicit Unix epoch cutoff
#
# Requires: wazuh-server VM up, jq installed on that VM (it is — wazuh ships it).
#
set -uo pipefail
cd "$(dirname "$0")/.."

EVIDENCE_DIR="evidence"
mkdir -p "$EVIDENCE_DIR"
OUT="${EVIDENCE_DIR}/threat-hunt_$(date +%Y%m%d_%H%M%S).md"
ALERTS=/var/ossec/logs/alerts/alerts.json

HUNT_HOURS="${HUNT_HOURS:-2}"

# -- optional --since <epoch> override (e.g. from the last measure run's T0) --
SINCE_EPOCH=""
if [[ "${1:-}" == "--since" && -n "${2:-}" ]]; then
  SINCE_EPOCH="$2"
fi

c_ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
c_bad()  { printf '\033[31m%s\033[0m\n' "$1"; }
c_info() { printf '  %s\n' "$1"; }

# Run a command on the wazuh-server VM (same pattern as measure-detection.sh).
# Strip CRLF so arithmetic never breaks on Windows hosts.
mgr() { vagrant ssh wazuh-server -c "$1" 2>/dev/null | tr -d '\r'; }

echo "############################################################"
echo "# NISec Threat Hunt Report"
echo "# output -> ${OUT}"
echo "############################################################"
echo

# ---------------------------------------------------------------------------
# 1. Determine the hunt window
# ---------------------------------------------------------------------------
if [[ -z "$SINCE_EPOCH" ]]; then
  SINCE_EPOCH="$(mgr "date -d '-${HUNT_HOURS} hours' +%s" 2>/dev/null)"
fi

if ! [[ "${SINCE_EPOCH:-}" =~ ^[0-9]+$ ]]; then
  c_bad "Cannot reach wazuh-server or read its clock."
  c_bad "Is the lab up?  Try: .\\nisec.ps1 healthcheck"
  exit 1
fi

SINCE_HUMAN="$(mgr "date -d @${SINCE_EPOCH} '+%Y-%m-%d %H:%M:%S'")"
NOW_HUMAN="$(mgr  "date '+%Y-%m-%d %H:%M:%S'")"

c_info "window: ${SINCE_HUMAN} → ${NOW_HUMAN}"

# ---------------------------------------------------------------------------
# 2. Pull alert data from the manager via jq (single clock — no VM skew)
# ---------------------------------------------------------------------------
c_info "querying alerts.json on wazuh-server..."

# Total alerts in window
TOTAL="$(mgr "sudo tail -n 20000 ${ALERTS} 2>/dev/null \
  | jq -r --argjson t0 ${SINCE_EPOCH} \
      'select(
         (.timestamp | sub(\"[.].*\$\";\"\") | strptime(\"%Y-%m-%dT%H:%M:%S\") | mktime)
         >= \$t0
       ) | .rule.id' 2>/dev/null \
  | wc -l")"
TOTAL="${TOTAL:-0}"

c_info "found ${TOTAL} alerts in window"

if [[ "$TOTAL" -eq 0 ]]; then
  c_bad "No alerts in the last ${HUNT_HOURS}h."
  c_bad "Run 'make attacks && make measure' first, then 'make hunt'."
  c_bad "Or widen the window: HUNT_HOURS=24 make hunt"
  exit 0
fi

# Full alert details as TSV: timestamp, rule_id, description, level, agent, srcip
# We cap at 20000 tail lines for speed on a busy manager.
ALERT_TSV="$(mgr "sudo tail -n 20000 ${ALERTS} 2>/dev/null \
  | jq -r --argjson t0 ${SINCE_EPOCH} \
      'select(
         (.timestamp | sub(\"[.].*\$\";\"\") | strptime(\"%Y-%m-%dT%H:%M:%S\") | mktime)
         >= \$t0
       )
       | [
           .timestamp,
           .rule.id,
           (.rule.description  // \"(no description)\"),
           (.rule.level        // \"?\"),
           (.agent.name        // \"unknown\"),
           (.data.srcip // .data.src_ip // \"—\")
         ]
       | @tsv' 2>/dev/null")"

UNIQUE_RULES="$(printf '%s\n' "$ALERT_TSV" | awk -F'\t' 'NF>=2 && $2!="" {print $2}' | sort -u)"
UNIQUE_RULE_COUNT="$(printf '%s\n' "$UNIQUE_RULES" | grep -c '[^[:space:]]' || echo 0)"

c_ok "  ${TOTAL} alerts | ${UNIQUE_RULE_COUNT} unique rule IDs | ${SINCE_HUMAN} → ${NOW_HUMAN}"

# ---------------------------------------------------------------------------
# 3. ATT&CK + remediation lookup  (keyed on Wazuh rule ID)
#    Returns pipe-delimited: tactic | tactic_id | technique_id | tech_name | remediation
# ---------------------------------------------------------------------------
attack_lookup() {
  local rid="$1"
  case "$rid" in
    100120) echo "Discovery / Impact|TA0007 / TA0040|T1046 / T1498.001|Network Service Discovery / Direct Network Flood|\
Implement strict ingress/egress ACLs. Rate-limit ICMP with iptables/nftables. \
Block unsolicited SYN scans at the perimeter firewall. Consider deploying a port-knock \
or single-packet authorisation scheme for administrative ports." ;;

    100101) echo "Multiple (Suricata HIGH)|—|—|Suricata HIGH Severity Alert|\
Investigate the specific Suricata signature that triggered this rule (check \
alert.signature in Wazuh). Determine whether the traffic is genuine attack or \
a mis-tuned rule. If genuine, escalate — severity 1 in Suricata's own scheme \
means the ruleset author considered it critical." ;;

    100102) echo "Multiple (Suricata MEDIUM)|—|—|Suricata MEDIUM Severity Alert|\
Review the triggering signature. If this fires on legitimate traffic (e.g. a \
scheduled scanner), add a threshold or whitelist the source in suricata.yaml \
to prevent alert fatigue obscuring real attacks." ;;

    100110) echo "Initial Access|TA0001|T1190|Exploit Public-Facing Application|\
Patch the web application immediately — check the CVE referenced in the Suricata \
signature. Enable a WAF (ModSecurity or NGINX rate-limiting). Review web server \
access logs for POST bodies that indicate successful exploitation (HTTP 200 on \
a suspicious path)." ;;

    100200) echo "Command and Control|TA0011|T1105|Ingress Tool Transfer|\
Audit the monitored directory for unexpected files. Remove any dropped payload \
immediately. Check for persistence (crontab -l, systemctl list-units, /etc/rc.local). \
Identify the delivery vector — was the file written by a web process, SSH session, \
or another means?" ;;

    100201) echo "Persistence|TA0003|T1554|Compromise Host Software Binary|\
Compare binary checksums: dpkg -V (Debian) or rpm -Va (RHEL). Reinstall the \
affected package from the official repository without rebooting if possible. \
Audit /var/log/auth.log for the session that performed the modification. \
Consider immutable filesystem flags (chattr +i) on critical binaries." ;;

    100202) echo "Impact|TA0040|T1486|Data Encrypted for Impact (Ransomware-like)|\
ISOLATE the host immediately — pull its network cable (or: vagrant halt monitored). \
Do NOT reboot; memory may hold decryption keys. Snapshot the VM disk for forensics \
before any recovery attempt. Restore files from an offline, tested backup. \
Identify the initial access vector (phishing? unpatched service?) before reconnecting." ;;

    5710|5712|5716|5720|100002) echo "Credential Access|TA0006|T1110.001|Brute Force: Password Guessing (SSH)|\
Enforce SSH key-based authentication and disable PasswordAuthentication in sshd_config. \
Implement account lockout (pam_faillock or failregex in fail2ban). Move SSH to a \
non-standard port to reduce automated scan noise. Wazuh active-response can auto-block \
brute-forcing IPs — enable with: make active-response." ;;

    86601) echo "Multiple|—|—|Suricata Base Alert|\
This is the Wazuh built-in Suricata parent rule. A custom rule above it (100101 / \
100102 / 100120) should have escalated it. If you see bare 86601 alerts, check \
that your local_rules.xml is loaded: sudo wazuh-logtest on the manager." ;;

    550|554) echo "Impact / Persistence|TA0040 / TA0003|T1486 / T1554|File Integrity Violation|\
Check /var/ossec/logs/ossec.log for the exact path that changed. Determine what \
process made the change (ausearch -f <path> if auditd is running). If unauthorised, \
restore from backup and investigate the session that made the change." ;;

    *) echo "Unknown|—|—|Rule ${rid}|\
Review this rule in the Wazuh manager rule set: /var/ossec/ruleset/rules/ and \
/var/ossec/etc/rules/local_rules.xml. Cross-reference the alert description with \
the MITRE ATT&CK technique that best fits." ;;
  esac
}

# ---------------------------------------------------------------------------
# 4. Write the report
# ---------------------------------------------------------------------------
{
  printf '# 🔍 Threat Hunt Report\n\n'
  printf '**Generated by** `scripts/hunt.sh`  \n'
  printf '**Report time:** %s  \n' "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '**Hunt window:** %s → %s  \n' "$SINCE_HUMAN" "$NOW_HUMAN"
  printf '**Data source:** `%s` on `wazuh-server`\n\n' "$ALERTS"
  printf '---\n\n'

  # ---- Executive Summary ----
  printf '## Executive Summary\n\n'
  printf '| Metric | Value |\n'
  printf '|---|---|\n'
  printf '| Total alerts in window | **%s** |\n' "$TOTAL"
  printf '| Unique rule IDs fired | **%s** |\n' "$UNIQUE_RULE_COUNT"
  printf '| Hunt window (hours) | %s |\n' "$HUNT_HOURS"
  printf '| Rule IDs observed | `%s` |\n\n' "$(printf '%s\n' "$UNIQUE_RULES" | tr '\n' ' ')"
  printf '---\n\n'

  # ---- Timeline ----
  printf '## Event Timeline\n\n'
  printf '> Chronological (oldest first). Capped at 30 events for readability.\n> '
  printf 'Full data remains in `alerts.json` on the manager.\n\n'
  printf '| Timestamp | Rule ID | Level | Agent | Source IP | Description |\n'
  printf '|---|---|---|---|---|---|\n'
  printf '%s\n' "$ALERT_TSV" | sort | head -n 30 \
    | while IFS=$'\t' read -r ts rid desc lvl agent srcip; do
        # jq output order: timestamp, rule.id, rule.description, rule.level, agent.name, data.srcip
        # Table header:    Timestamp | Rule ID  | Level | Agent | Source IP | Description
        printf '| %s | %s | %s | %s | %s | %s |\n' \
          "${ts:0:19}" "$rid" "$lvl" "$agent" "$srcip" "$desc"
      done
  printf '\n---\n\n'

  # ---- ATT&CK Mapping ----
  printf '## MITRE ATT&CK Mapping\n\n'
  printf '| Rule ID | Alert Count | Tactic | Technique ID | Technique Name |\n'
  printf '|---|---|---|---|---|\n'
  while IFS= read -r rid; do
    [[ -z "$rid" ]] && continue
    count="$(printf '%s\n' "$ALERT_TSV" \
      | awk -F'\t' -v r="$rid" '$2==r{c++}END{print c+0}')"
    IFS='|' read -r tactic tactic_id tech_id tech_name _ \
      <<< "$(attack_lookup "$rid")"
    printf '| %s | %s× | %s | %s | %s |\n' \
      "$rid" "$count" "$tactic" "$tech_id" "$tech_name"
  done <<< "$UNIQUE_RULES"
  printf '\n---\n\n'

  # ---- Remediation ----
  printf '## Remediation Advice\n\n'
  while IFS= read -r rid; do
    [[ -z "$rid" ]] && continue
    IFS='|' read -r tactic tactic_id tech_id tech_name remediation \
      <<< "$(attack_lookup "$rid")"
    printf '### Rule %s — %s\n\n' "$rid" "$tech_name"
    printf '**Tactic:** %s  |  **Technique:** %s\n\n' "$tactic" "$tech_id"
    printf '%s\n\n' "$remediation"
  done <<< "$UNIQUE_RULES"
  printf '---\n\n'

  # ---- Frequency Breakdown ----
  printf '## Rule Frequency Breakdown\n\n'
  printf '| Rule ID | Alert Count | %% of total |\n'
  printf '|---|---|---|\n'
  printf '%s\n' "$ALERT_TSV" \
    | awk -F'\t' -v total="$TOTAL" '
        NF>=2 { count[$2]++ }
        END {
          for (r in count)
            printf "| %s | %d | %.1f%% |\n", r, count[r], (count[r]/total)*100
        }' \
    | sort -t'|' -k3 -rn
  printf '\n---\n\n'

  # ---- Method ----
  printf '## Method\n\n'
  printf '- Alert data queried from `%s` on `wazuh-server` via `jq`.\n' "$ALERTS"
  printf '- Window cutoff (T0 = %s) applied on the manager — single clock, no VM skew.\n' "$SINCE_EPOCH"
  echo '- Timeline capped at 30 events; full data remains in `alerts.json`.'
  echo '- ATT&CK mapping is static, derived from `config/wazuh-manager/local_rules.xml`.'
  echo '- False negatives (missed attacks) are in the evasion report (`make evasion`).'
  echo

} > "$OUT"

# Append self-hash AFTER the file is complete
SELF_HASH="$(sha256sum "$OUT" 2>/dev/null | awk '{print $1}')"
{
  printf '---\n\n'
  printf '## Evidence Integrity\n\n'
  printf '```\n'
  printf 'SHA-256: %s  %s\n' "$SELF_HASH" "$(basename "$OUT")"
  printf 'Sealed:  %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
  printf '```\n\n'
  printf '> Run `make seal` to include this file in the tamper-evident evidence manifest.\n'
} >> "$OUT"

echo
c_ok "Threat hunt report -> ${OUT}"
printf '  alerts analysed : %s\n' "$TOTAL"
printf '  unique rule IDs : %s\n' "$UNIQUE_RULE_COUNT"
printf '  hunt window     : %sh  (%s → %s)\n' "$HUNT_HOURS" "$SINCE_HUMAN" "$NOW_HUMAN"
