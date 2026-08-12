#!/usr/bin/env bash
# _alert-probe.sh — runs ON the Wazuh manager. Prints the FIRST alert matching
# <rule-id-regex> that is not older than <t0-epoch>, as:
#
#     <epoch>\t<rule-id>\t<description>
#
# Prints nothing if no such alert exists yet. Called in a poll loop by
# scripts/measure-detection.sh.
#
# WHY THIS IS A SEPARATE FILE
# The jq/date work runs natively on the manager rather than being quoted
# through `vagrant ssh -c "..."`, which keeps the quoting readable AND — the
# part that matters for the measurement — means every timestamp is produced by
# the manager's own clock. Comparing an alert time from one VM against a start
# time from another would fold VM clock skew into the reported latency.
set -uo pipefail

IDS="${1:?usage: _alert-probe.sh <rule-id-regex> <t0-epoch>}"
T0="${2:?usage: _alert-probe.sh <rule-id-regex> <t0-epoch>}"

ALERTS=/var/ossec/logs/alerts/alerts.json
[ -r "$ALERTS" ] || exit 0

# Only the tail is relevant: we are looking for something that fired seconds
# ago, and alerts.json grows quickly once the ET Open ruleset is live.
tail -n 5000 "$ALERTS" 2>/dev/null \
  | jq -r --arg ids "$IDS" '
      select(.rule.id | test("^(" + $ids + ")$"))
      | "\(.timestamp)\t\(.rule.id)\t\(.rule.description)"' 2>/dev/null \
  | while IFS=$'\t' read -r ts rid desc; do
      epoch="$(date -d "$ts" +%s 2>/dev/null)" || continue
      # alerts.json is append-ordered, so the first line at or after T0 is the
      # first alert this attack could have caused.
      if [ "$epoch" -ge "$T0" ]; then
        printf '%s\t%s\t%s\n' "$epoch" "$rid" "$desc"
        break
      fi
    done
