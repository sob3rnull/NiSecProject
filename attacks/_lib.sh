#!/usr/bin/env bash
# _lib.sh — shared helpers for attack scripts: target vars + timestamped logging.
#
# NOTE ON ERROR HANDLING
# Individual attack scripts DO want strict mode (a broken command should stop
# that script). The runner (run_all.sh) does NOT — several tools legitimately
# exit non-zero on their expected outcome:
#   * hydra  -> non-zero when no password is found (which is what we WANT)
#   * nikto  -> non-zero when it finds issues
#   * hping3 -> killed by `timeout`, so always non-zero
# run_all.sh therefore sets NISEC_RUNNER=1 before sourcing, which keeps
# `set -e` off so one expected failure can't abort the whole suite.
if [ "${NISEC_RUNNER:-0}" = "1" ]; then
  set -uo pipefail
else
  set -euo pipefail
fi

TARGET="${TARGET:-192.168.56.20}"          # monitored server
WAZUH_SERVER="${WAZUH_SERVER:-192.168.56.40}"
DVWA_URL="${DVWA_URL:-http://192.168.56.20}"

# Fall back to a local dir when /vagrant isn't mounted (e.g. running by hand).
DEFAULT_LOGDIR=/vagrant/evidence/logs
if [ ! -d /vagrant ]; then
  DEFAULT_LOGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/evidence/logs"
fi
LOGDIR="${LOGDIR:-$DEFAULT_LOGDIR}"
if ! mkdir -p "$LOGDIR" 2>/dev/null; then
  LOGDIR="/tmp/nisec-logs"
  mkdir -p "$LOGDIR"
fi

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(_ts)] $*"; }

# log_path <label> : the timestamped evidence-log path for <label>. One place
# owns the naming convention so every test's evidence lands the same way.
log_path() { echo "${LOGDIR}/${1}_$(date +%Y%m%d_%H%M%S).log"; }

# run_logged <label> <command...> : echo, run, and tee output to a log file.
# Returns the command's OWN exit status (not tee's) so the caller can decide
# what a non-zero status means. This matters: run_all.sh's PASS/done summary
# reads that status, and several tools here exit non-zero on their EXPECTED
# outcome — a caller that wants to ignore it appends `|| true`.
run_logged() {
  local label="$1"; shift
  local logfile; logfile="$(log_path "$label")"
  local rc=0
  log "=== ${label} -> ${TARGET} ==="
  log "cmd: $*"
  log "log: ${logfile}"
  { echo "# $(_ts)  $*"; "$@"; } > >(tee "$logfile") 2>&1 || rc=$?
  wait
  log "=== ${label} done (exit ${rc}) ==="
  return "$rc"
}
