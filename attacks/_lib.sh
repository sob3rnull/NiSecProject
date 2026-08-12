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
mkdir -p "$LOGDIR" 2>/dev/null || LOGDIR="/tmp/nisec-logs" && mkdir -p "$LOGDIR"

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(_ts)] $*"; }

# run_logged <label> <command...> : echo, run, and tee output to a log file.
# Returns the command's own exit status (not tee's), and never aborts the
# caller — the caller decides what a non-zero status means.
run_logged() {
  local label="$1"; shift
  local logfile="${LOGDIR}/${label}_$(date +%Y%m%d_%H%M%S).log"
  local rc=0
  log "=== ${label} -> ${TARGET} ==="
  log "cmd: $*"
  log "log: ${logfile}"
  { echo "# $(_ts)  $*"; "$@"; } > >(tee "$logfile") 2>&1 || rc=$?
  wait
  log "=== ${label} done (exit ${rc}) ==="
  return 0
}
