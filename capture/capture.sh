#!/usr/bin/env bash
# capture.sh [seconds] [bpf-filter] — headless packet capture with tshark.
# Run on the monitored server while attacks run from Kali.
set -euo pipefail

DURATION="${1:-60}"
FILTER="${2:-}"
IFACE="$(ip -o -4 addr show | awk '/192\.168\.56\./{print $2; exit}')"
IFACE="${IFACE:-eth1}"
OUTDIR="/vagrant/evidence/pcaps"
mkdir -p "$OUTDIR"
OUT="${OUTDIR}/capture_$(date +%Y%m%d_%H%M%S).pcap"

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark not installed. Run: sudo apt-get install -y tshark" >&2
  exit 1
fi

echo "[capture] interface : ${IFACE}"
echo "[capture] duration  : ${DURATION}s"
echo "[capture] filter    : ${FILTER:-<none>}"
echo "[capture] output    : ${OUT}"
echo "[capture] --- run your attack from Kali now ---"

if [ -n "$FILTER" ]; then
  sudo tshark -i "$IFACE" -a duration:"$DURATION" -w "$OUT" -f "$FILTER"
else
  sudo tshark -i "$IFACE" -a duration:"$DURATION" -w "$OUT"
fi

# Best effort: /vagrant is a VirtualBox shared folder, which does not support
# chmod. Under `set -e` a failure here would abort AFTER a successful capture
# and swallow the "where is my file" message, which is the worst moment to die.
sudo chmod 644 "$OUT" 2>/dev/null || true
echo "[capture] saved: ${OUT}  ($(du -h "$OUT" | cut -f1))"
echo "[capture] analyse with: bash /vagrant/capture/analyze.sh ${OUT}"
