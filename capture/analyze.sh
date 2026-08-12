#!/usr/bin/env bash
# analyze.sh <file.pcap> — quick text summary of a capture, for the report.
set -euo pipefail
PCAP="${1:?usage: analyze.sh <file.pcap>}"
[ -f "$PCAP" ] || { echo "no such file: $PCAP" >&2; exit 1; }

echo "=== $PCAP ==="
echo
echo "--- Capture summary ---"
capinfos -c -u -a -e "$PCAP" 2>/dev/null || tshark -r "$PCAP" -q -z io,stat,0

echo
echo "--- Top talkers (IPv4 conversations) ---"
tshark -r "$PCAP" -q -z conv,ip 2>/dev/null | head -20

echo
echo "--- Protocol breakdown ---"
tshark -r "$PCAP" -q -z io,phs 2>/dev/null | head -30

echo
echo "--- SYN packets without ACK (port-scan fingerprint) ---"
tshark -r "$PCAP" -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' 2>/dev/null | wc -l \
  | xargs -I{} echo "  {} SYN probes"

echo
echo "--- ICMP echo requests (ping-flood fingerprint) ---"
tshark -r "$PCAP" -Y 'icmp.type==8' 2>/dev/null | wc -l \
  | xargs -I{} echo "  {} echo requests"

echo
echo "--- Destination ports touched (top 15) ---"
tshark -r "$PCAP" -T fields -e tcp.dstport 2>/dev/null \
  | tr -d ' ' | grep -v '^$' | sort -n | uniq -c | sort -rn | head -15
