#!/usr/bin/env bash
# _ossec-merge.sh — helper: insert an <ossec_config> snippet into ossec.conf
# once, before the final closing tag. Sourced by the role scripts.
set -euo pipefail

# merge_ossec_snippet <snippet-file> <unique-grep-marker>
merge_ossec_snippet() {
  local snippet="$1" marker="$2"
  local conf=/var/ossec/etc/ossec.conf

  if ! sudo test -f "$conf"; then
    echo "[ossec-merge] $conf not found — is the agent installed?" >&2
    return 1
  fi
  if sudo grep -q "$marker" "$conf"; then
    echo "[ossec-merge] '${marker}' already present — skipping."
    return 0
  fi

  echo "[ossec-merge] inserting $(basename "$snippet")..."
  sudo python3 - "$conf" "$snippet" <<'PY'
import sys
conf, snippet = sys.argv[1], sys.argv[2]
data = open(conf).read()
add  = open(snippet).read().strip() + "\n"
marker = "</ossec_config>"
idx = data.rfind(marker)
if idx == -1:
    data = data + "\n" + add
else:
    # place after the last complete config block
    end = idx + len(marker)
    data = data[:end] + "\n\n" + add + data[end:]
open(conf, "w").write(data)
print("  inserted")
PY
}
