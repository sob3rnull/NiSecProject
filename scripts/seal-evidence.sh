#!/usr/bin/env bash
# seal-evidence.sh — hash every evidence file and record the manifest.
#
# `configure-retention.sh` promises indices become "read-only, immutable
# (tamper evidence)" after 30 days. That claim covers alerts inside the
# indexer. It says nothing about the screenshots, logs and pcaps in evidence/,
# which are the artefacts actually submitted — and which sit in a directory
# anyone can edit.
#
# This closes that gap the way a real investigation would: hash the artefacts
# at collection time, keep the manifest, and re-verify before submission. If a
# marker or examiner asks "how do you know this screenshot is the one your test
# produced?", the answer is a hash recorded at the time rather than a promise.
#
#     bash scripts/seal-evidence.sh          # write/refresh the manifest
#     bash scripts/seal-evidence.sh --verify # re-check nothing changed
#
# HONEST LIMITATION, and state it if you cite this in the report: a manifest
# stored beside the files it protects proves *consistency*, not *authenticity*.
# Anyone who edits a file can re-run this and regenerate the manifest. Real
# tamper-evidence needs the digest somewhere the editor cannot reach — commit
# it to git, email it to yourself, or read the hash aloud on the demo
# recording. The manifest makes accidental change detectable and deliberate
# change require a second, visible step; do not claim more than that.
set -uo pipefail

cd "$(dirname "$0")/.."
EVIDENCE_DIR="evidence"
MANIFEST="${EVIDENCE_DIR}/MANIFEST.sha256"

if [ ! -d "$EVIDENCE_DIR" ]; then
  echo "no ${EVIDENCE_DIR}/ directory here" >&2
  exit 1
fi

hash_all() {
  # Skip the manifest itself and the .gitkeep placeholders.
  find "$EVIDENCE_DIR" -type f \
    ! -name 'MANIFEST.sha256' \
    ! -name '.gitkeep' \
    -print0 2>/dev/null \
  | sort -z \
  | xargs -0 -r sha256sum 2>/dev/null
}

if [ "${1:-}" = "--verify" ]; then
  if [ ! -f "$MANIFEST" ]; then
    echo "no manifest at ${MANIFEST} — run without --verify first" >&2
    exit 1
  fi
  echo "=== verifying evidence against ${MANIFEST} ==="
  # Ignore the manifest's own comment lines.
  if grep -v '^#' "$MANIFEST" | sha256sum -c --quiet - 2>/dev/null; then
    echo "OK — every recorded file still matches its hash."
  else
    echo
    echo "MISMATCH. A file changed, or is missing, since the manifest was written." >&2
    echo "That is not automatically bad — re-running a test legitimately changes" >&2
    echo "the evidence — but you should know WHICH file and WHY before submitting." >&2
    exit 1
  fi
  exit 0
fi

COUNT="$(hash_all | wc -l)"
if [ "$COUNT" -eq 0 ]; then
  echo "No evidence files yet. Run the tests first:"
  echo "  make attacks && make measure && make capture"
  exit 0
fi

{
  echo "# NISec evidence manifest"
  echo "# sealed: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "# files : ${COUNT}"
  echo "# verify: bash scripts/seal-evidence.sh --verify"
  hash_all
} > "$MANIFEST"

echo "sealed ${COUNT} evidence files -> ${MANIFEST}"
echo
echo "Commit this manifest to git now — that is what puts the digests somewhere"
echo "you cannot silently rewrite, and it timestamps them:"
echo "    git add ${MANIFEST} && git commit -m 'Seal evidence manifest'"
