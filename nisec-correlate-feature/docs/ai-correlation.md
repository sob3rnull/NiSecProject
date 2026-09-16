# AI-Assisted Attack Chain Correlation

Wazuh and Suricata remain fully responsible for detection. This module adds
one thing on top: it looks at alerts *already generated* by those two tools
and asks whether groups of them form a coherent attack sequence, using
Google's Gemini API for the semantic reasoning step only.

```
Existing alerts (alerts.json)
        ↓
Deterministic candidate grouping   ← no AI, no cost
        ↓
Deduplication + cache check        ← no AI, no cost, if seen before
        ↓
Gemini structured-output analysis  ← only for multi-event, uncached groups
        ↓
Attack chain + evidence report     → evidence/attack-correlation_*.md
```

It never replaces or overrides a Wazuh/Suricata alert — the raw
`alerts.json` on `wazuh-server` is untouched by this module.

## Install

```bash
pip install -r scripts/requirements-correlate.txt --break-system-packages
```

(Only needed on whichever machine actually runs `correlate` in `gemini`
mode. `mock` and `--dry-run` modes work without `google-genai` installed
at all, other than the standard library.)

## Quick start

```powershell
# Safe by default — mock mode, zero API calls, works right now:
.\nisec.ps1 correlate

# Offline unit tests (10 required scenarios) — no network, no key:
.\nisec.ps1 correlate-test

# See what WOULD be sent to Gemini, without sending anything:
.\nisec.ps1 correlate --dry-run

# The real thing, once GEMINI_API_KEY is set:
$env:GEMINI_API_KEY = "your-key-here"
$env:AI_CORRELATION_MODE = "gemini"
.\nisec.ps1 correlate
```

`correlate` is pure Python — it runs the same way on Windows, macOS, or
Linux and does **not** need Git Bash, unlike `healthcheck`/`test`/`measure`/
`seal`/`hunt`/`compare`/`score`.

## Configuration

All variables are optional; every default is the conservative (cheapest,
safest) choice.

| Variable | Default | Meaning |
|---|---|---|
| `AI_CORRELATION_MODE` | `mock` | `mock` = no network calls at all. `gemini` = real API calls. |
| `GEMINI_API_KEY` | *(unset)* | Required only for `gemini` mode. Never hard-coded. |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Cost-efficient model for structured classification. Only override to a stronger Flash model deliberately — never defaults to Pro. |
| `CORRELATION_WINDOW_SECONDS` | `300` | Alerts must fall within this time window of each other to even be *considered* related. |
| `GEMINI_MAX_REQUESTS_PER_RUN` | `10` | Hard ceiling per invocation. Once hit, remaining incidents keep their deterministic grouping with no AI analysis — the run never silently exceeds this. |
| `GEMINI_MAX_EVENTS_PER_REQUEST` | `50` | Caps how many deduplicated events go into a single candidate incident's prompt. |
| `GEMINI_TIMEOUT_SECONDS` | `30` | Per-request timeout. |
| `AI_CORRELATION_CACHE_DIR` | `evidence/ai-cache` | Where correlation results are cached, keyed by a fingerprint of (prompt version + sorted event IDs). |

## Why this doesn't burn API credit

1. **Deterministic grouping happens first.** 500 alerts typically become a
   handful of candidate incidents — most alerts are isolated and never
   reach Gemini at all (`scripts/nisec_correlate/grouping.py`).
2. **Isolated alerts are skipped entirely.** A single unrelated alert with
   no related event never triggers a request.
3. **Identical candidate groups are cached.** Re-running `correlate`
   during development costs zero additional calls once a group has been
   analyzed once (`scripts/nisec_correlate/cache.py`).
4. **`--dry-run` makes the network unreachable by construction** — the
   code path that would call Gemini is never executed, only counted.
5. **`GEMINI_MAX_REQUESTS_PER_RUN` is enforced mid-run**, not just
   documented — hitting it stops new calls but keeps processing the rest
   with deterministic-only results.

## Files

```
scripts/correlate.py                    CLI entry point
scripts/nisec_correlate/
    config.py                           env var handling + defaults
    events.py                           fetch (live or --from-file) + normalize
    grouping.py                         deterministic candidate correlation
    dedup.py                            fingerprinting + dedup + cache keys
    cache.py                            evidence/ai-cache/ persistence
    schema.py                           system instruction + JSON schema
    gemini_client.py                    real API call (+ mock fixture logic)
    pipeline.py                         orchestration + spend-limit enforcement
    report.py                           evidence/attack-correlation_*.md writer
scripts/requirements-correlate.txt      google-genai dependency
tests/test_correlate.py                 10 offline scenarios, zero network
evidence/sample-alerts.json             sample data for --from-file demos
```

## Testing without a live lab

`--from-file` accepts a JSON array or JSONL file shaped like Wazuh's
`alerts.json` and skips the live `wazuh-server` VM entirely — useful for
demos, CI, or when your machine can't run the full lab:

```powershell
python scripts/correlate.py --mock --from-file evidence/sample-alerts.json
```

## What this is not

It is not an autonomous SOC agent. Gemini has no tool access, cannot
execute commands, cannot modify the lab, and cannot trigger a response.
Its only output is a structured JSON opinion about already-collected
evidence, which is written to a report for a human to read. If the API
is unavailable for any reason, the deterministic correlation and the rest
of the NISec pipeline continue to work exactly as before this feature
existed.
