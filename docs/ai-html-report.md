# AI-Narrated HTML Security Report

> **Current implementation:** `scripts/generate_html_report.py` and `scripts/nisec_report/`.
> The report feature is optional and downstream of the Wazuh/Suricata evidence pipeline.

Turns NISec's existing evidence (`measure`, `hunt`, `correlate`) into one
self-contained HTML report: `evidence/report_<timestamp>.html`. Open it in
any browser — no server, no internet, no JS framework required.

Gemini writes **only the narrative paragraphs** (executive summary, attack
narrative, detection analysis, conclusion). Every number, timestamp, table,
chart, and MITRE ID comes directly from your own evidence files and is
rendered by Python — Gemini never sees or touches those values, and never
generates HTML.

```
measure / hunt / correlate evidence
        ↓
  evidence_parser.py         ← 100% deterministic, no AI
        ↓
  structured report context
        ↓
  ┌─────────────┬─────────────┐
  │ tables/charts│  Gemini     │
  │ (Python)     │  narrative  │
  └─────────────┴─────────────┘
        ↓
  html_renderer.py            ← escapes everything, including AI text
        ↓
  evidence/report_*.html
```

## Quick start

```powershell
.\nisec.ps1 report              # mock mode, zero API calls, works right now
.\nisec.ps1 report-test         # 13 offline tests, no network needed
.\nisec.ps1 report --dry-run    # see cost estimate without generating anything
.\nisec.ps1 report --force      # bypass the AI cache, still capped at 1 request

$env:GEMINI_API_KEY = "..."
$env:AI_REPORT_MODE = "gemini"
.\nisec.ps1 report              # the real thing — one Gemini call, ever, per report
```

`report` needs no Git Bash — it's pure Python. If you'd rather have zero
Python/AI dependency at all, `report-basic` still exists (bash + inline SVG
only, no narrative section).

## Install

Uses the same dependency as `correlate` — install once, both features work:

```bash
pip install -r scripts/requirements-correlate.txt --break-system-packages
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AI_REPORT_MODE` | `mock` | `mock` = no network calls. `gemini` = real API call. |
| `GEMINI_API_KEY` | *(unset)* | Required only for `gemini` mode. |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Cost-efficient model for report narration. |
| `GEMINI_MAX_REQUESTS_PER_RUN` | `1` | A report needs exactly one narrative — never one per alert/section/table. |
| `GEMINI_TIMEOUT_SECONDS` | `30` | Per-request timeout. |
| `AI_REPORT_CACHE_DIR` | `evidence/ai-cache` | Shared with `correlate`'s cache directory; keys are prefixed `report:` so they never collide. |

## Why one report costs at most one Gemini call

The entire evidence set (alerts, timeline, MITRE mapping, attack chain) is
aggregated into a single compact JSON context **before** any AI call — see
`ReportData.as_ai_context()`. Gemini is asked once to interpret that whole
context, not once per alert, per stage, or per table. Re-generating the
same report (same evidence, same prompt version) is a cache hit and costs
nothing.

## What happens when Gemini is unavailable

Every AI-authored section falls back to a clearly labeled placeholder
("AI analysis unavailable — showing fallback text.") while every
deterministic section — tables, charts, MITRE mapping, timeline — renders
exactly as it would with AI enabled. The report is never blocked on Gemini.

## Files

```
scripts/generate_html_report.py       CLI entry point
scripts/nisec_report/
    config.py                         env vars + defaults
    evidence_parser.py                measure/hunt/correlate evidence -> structured report data
    schema.py                         narrative-only system instruction + JSON schema
    gemini_client.py                  real API call (+ mock fixture)
    html_renderer.py                  self-contained HTML/CSS/SVG, escapes everything
    pipeline.py                       orchestration, cache, spend-limit enforcement
tests/test_report.py                  13 offline scenarios, zero network
```
