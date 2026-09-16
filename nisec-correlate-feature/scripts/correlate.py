#!/usr/bin/env python3
"""
correlate.py — CLI for AI-assisted attack chain correlation.

    python3 scripts/correlate.py                 # uses AI_CORRELATION_MODE (default: mock)
    python3 scripts/correlate.py --dry-run        # zero API calls, ever — shows what WOULD happen
    python3 scripts/correlate.py --mock           # force mock mode regardless of env
    python3 scripts/correlate.py --force          # bypass cache, re-analyze every candidate group
    python3 scripts/correlate.py --hours 6        # widen the alert window (default: 2, like hunt.sh)
    python3 scripts/correlate.py --from-file evidence/sample-alerts.json   # skip live VM, use a file

Runs natively on Windows, macOS, or Linux — this file has no bash
dependency, unlike healthcheck/test/measure/seal/hunt/compare/score.
"""
from __future__ import annotations
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from nisec_correlate.config import load_config
from nisec_correlate.events import fetch_live, load_from_file
from nisec_correlate.pipeline import run_pipeline
from nisec_correlate.report import write_report


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-assisted attack chain correlation")
    parser.add_argument("--dry-run", action="store_true",
                         help="Show what would be sent to Gemini. Makes zero API calls.")
    parser.add_argument("--mock", action="store_true",
                         help="Force mock mode (no API calls) regardless of AI_CORRELATION_MODE.")
    parser.add_argument("--force", action="store_true",
                         help="Bypass the cache and re-analyze every candidate group.")
    parser.add_argument("--hours", type=int, default=2,
                         help="Alert window in hours when reading from the live manager (default: 2).")
    parser.add_argument("--from-file", type=str, default=None,
                         help="Read alerts from a JSON/JSONL file instead of the live wazuh-server VM.")
    args = parser.parse_args()

    cfg = load_config()
    if args.mock:
        cfg = cfg.__class__(**{**cfg.__dict__, "mode": "mock"})

    print("#" * 60)
    print("# NISec Attack Chain Correlation")
    print("#" * 60)
    print(f"  mode                 : {'dry-run' if args.dry_run else cfg.mode}")
    print(f"  model                : {cfg.model if cfg.mode == 'gemini' else 'n/a (mock)'}")
    print(f"  correlation window   : {cfg.correlation_window_seconds}s")
    print(f"  max requests/run     : {cfg.max_requests_per_run}")
    print()

    if cfg.mode == "gemini" and not args.dry_run and not cfg.api_key:
        print("GEMINI_API_KEY is not set. Falling back to a dry-run so nothing breaks.")
        print("Set GEMINI_API_KEY, or use --mock to test the pipeline without a key.\n")
        args.dry_run = True

    if args.from_file:
        print(f"  reading alerts from  : {args.from_file}")
        events = load_from_file(args.from_file)
    else:
        print("  reading alerts from  : live wazuh-server VM")
        events = fetch_live(hours=args.hours)

    print(f"  alerts loaded        : {len(events)}\n")
    if not events:
        print("No alerts to correlate. Run 'make attacks && make measure' first, or pass --from-file.")
        return 0

    summary = run_pipeline(events, cfg, dry_run=args.dry_run, force=args.force)

    print("Candidate incidents:      ", summary.candidate_incidents)
    print("Gemini requests required: ", summary.new_api_calls if args.dry_run else "n/a")
    print("Skipped isolated alerts:  ", summary.skipped_isolated)
    print("Cached incidents:         ", summary.cached)
    if not args.dry_run:
        print("New API calls made:       ", summary.new_api_calls)
    if summary.limit_reached:
        print(f"\n⚠️  GEMINI_MAX_REQUESTS_PER_RUN reached — remaining incidents kept their")
        print(f"   deterministic correlation only, with no AI analysis this run.")

    out_path = write_report(summary, cfg, cfg.evidence_dir, dry_run=args.dry_run)
    print(f"\nReport -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
