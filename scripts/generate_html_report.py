#!/usr/bin/env python3
"""
generate_html_report.py — CLI for the AI-narrated HTML security report.

    python3 scripts/generate_html_report.py                # AI_REPORT_MODE (default: mock)
    python3 scripts/generate_html_report.py --dry-run       # zero API calls, shows what would happen
    python3 scripts/generate_html_report.py --mock          # force mock mode
    python3 scripts/generate_html_report.py --force         # bypass cache, still respects request limit

Pure Python — runs the same on Windows/macOS/Linux, no Git Bash needed.
"""
from __future__ import annotations
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from nisec_report.config import load_config
from nisec_report.pipeline import generate_report


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-narrated HTML security report generator")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen. Zero API calls.")
    parser.add_argument("--mock", action="store_true", help="Force mock mode regardless of AI_REPORT_MODE.")
    parser.add_argument("--force", action="store_true", help="Bypass the AI cache (still respects the request limit).")
    args = parser.parse_args()

    cfg = load_config()
    if args.mock:
        cfg = cfg.__class__(**{**cfg.__dict__, "mode": "mock"})

    print("#" * 60)
    print("# NISec HTML Security Report Generator")
    print("#" * 60)
    print(f"  mode  : {'dry-run' if args.dry_run else cfg.mode}")
    if cfg.use_enterprise:
        print(f"  auth  : service account (enterprise/Agent Platform)")
        print(f"  project: {cfg.gcp_project or 'NOT SET'}")
    else:
        print(f"  model : {cfg.model if cfg.mode == 'gemini' else 'n/a'}")
    print()

    if cfg.mode == "gemini" and not args.dry_run and not cfg.use_enterprise and not cfg.api_key:
        print("GEMINI_API_KEY is not set. Falling back to --dry-run so nothing breaks.\n")
        args.dry_run = True

    result = generate_report(cfg, dry_run=args.dry_run, force=args.force)

    if result["dry_run"]:
        print(f"Report incidents:          {result['report_incidents']}")
        print(f"Existing AI cache:         {result['cache_status']}")
        print(f"Gemini requests required:  {result['gemini_requests_required']}")
        print(f"Approximate context size: {result['approx_context_size_kb']} KB")
        print(f"API calls made:            {result['api_calls_made']}")
    else:
        print(f"Report ID:      {result['report_id']}")
        print(f"AI status:      {result['ai_status']}")
        print(f"Model used:     {result['model']}")
        print(f"Cache status:   {result['cache_status']}")
        print(f"API calls made: {result['api_calls_made']}")
        print(f"\nReport -> {result['report_path']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
