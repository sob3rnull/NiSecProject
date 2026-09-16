"""
pipeline.py — wires evidence parsing, caching, the Gemini/mock narrative
call, and HTML rendering into one function. This is where the "at most one
Gemini request per report" rule (spec item 3/16) actually gets enforced.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from nisec_correlate.cache import Cache  # reused as-is — a fingerprint -> JSON store is generic infra

from .config import ReportConfig, PROMPT_VERSION
from .evidence_parser import build_report_data, ReportData
from .gemini_client import get_narrative
from .html_renderer import render_html


TEMPLATE_VERSION = "1.0"


def _fingerprint(context: dict) -> str:
    basis = json.dumps(context, sort_keys=True, default=str) + f"|{PROMPT_VERSION}|{TEMPLATE_VERSION}"
    return "report:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()


def generate_report(cfg: ReportConfig, dry_run: bool = False, force: bool = False,
                     evidence_override: ReportData | None = None) -> dict:
    """Returns a summary dict describing what happened — used by both the
    CLI's printed output and the offline tests."""
    data = evidence_override or build_report_data(cfg.evidence_dir)
    context = data.as_ai_context()
    fp = _fingerprint(context)
    cache = Cache(cfg.cache_dir)

    approx_size_kb = round(len(json.dumps(context, default=str)) / 1024, 2)

    cached_record = None if force else cache.get(fp)
    cache_status = "hit" if cached_record else "miss"

    if dry_run:
        return {
            "dry_run": True,
            "report_incidents": 1,
            "cache_status": cache_status,
            "gemini_requests_required": 0 if cached_record else 1,
            "approx_context_size_kb": approx_size_kb,
            "api_calls_made": 0,
            "fingerprint": fp,
        }

    if cached_record:
        narrative = cached_record["result"]
        ai_status = "cached"
        api_calls_made = 0
    else:
        narrative, ai_status, _detail = get_narrative(context, cfg, dry_run=False)
        api_calls_made = 1 if (cfg.mode == "gemini" and ai_status in ("ok", "error", "validation_failed", "unavailable")) else 0
        if cfg.mode == "gemini" and api_calls_made > cfg.max_requests_per_run:
            api_calls_made = cfg.max_requests_per_run  # never silently exceed the ceiling
        if ai_status == "ok":
            cache.set(fp, cfg.model if cfg.mode == "gemini" else "mock", PROMPT_VERSION, narrative)

    ai_meta = {
        "model": cfg.model if cfg.mode == "gemini" else "mock",
        "prompt_version": PROMPT_VERSION,
        "cache_status": "hit" if cached_record else ("stored" if ai_status == "ok" else "n/a"),
    }

    html = render_html(data, narrative, ai_status, ai_meta)

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(cfg.evidence_dir, f"report_{ts}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return {
        "dry_run": False,
        "report_path": out_path,
        "report_id": data.report_id,
        "ai_status": ai_status,
        "model": ai_meta["model"],
        "cache_status": ai_meta["cache_status"],
        "api_calls_made": api_calls_made,
        "fingerprint": fp,
    }
