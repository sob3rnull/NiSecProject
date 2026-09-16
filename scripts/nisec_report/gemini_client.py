"""
gemini_client.py — the only file in this package that talks to Google's
API. One call per report generation, at most (GEMINI_MAX_REQUESTS_PER_RUN
defaults to 1 — a report needs exactly one narrative, never one per alert).
"""
from __future__ import annotations
import json
import time
from .schema import SYSTEM_INSTRUCTION, RESPONSE_SCHEMA, fallback_result
from .config import ReportConfig


def call_mock(context: dict) -> tuple[dict, str, str]:
    """Deterministic fixture narrative — no network call, spec item 14."""
    stats = context.get("statistics", {})
    incident = context.get("incident", {})
    chain = context.get("attack_chain", [])
    stages = ", ".join(s.get("stage", "?") for s in chain) or "no correlated stages"

    result = {
        "executive_summary": (
            f"[MOCK] {stats.get('total_alerts', 0)} alerts were observed, of which "
            f"{stats.get('correlated_events', 0)} were correlated into a candidate attack chain "
            f"covering: {stages}."
        ),
        "incident_overview": (
            f"[MOCK] Severity assessed as {incident.get('severity', 'UNKNOWN')} based on the "
            f"supplied detection results. This text is a fixture, not a model output."
        ),
        "attack_narrative": f"[MOCK] Observed stage sequence: {stages}.",
        "attack_chain_analysis": "[MOCK] Attack chain analysis placeholder — see attack_chain data for real stages.",
        "detection_analysis": (
            f"[MOCK] {stats.get('suricata_alerts', 0)} network-layer and "
            f"{stats.get('wazuh_alerts', 0)} host-layer alerts contributed to this window."
        ),
        "key_findings": ["[MOCK] This report was generated in mock mode — no real model reasoning occurred."],
        "limitations": ["[MOCK] Mock mode output; not a substitute for a real Gemini analysis."],
        "conclusion": "[MOCK] Replace with a real run (AI_REPORT_MODE=gemini) before submission.",
    }
    return result, "ok", "mock narrative generated"


def call_gemini(context: dict, cfg: ReportConfig) -> tuple[dict | None, str, str]:
    """
    Supports two auth modes:
      - API key mode (default): set GEMINI_API_KEY
      - Enterprise/service account mode: set GOOGLE_GENAI_USE_ENTERPRISE=true,
        GOOGLE_CLOUD_PROJECT, and GOOGLE_APPLICATION_CREDENTIALS (path to JSON key)
    """
    use_enterprise = getattr(cfg, "use_enterprise", False)
    gcp_project = getattr(cfg, "gcp_project", None)
    gcp_location = getattr(cfg, "gcp_location", "global")
    sa_file = getattr(cfg, "service_account_file", None)

    if use_enterprise:
        if not gcp_project:
            return None, "unavailable", (
                "GOOGLE_CLOUD_PROJECT is not set. "
                "Set it to your GCP project ID for enterprise/service-account mode."
            )
        if sa_file:
            import os as _os
            _os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", sa_file)
    else:
        if not cfg.api_key:
            return None, "unavailable", "GEMINI_API_KEY is not set"

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return None, "unavailable", "google-genai package is not installed"

    contents = json.dumps(context, separators=(",", ":"), default=str)

    last_error = ""
    for attempt in range(2):  # at most one retry
        try:
            if use_enterprise:
                client = genai.Client(
                    enterprise=True,
                    project=gcp_project,
                    location=gcp_location,
                    http_options=types.HttpOptions(timeout=cfg.timeout_seconds * 1000),
                )
            else:
                client = genai.Client(
                    api_key=cfg.api_key,
                    http_options=types.HttpOptions(timeout=cfg.timeout_seconds * 1000),
                )
            response = client.models.generate_content(
                model=cfg.model,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_json_schema=RESPONSE_SCHEMA,
                    temperature=0.2,
                ),
            )
            result = json.loads(response.text or "")
            return result, "ok", response.text or ""
        except json.JSONDecodeError as e:
            return None, "validation_failed", f"model did not return valid JSON: {e}"
        except Exception as e:  # noqa: BLE001 — SDK exception types vary by version
            last_error = str(e)
            shape_error = "schema" in last_error.lower() or "invalid" in last_error.lower()
            if shape_error or attempt == 1:
                break
            time.sleep(2 ** (attempt + 1))

    return None, "error", last_error


def get_narrative(context: dict, cfg: ReportConfig, dry_run: bool) -> tuple[dict, str, str]:
    """Single decision point: mock / dry-run / gemini -> always returns a
    usable result dict (falls back to fallback_result() text on any failure)."""
    if dry_run:
        return fallback_result(), "dry_run", "dry run — no narrative generated"
    if cfg.mode == "mock":
        return call_mock(context)

    result, status, detail = call_gemini(context, cfg)
    if result is None:
        return fallback_result(), status, detail
    return result, status, detail
