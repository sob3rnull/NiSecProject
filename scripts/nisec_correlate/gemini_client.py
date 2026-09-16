"""
gemini_client.py — the only file that talks to Google's API, and the only
file that needs a real network connection. Everything upstream of this
(grouping, dedup, cache) works identically whether this file ever runs
for real or not.

Two entry points:
  call_mock()   — deterministic, offline, zero cost. Used by AI_CORRELATION_MODE=mock.
  call_gemini() — the real thing. Used by AI_CORRELATION_MODE=gemini.

Both return the same shape: (result_dict | None, ai_status, raw_text).
"""
from __future__ import annotations
import json
import time
from .schema import SYSTEM_INSTRUCTION, RESPONSE_SCHEMA, all_event_ids_referenced_exist
from .config import Config, PROMPT_VERSION


class GeminiUnavailable(Exception):
    pass


def call_mock(events_normalized: list[dict]) -> tuple[dict, str, str]:
    """
    Deterministic fixture logic — no network call. Good enough to exercise
    every branch of the pipeline (correlated / not correlated / partial
    chain) without spending a cent, per spec item 14.
    """
    ids = [e["id"] for e in events_normalized]
    categories = " ".join((e.get("category") or "") + " " + (e.get("description") or "")
                           for e in events_normalized).lower()

    has_scan = "scan" in categories or "discovery" in categories
    has_auth = "auth" in categories or "brute" in categories or "ssh" in categories
    has_fim = "syscheck" in categories or "integrity" in categories or "fim" in categories

    if len(ids) < 2 or not (has_scan or has_auth or has_fim):
        result = {
            "is_correlated": False, "confidence": 0.3,
            "attack_chain": [], "relationships": [], "mitre_attack": [],
            "uncertainties": ["Insufficient shared context between supplied events (mock mode)."],
        }
        return result, "ok", "mock: not correlated"

    chain = []
    if has_scan:
        chain.append({"stage": "reconnaissance", "event_ids": ids[:max(1, len(ids)//2)], "confidence": 0.85})
    if has_auth:
        chain.append({"stage": "credential_access", "event_ids": ids[len(ids)//2:], "confidence": 0.8})
    if has_fim and not chain:
        chain.append({"stage": "impact", "event_ids": ids, "confidence": 0.8})

    relationships = []
    if len(ids) >= 2:
        relationships.append({
            "from_event": ids[0], "to_event": ids[-1],
            "relationship": "possible_attack_progression", "confidence": 0.75,
            "reason": "Same source observed across the candidate window (mock heuristic).",
        })

    result = {
        "is_correlated": True, "confidence": 0.8,
        "attack_chain": chain, "relationships": relationships,
        "mitre_attack": [{"technique": "T1595" if has_scan else "T1110", "event_ids": ids[:1], "confidence": 0.7}],
        "uncertainties": ["This is a MOCK result — no real model reasoning was performed."],
    }
    return result, "ok", "mock: correlated"


def call_gemini(events_normalized: list[dict], cfg: Config) -> tuple[dict | None, str, str]:
    """
    Real call, with: one retry on transient failure (exponential backoff),
    no retry on a request/schema-shaped error, and a hard timeout. Any
    failure returns ai_status describing why rather than raising — the
    caller (pipeline.py) always has a deterministic result to fall back on.

    Supports two auth modes:
      - API key mode (default): set GEMINI_API_KEY
      - Enterprise/service account mode: set GOOGLE_GENAI_USE_ENTERPRISE=true,
        GOOGLE_CLOUD_PROJECT, and GOOGLE_APPLICATION_CREDENTIALS (path to JSON key)
    """
    # --- auth check ---
    if cfg.use_enterprise:
        if not cfg.gcp_project:
            return None, "unavailable", (
                "GOOGLE_CLOUD_PROJECT is not set. "
                "Set it to your GCP project ID for enterprise/service-account mode."
            )
        if cfg.service_account_file:
            import os as _os
            _os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", cfg.service_account_file)
    else:
        if not cfg.api_key:
            return None, "unavailable", "GEMINI_API_KEY is not set"

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return None, "unavailable", "google-genai package is not installed"

    contents = json.dumps({"candidate_events": events_normalized}, separators=(",", ":"))

    last_error = ""
    for attempt in range(2):  # at most one retry (spec item 16)
        try:
            if cfg.use_enterprise:
                client = genai.Client(
                    enterprise=True,
                    project=cfg.gcp_project,
                    location=cfg.gcp_location,
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
                    temperature=0.1,  # correlation should be consistent, not creative
                ),
            )
            text = response.text or ""
            result = json.loads(text)

            valid_ids = {e["id"] for e in events_normalized}
            problems = all_event_ids_referenced_exist(result, valid_ids)
            if problems:
                return None, "validation_failed", "; ".join(problems)

            return result, "ok", text

        except json.JSONDecodeError as e:
            last_error = f"model did not return valid JSON: {e}"
            break  # a schema/shape problem — do not retry (spec item 16)
        except Exception as e:  # noqa: BLE001 — SDK exception types vary by version
            last_error = str(e)
            is_request_shape_error = "schema" in last_error.lower() or "invalid" in last_error.lower()
            if is_request_shape_error or attempt == 1:
                break
            time.sleep(2 ** (attempt + 1))  # exponential backoff before the single retry

    return None, "error", last_error
