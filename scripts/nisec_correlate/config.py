"""
config.py — environment configuration for the AI attack-chain correlation
module, with safe, conservative defaults.

Every value here is overridable via environment variable. Defaults are
chosen so that running `correlate` with NO configuration at all never
spends API credit (AI_CORRELATION_MODE defaults to "mock").
"""
from __future__ import annotations
import os
from dataclasses import dataclass

PROMPT_VERSION = "1.0"  # bump this if SYSTEM_INSTRUCTION or the schema changes


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Config:
    mode: str                       # "mock" | "gemini"  (dry-run is a CLI flag, not a mode)
    model: str
    api_key: str | None
    correlation_window_seconds: int
    max_requests_per_run: int
    max_events_per_request: int
    timeout_seconds: int
    cache_dir: str
    evidence_dir: str
    # Service-account / Agent Platform auth (alternative to api_key)
    use_enterprise: bool            # True  → Agent Platform mode (service account)
    gcp_project: str | None         # GOOGLE_CLOUD_PROJECT  (required for enterprise mode)
    gcp_location: str               # GOOGLE_CLOUD_LOCATION (default: global)
    service_account_file: str | None  # GOOGLE_APPLICATION_CREDENTIALS path to JSON key


def load_config() -> Config:
    use_enterprise = os.environ.get("GOOGLE_GENAI_USE_ENTERPRISE", "").strip().lower() in ("1", "true", "yes")
    return Config(
        # Conservative default: never call the real API unless explicitly asked.
        mode=os.environ.get("AI_CORRELATION_MODE", "mock").strip().lower(),
        model=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite").strip(),
        api_key=os.environ.get("GEMINI_API_KEY"),
        correlation_window_seconds=_int_env("CORRELATION_WINDOW_SECONDS", 300),
        max_requests_per_run=_int_env("GEMINI_MAX_REQUESTS_PER_RUN", 10),
        max_events_per_request=_int_env("GEMINI_MAX_EVENTS_PER_REQUEST", 50),
        timeout_seconds=_int_env("GEMINI_TIMEOUT_SECONDS", 30),
        cache_dir=os.environ.get("AI_CORRELATION_CACHE_DIR", "evidence/ai-cache"),
        evidence_dir=os.environ.get("EVIDENCE_DIR", "evidence"),
        use_enterprise=use_enterprise,
        gcp_project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
        gcp_location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
        service_account_file=os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"),
    )
