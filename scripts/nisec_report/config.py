"""
config.py — env configuration for the AI-narrated HTML report generator.
Mirrors nisec_correlate/config.py's philosophy: every default is the
conservative, zero-cost choice.
"""
from __future__ import annotations
import os
from dataclasses import dataclass

PROMPT_VERSION = "1.0"  # AI_REPORT_PROMPT_VERSION — bump if the system instruction or schema changes


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class ReportConfig:
    mode: str                      # "mock" | "dry-run" | "gemini"
    model: str
    api_key: str | None
    max_requests_per_run: int
    timeout_seconds: int
    cache_dir: str
    evidence_dir: str
    # Service-account / Agent Platform auth (alternative to api_key)
    use_enterprise: bool = False
    gcp_project: str | None = None
    gcp_location: str = "global"
    service_account_file: str | None = None


def load_config() -> ReportConfig:
    use_enterprise = os.environ.get("GOOGLE_GENAI_USE_ENTERPRISE", "").strip().lower() in ("1", "true", "yes")
    return ReportConfig(
        mode=os.environ.get("AI_REPORT_MODE", "mock").strip().lower(),
        model=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite").strip(),
        api_key=os.environ.get("GEMINI_API_KEY"),
        max_requests_per_run=_int_env("GEMINI_MAX_REQUESTS_PER_RUN", 1),
        timeout_seconds=_int_env("GEMINI_TIMEOUT_SECONDS", 30),
        cache_dir=os.environ.get("AI_REPORT_CACHE_DIR", "evidence/ai-cache"),
        evidence_dir=os.environ.get("EVIDENCE_DIR", "evidence"),
        use_enterprise=use_enterprise,
        gcp_project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
        gcp_location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
        service_account_file=os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"),
    )
