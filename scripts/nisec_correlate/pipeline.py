"""
pipeline.py — wires together grouping, dedup, cache, and the Gemini/mock
client into the full "existing alerts -> structured attack chain" flow
described in the feature spec.

This is the one place that enforces spend discipline:
  - isolated singleton alerts never reach Gemini (item 18)
  - a cache hit never reaches Gemini (item 12)
  - GEMINI_MAX_REQUESTS_PER_RUN is a hard ceiling per invocation (item 15)
  - --dry-run makes this whole function a no-op w.r.t. the network (item 20)
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .config import Config, PROMPT_VERSION
from .events import Event
from .grouping import group_candidates
from .dedup import dedupe_for_ai, group_fingerprint
from .cache import Cache
from . import gemini_client


@dataclass
class IncidentResult:
    incident_id: str
    candidate_event_ids: list[str]
    ai_status: str                 # ok | skipped_isolated | cached | skipped_limit_reached | unavailable | error | validation_failed | dry_run
    model: str | None = None
    result: dict | None = None     # the Gemini/mock structured output, if any
    detail: str = ""               # human-readable reason, especially for non-"ok" statuses
    processing_ms: int = 0


@dataclass
class RunSummary:
    total_alerts: int
    candidate_incidents: int
    skipped_isolated: int
    cached: int
    new_api_calls: int
    limit_reached: bool
    incidents: list[IncidentResult] = field(default_factory=list)


def run_pipeline(events: list[Event], cfg: Config, dry_run: bool = False,
                  force: bool = False) -> RunSummary:
    import time as _time

    groups = group_candidates(events, cfg.correlation_window_seconds)
    cache = Cache(cfg.cache_dir)

    incidents: list[IncidentResult] = []
    skipped_isolated = 0
    cached_count = 0
    new_calls = 0
    limit_reached = False

    multi_event_groups = [g for g in groups if len(g) > 1]
    skipped_isolated = len(groups) - len(multi_event_groups)

    for idx, group in enumerate(multi_event_groups, start=1):
        t0 = _time.time()
        incident_id = f"INC{idx:03d}"
        deduped = dedupe_for_ai(group)[: cfg.max_events_per_request]
        fp = group_fingerprint(deduped)
        candidate_ids = [e.id for e in deduped]

        if dry_run:
            cached_hit = cache.get(fp) is not None
            if cached_hit:
                cached_count += 1
            incidents.append(IncidentResult(
                incident_id=incident_id, candidate_event_ids=candidate_ids,
                ai_status="dry_run",
                detail="would use cache" if cached_hit else "would call Gemini",
            ))
            if not cached_hit:
                new_calls += 1
            continue

        cached_record = None if force else cache.get(fp)
        if cached_record:
            cached_count += 1
            incidents.append(IncidentResult(
                incident_id=incident_id, candidate_event_ids=candidate_ids,
                ai_status="cached", model=cached_record.get("model"),
                result=cached_record.get("result"),
                detail=f"cache hit (fingerprint {fp[:12]}...)",
                processing_ms=int((_time.time() - t0) * 1000),
            ))
            continue

        if cfg.mode == "mock":
            result, status, detail = gemini_client.call_mock(
                [e.normalized() for e in deduped]
            )
            cache.set(fp, "mock", PROMPT_VERSION, result)
        else:  # cfg.mode == "gemini"
            if new_calls >= cfg.max_requests_per_run:
                limit_reached = True
                incidents.append(IncidentResult(
                    incident_id=incident_id, candidate_event_ids=candidate_ids,
                    ai_status="skipped_limit_reached",
                    detail=f"GEMINI_MAX_REQUESTS_PER_RUN={cfg.max_requests_per_run} reached; "
                           f"deterministic grouping preserved, no AI analysis for this incident",
                ))
                continue
            result, status, detail = gemini_client.call_gemini(
                [e.normalized() for e in deduped], cfg
            )
            new_calls += 1
            if status == "ok":
                cache.set(fp, cfg.model, PROMPT_VERSION, result)

        incidents.append(IncidentResult(
            incident_id=incident_id, candidate_event_ids=candidate_ids,
            ai_status=status if cfg.mode == "gemini" else "ok",
            model=cfg.model if cfg.mode == "gemini" else "mock",
            result=result, detail=detail,
            processing_ms=int((_time.time() - t0) * 1000),
        ))

    return RunSummary(
        total_alerts=len(events),
        candidate_incidents=len(multi_event_groups),
        skipped_isolated=skipped_isolated,
        cached=cached_count,
        new_api_calls=new_calls,
        limit_reached=limit_reached,
        incidents=incidents,
    )
