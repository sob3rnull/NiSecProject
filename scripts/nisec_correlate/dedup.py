"""
dedup.py — two related but distinct jobs:

1. dedupe_for_ai(): collapse repeated copies of the same alert so they don't
   consume extra tokens or skew the model's read of event frequency. The
   ORIGINAL raw list is never touched — this only affects what gets sent
   to Gemini.

2. fingerprint(): a deterministic content hash per event (used when Wazuh
   doesn't give a stable alert ID) and a group fingerprint (used as the
   cache key, spec item 12/13).
"""
from __future__ import annotations
import hashlib
from .events import Event
from .config import PROMPT_VERSION


def event_fingerprint(e: Event) -> str:
    basis = "|".join([
        e.timestamp, str(e.src_ip), str(e.dst_ip),
        str(e.rule_id), str(e.category),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def dedupe_for_ai(events: list[Event]) -> list[Event]:
    seen: set[str] = set()
    deduped: list[Event] = []
    for e in events:
        fp = event_fingerprint(e)
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(e)
    return deduped


def group_fingerprint(events: list[Event]) -> str:
    """
    The correlation cache key: SHA256 of the prompt version + sorted event
    IDs. Same candidate group + same prompt version => same key => cache
    hit => zero additional Gemini requests (spec item 12).
    """
    ids_sorted = sorted(e.id for e in events)
    basis = PROMPT_VERSION + "|" + ",".join(ids_sorted)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
