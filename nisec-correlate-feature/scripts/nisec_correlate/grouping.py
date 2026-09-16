"""
grouping.py — deterministic candidate correlation. Runs BEFORE Gemini is
ever considered, and is what keeps API usage low: 500 alerts should become
a handful of candidate groups, not 500 requests.

Rule (spec item 3): matching a SINGLE field is never enough. Two events
join a candidate group only if they're within the time window AND share
a source, AND share at least one more identifying attribute (destination
host, destination port, or rule/category family). This deliberately avoids
lumping every alert from a noisy scanner into one giant fake "incident".

Implemented as union-find over pairs — this naturally produces transitive
chains (A relates to B, B relates to C => A, B, C are one candidate group)
without needing to guess a single clustering key up front.
"""
from __future__ import annotations
from datetime import datetime, timezone
from .events import Event


def _parse_ts(ts: str) -> float:
    try:
        cleaned = ts.split(".")[0].replace("Z", "")
        return datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, IndexError):
        return 0.0


def _related(a: Event, b: Event, window_seconds: int) -> bool:
    if a.id == b.id:
        return False
    if abs(_parse_ts(a.timestamp) - _parse_ts(b.timestamp)) > window_seconds:
        return False

    same_source_ip = bool(a.src_ip) and a.src_ip == b.src_ip
    if not same_source_ip:
        return False  # a shared attacker source is the minimum bar to even consider a link

    # ...and at least ONE more shared attribute, so "same attacker IP" alone
    # (e.g. a noisy scanner) doesn't merge unrelated activity into one group.
    second_signal = (
        (a.dst_ip and a.dst_ip == b.dst_ip)
        or (a.agent and a.agent == b.agent)
        or (a.dst_port and a.dst_port == b.dst_port)
        or (a.category and b.category and set(a.category.split(",")) & set(b.category.split(",")))
    )
    return bool(second_signal)


class _UnionFind:
    def __init__(self, ids: list[str]):
        self.parent = {i: i for i in ids}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def group_candidates(events: list[Event], window_seconds: int) -> list[list[Event]]:
    """Returns a list of candidate groups (each a list of Event), including
    singleton groups for events with no related alert."""
    if not events:
        return []

    uf = _UnionFind([e.id for e in events])
    events_sorted = sorted(events, key=lambda e: _parse_ts(e.timestamp))

    # O(n^2) worst case, but candidate lists here are per-hunt-window alert
    # counts (tens to low hundreds), not the full alert firehose — fine.
    for i, a in enumerate(events_sorted):
        for b in events_sorted[i + 1:]:
            if _parse_ts(b.timestamp) - _parse_ts(a.timestamp) > window_seconds:
                break  # sorted by time — nothing further can be in-window
            if _related(a, b, window_seconds):
                uf.union(a.id, b.id)

    groups: dict[str, list[Event]] = {}
    for e in events_sorted:
        root = uf.find(e.id)
        groups.setdefault(root, []).append(e)

    return list(groups.values())
