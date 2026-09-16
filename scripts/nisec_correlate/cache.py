"""
cache.py — persistent cache so repeated development runs (or a real
re-analysis of the same candidate group) never re-spend API credit.

One JSON file per fingerprint under evidence/ai-cache/. Deliberately simple
(no database) — this is a student lab, not a production cache tier, and
the whole point is to be inspectable: `cat evidence/ai-cache/<fp>.json`
should just work.
"""
from __future__ import annotations
import json
import os
import time


class Cache:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _path(self, fingerprint: str) -> str:
        return os.path.join(self.cache_dir, f"{fingerprint}.json")

    def get(self, fingerprint: str) -> dict | None:
        path = self._path(fingerprint)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, fingerprint: str, model: str, prompt_version: str, result: dict) -> None:
        record = {
            "fingerprint": fingerprint,
            "model": model,
            "prompt_version": prompt_version,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "result": result,
        }
        with open(self._path(fingerprint), "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
