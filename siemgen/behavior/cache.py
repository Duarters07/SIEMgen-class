"""Decision cache for the LLM director.

Buckets the decision context (hour, state, coarse day-progress, per-user identity)
so the same situation always yields the same cached decision — giving reproducible
datasets and cutting the number of Ollama calls. Optionally persisted to a JSON file
so reproducibility survives across runs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _bucket30(v) -> int:
    try:
        return int(round(float(v) / 30.0))
    except (TypeError, ValueError):
        return 0


class DecisionCache:
    def __init__(self, path: str | None = None):
        self._mem: dict = {}
        self.path = path
        self.hits = 0
        self.misses = 0
        if path and Path(path).exists():
            try:
                self._mem = json.loads(Path(path).read_text())
            except Exception:  # noqa: BLE001 — a corrupt cache must never break a run
                self._mem = {}

    def key(self, model: str, ctx) -> str:
        t = ctx.traits or {}
        bucket = {
            "m": model,
            "u": getattr(ctx, "username", None) or ctx.archetype,
            "wd": ctx.weekday,
            "h": ctx.hour,
            "cs": ctx.current_state,
            "tw": _bucket30(ctx.today_so_far.get("work_min", 0)),
            "tl": _bucket30(ctx.today_so_far.get("leisure_min", 0)),
            "tm": _bucket30(ctx.today_so_far.get("meeting_min", 0)),
            "a": ctx.archetype,
            "d": round(float(t.get("distractibility", 0)), 1),
            "mp": round(float(t.get("meeting_propensity", 0)), 1),
            "sl": t.get("slump_hour"),
            "ev": sorted(ctx.events or []),
        }
        raw = json.dumps(bucket, sort_keys=True)
        return hashlib.sha1(raw.encode()).hexdigest()

    def get(self, key: str):
        v = self._mem.get(key)
        if v is None:
            self.misses += 1
        else:
            self.hits += 1
        return v

    def put(self, key: str, value: dict) -> None:
        self._mem[key] = value

    def save(self) -> None:
        if not self.path:
            return
        try:
            Path(self.path).write_text(json.dumps(self._mem))
        except Exception:  # noqa: BLE001
            pass
