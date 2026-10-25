"""Map a Director state to the existing emitters.

The Director (director.py) decides WHICH state a user is in; this module renders a
minute (or stamps a working event) for that state, reusing the calibrated leisure
motor and the suricata/dns/pfsense sources. Every produced event carries
`labels.state` (ground truth). No new source types are introduced — `meeting`
(Zoom/Teams) is just a near-symmetric, UDP flow profile fed through the same path.

    absent   -> nothing (gaps in the logs)
    working  -> baseline activity mix (emitted by the engine via per_tick_lambda)
    leisure  -> leisure.minute_events with the user's preferred app
    mixed    -> working + occasional leisure minute (engine-gated by focus_bias)
    meeting  -> leisure.minute_events with the meeting (Zoom/Teams) profile
"""
from __future__ import annotations

import random
from datetime import datetime

from . import leisure as _leisure


def leisure_context(app: str, prof: dict, leisure_cfg: dict, rng: random.Random) -> dict:
    """Per-session leisure context with the state label added for ground truth."""
    ctx = _leisure.session_context(app, prof, leisure_cfg, rng)
    ctx["labels"] = {**ctx["labels"], "state": "leisure"}
    return ctx


def meeting_context(meeting_app: dict, leisure_cfg: dict, rng: random.Random) -> dict:
    """A Zoom/Teams call rendered through the leisure motor: UDP, near-symmetric
    bytes (down_up ~1.3), labelled state=meeting (NOT off-task)."""
    ctx = _leisure.session_context("meeting", meeting_app, leisure_cfg or {}, rng)
    ctx["transport"] = "udp"                      # media over UDP, not QUIC-via-TCP fallback
    ctx["labels"] = {"state": "meeting", "activity": "meeting",
                     "category": meeting_app.get("category", "meeting"), "app": "meeting"}
    return ctx


def minute(sources: dict, host, ts: datetime, ctx: dict, rng: random.Random) -> list:
    """One minute of a leisure or meeting session (calibrated per-minute rates)."""
    return _leisure.minute_events(sources, host, ts, ctx, rng)


def stamp_state(events: list, state: str) -> list:
    """Tag a batch of working/mixed events with their state (ground truth)."""
    for ev in events:
        if ev is not None:
            ev.labels = {**(ev.labels or {}), "state": state}
    return events
