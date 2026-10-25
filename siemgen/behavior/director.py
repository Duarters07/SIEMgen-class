"""The Director — a per-user state machine over {absent, working, leisure, mixed,
meeting}, in the *Generative Agents* spirit (Park et al., 2023): at every state
transition a decision-maker picks the next state + duration, given the user's
archetype, sampled traits and the day/time context.

Two interchangeable decision-makers:
  * RULES (default) — a deterministic, seeded heuristic. No external dependency.
  * LLM  (opt-in)  — a local Llama (via Ollama) that returns the same JSON contract.

Both go through the SAME validation + guardrails, so the LLM can never produce an
impossible day: weekends/holidays/out-of-hours are forced to `absent` in code, and
any malformed decision falls back to the rules. Determinism (for reproducible
datasets) comes from a per-(user, day) RNG plus temperature 0 + a decision cache on
the LLM path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..org.model import User
from . import holidays
from .personas import STATES, Traits
from .profiles import (Persona, _stable_seed, arrival_time, departure_time,
                       user_seed)

DURATION_MIN, DURATION_MAX = 2, 180


@dataclass
class DirectorContext:
    archetype: str
    role: str
    domain: str
    username: str
    traits: dict
    weekday: str
    date: str
    is_weekend: bool
    is_holiday: bool
    hour: int
    minute: int
    current_state: str
    minutes_in_state: int
    today_so_far: dict
    events: list = field(default_factory=list)


@dataclass
class Decision:
    next_state: str
    duration_min: int
    app: str | None = None
    reason: str = ""


@dataclass
class Segment:
    state: str
    app: str | None
    start_min: int      # minute-of-day [0, 1440)
    end_min: int


# --------------------------------------------------------------------------- #
# Validation + guardrails (apply to BOTH rules and LLM output)                 #
# --------------------------------------------------------------------------- #
def validate(decision: Decision, leisure_apps: set[str]) -> Decision | None:
    """Return a sane Decision or None (caller falls back to rules)."""
    if decision is None or decision.next_state not in STATES:
        return None
    try:
        dur = int(decision.duration_min)
    except (TypeError, ValueError):
        return None
    dur = max(DURATION_MIN, min(DURATION_MAX, dur))
    app = decision.app
    if decision.next_state in ("leisure", "mixed"):
        if app not in leisure_apps:
            app = next(iter(leisure_apps), None)
            if app is None and decision.next_state == "leisure":
                return None        # no leisure app available -> let rules decide
    else:
        app = None
    return Decision(decision.next_state, dur, app, decision.reason)


# --------------------------------------------------------------------------- #
# Rules decision-maker (the heuristic the LLM is asked to emulate)            #
# --------------------------------------------------------------------------- #
def rules_decide(ctx: DirectorContext, traits: Traits, rng) -> Decision:
    hour, cur = ctx.hour, ctx.current_state
    apps = traits.preferred_leisure

    # leaving a break -> back to a working block
    if cur in ("leisure", "meeting", "mixed"):
        return Decision("working", rng.randint(40, 110), reason="back to work")

    # currently working (or just arrived): decide the next break/meeting/focus block
    p_leisure = traits.distractibility * 0.45
    if hour == traits.slump_hour:
        p_leisure += 0.25
    if hour >= 13:
        p_leisure += 0.10
    sessions_done = ctx.today_so_far.get("leisure_min", 0) / 20.0
    if sessions_done >= max(0.5, traits.leisure_propensity):
        p_leisure *= 0.2                     # leisure budget spent
    p_meeting = traits.meeting_propensity * (0.40 if 9 <= hour <= 17 else 0.05)

    roll = rng.random()
    if roll < p_meeting:
        return Decision("meeting", rng.randint(20, 60), reason="scheduled call")
    if apps and roll < p_meeting + p_leisure:
        if traits.distractibility > 0.6 and rng.random() < 0.35:
            return Decision("mixed", rng.randint(30, 70), app=rng.choice(apps),
                            reason="multitasking")
        return Decision("leisure", rng.randint(8, 35), app=rng.choice(apps),
                        reason="afternoon break" if hour >= 13 else "short break")
    return Decision("working", rng.randint(45, 110), reason="focused work")


# --------------------------------------------------------------------------- #
# Director                                                                     #
# --------------------------------------------------------------------------- #
class Director:
    """Decision-maker facade. mode='rules' (default) or 'llm'."""

    def __init__(self, mode: str, leisure_cfg: dict | None, seed: int,
                 llm=None, cache=None):
        self.mode = mode if mode in ("rules", "llm") else "rules"
        self.seed = seed
        self.llm = llm
        self.cache = cache
        profiles = (leisure_cfg or {}).get("profiles", {}) or {}
        # leisure apps the validator will accept (+ the meeting profile's apps live
        # under the meeting state, not here)
        self.leisure_apps = set(profiles.keys())
        self.llm_calls = 0
        self.llm_fallbacks = 0

    def decide(self, ctx: DirectorContext, traits: Traits, rng) -> Decision:
        if self.mode == "llm" and self.llm is not None:
            dec = self._llm_decide(ctx)
            dec = validate(dec, self.leisure_apps) if dec else None
            if dec is not None:
                return dec
            self.llm_fallbacks += 1
        return rules_decide(ctx, traits, rng)

    # -- LLM path ----------------------------------------------------------- #
    def _llm_decide(self, ctx: DirectorContext) -> Decision | None:
        key = None
        if self.cache is not None:
            key = self.cache.key(self.llm.model, ctx)
            cached = self.cache.get(key)
            if cached is not None:
                return _decision_from_dict(cached)
        try:
            self.llm_calls += 1
            raw = self.llm.decide_json(build_prompt(ctx))
        except Exception:
            return None
        if not isinstance(raw, dict):
            return None
        if self.cache is not None and key is not None:
            self.cache.put(key, raw)
        return _decision_from_dict(raw)


def _decision_from_dict(d: dict) -> Decision | None:
    if not isinstance(d, dict) or "next_state" not in d:
        return None
    return Decision(
        next_state=str(d.get("next_state")),
        duration_min=d.get("duration_min", 30),
        app=d.get("app"),
        reason=str(d.get("reason", "")),
    )


SYSTEM_RULES = (
    "You are simulating one office worker's day. Decide ONLY the next behavioural "
    "state and how long it lasts. States: absent, working, leisure, mixed, meeting. "
    "Stay plausible for the archetype, hour and traits. Reply with a single JSON "
    'object: {"next_state","duration_min","app","reason"}. "app" is required for '
    "leisure/mixed (one of the user's preferred leisure apps) and null otherwise. "
    "duration_min is an integer in [2,180]."
)


def build_prompt(ctx: DirectorContext) -> str:
    import json
    payload = {
        "archetype": ctx.archetype, "role": ctx.role, "domain": ctx.domain,
        "traits": ctx.traits, "weekday": ctx.weekday, "date": ctx.date,
        "is_weekend": ctx.is_weekend, "is_holiday": ctx.is_holiday,
        "hour": ctx.hour, "minute": ctx.minute,
        "current_state": ctx.current_state, "minutes_in_state": ctx.minutes_in_state,
        "today_so_far": ctx.today_so_far, "events": ctx.events,
    }
    return f"{SYSTEM_RULES}\n\nContext:\n{json.dumps(payload)}\n\nDecision JSON:"


# --------------------------------------------------------------------------- #
# Scheduler — runs the state machine across one day (used by backfill)         #
# --------------------------------------------------------------------------- #
class Scheduler:
    def __init__(self, director: Director, seed: int):
        self.director = director
        self.seed = seed

    def _present_today(self, user: User, traits: Traits, day: datetime, rng) -> bool:
        """Guardrails: holidays close the org; weekends only for users with a
        weekend_work_chance; otherwise a small daily chance of being off (leave/sick)."""
        if holidays.is_holiday(day):
            return False
        if day.weekday() >= 5:               # Sat/Sun
            return rng.random() < traits.weekend_work_chance
        if day.weekday() not in user.work_days:
            return rng.random() < traits.weekend_work_chance
        if rng.random() < 0.06:              # ~6% day off (vacation/sick)
            return False
        return True

    def _day_events(self, user: User, day: datetime) -> list:
        import calendar
        last = calendar.monthrange(day.year, day.month)[1]
        out = []
        if day.day >= last - 2 and user.domain in ("FIN", "EXE", "OPS"):
            out.append("month_end")
        return out

    def day_segments(self, user: User, traits: Traits, day: datetime,
                     persona: Persona) -> list[Segment]:
        """Return the ordered list of state Segments for this user on this day.
        Empty list = user absent all day (no events)."""
        rng = _day_rng(self.seed, user, day)
        if not self._present_today(user, traits, day, rng):
            return []

        arr = arrival_time(user, persona, day)
        dep = departure_time(user, persona, day)
        start = arr.hour * 60 + arr.minute
        end = max(start + 30, dep.hour * 60 + dep.minute)
        events = self._day_events(user, day)
        traits_d = _traits_dict(traits)

        segments: list[Segment] = []
        cursor = start
        cur_state = "absent"
        minutes_in = 0
        today = {"work_min": 0, "leisure_min": 0, "meeting_min": 0}

        while cursor < end:
            hour = cursor // 60
            ctx = DirectorContext(
                archetype=traits.archetype, role=user.role, domain=user.domain,
                username=user.username,
                traits=traits_d, weekday=day.strftime("%A"),
                date=day.strftime("%Y-%m-%d"), is_weekend=day.weekday() >= 5,
                is_holiday=False, hour=hour, minute=cursor % 60,
                current_state=cur_state, minutes_in_state=minutes_in,
                today_so_far=dict(today), events=events,
            )
            dec = self.director.decide(ctx, traits, rng)
            dur = max(DURATION_MIN, min(DURATION_MAX, int(dec.duration_min)))
            seg_end = min(end, cursor + dur)
            real = seg_end - cursor
            if real <= 0:
                break
            segments.append(Segment(dec.next_state, dec.app, cursor, seg_end))
            if dec.next_state == "working":
                today["work_min"] += real
            elif dec.next_state == "meeting":
                today["meeting_min"] += real
            elif dec.next_state in ("leisure", "mixed"):
                today["leisure_min"] += real
                if dec.next_state == "mixed":
                    today["work_min"] += real
            cursor = seg_end
            cur_state = dec.next_state
            minutes_in = real

        return segments


def _day_rng(seed: int, user: User, day: datetime):
    import random
    return random.Random(_stable_seed(seed, "director", user.username, day.toordinal()))


def _traits_dict(t: Traits) -> dict:
    return {
        "distractibility": round(t.distractibility, 2),
        "focus_bias": round(t.focus_bias, 2),
        "leisure_propensity": round(t.leisure_propensity, 2),
        "meeting_propensity": round(t.meeting_propensity, 2),
        "preferred_leisure": t.preferred_leisure,
        "slump_hour": t.slump_hour,
    }
