"""Per-user personas and the session/diurnal scheduling used by the live stream.

A persona is STABLE per user (derived from a per-user seed): same browser, same
daily volume tendency, same arrival/leave offsets — so logs read like the *same*
person/company day after day, while the actual content stays high-entropy and
non-repetitive."""
from __future__ import annotations

import calendar
import hashlib
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..org.model import Host, User

UA_WINDOWS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
UA_LINUX = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
UA_MAC = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# Baseline TOTAL activity events per active day, by role (spread across the day).
ROLE_DAILY = {
    "c-level": 45, "it-admin": 130, "finance": 170, "hr": 140,
    "legal": 110, "ops": 100, "employee": 160,
}


def user_seed(user: User, seed: int) -> int:
    h = int(hashlib.md5(user.username.encode()).hexdigest()[:8], 16)
    return (seed * 2654435761 ^ h) & 0xFFFFFFFF


@dataclass
class Persona:
    seed: int
    ua: str
    daily_events: float
    arrival_off: int     # minutes relative to work_start
    dep_off: int         # minutes relative to work_end


def make_persona(user: User, host: Host, seed: int) -> Persona:
    r = random.Random(user_seed(user, seed))
    if host.os == "windows":
        ua = r.choice(UA_WINDOWS)
    elif host.os == "linux":
        ua = r.choice(UA_LINUX)
    else:
        ua = r.choice(UA_MAC)
    daily = ROLE_DAILY.get(user.role, 120) * r.uniform(0.7, 1.3)
    return Persona(
        seed=user_seed(user, seed),
        ua=ua,
        daily_events=daily,
        arrival_off=r.randint(-15, 50),
        dep_off=r.randint(-40, 30),
    )


def arrival_time(user: User, persona: Persona, day: datetime) -> datetime:
    base = day.replace(hour=min(user.work_start, 23), minute=0, second=0, microsecond=0)
    return base + timedelta(minutes=persona.arrival_off)


def departure_time(user: User, persona: Persona, day: datetime) -> datetime:
    base = day.replace(hour=min(user.work_end, 23), minute=0, second=0, microsecond=0)
    return base + timedelta(minutes=persona.dep_off)


def per_tick_lambda(persona: Persona, weights_map: dict[int, float], total_w: float,
                    hour: int, tick_seconds: float) -> float:
    """Expected number of activity events for this user in one tick (Poisson mean)."""
    if total_w <= 0:
        return 0.0
    w = weights_map.get(hour, 0.0)
    if w <= 0:
        return 0.0
    events_this_hour = persona.daily_events * (w / total_w)
    return events_this_hour * (tick_seconds / 3600.0)


def poisson(rng: random.Random, lam: float) -> int:
    """Knuth's algorithm — fine for the small means used here."""
    if lam <= 0:
        return 0
    el = math.exp(-lam)
    k = 0
    p = 1.0
    while True:
        p *= rng.random()
        if p <= el:
            return k
        k += 1


def _stable_seed(*parts) -> int:
    """Stable integer seed from arbitrary parts (not affected by PYTHONHASHSEED)."""
    h = hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()
    return int(h[:8], 16)


# Day-of-week volume multipliers (Mon..Sun). Weekends only reached if the user
# actually works them (on-call IT / executives).
_DOW = {0: 1.15, 1: 1.05, 2: 1.0, 3: 0.95, 4: 0.85, 5: 0.5, 6: 0.5}


def day_factor(user: User, day: datetime, seed: int) -> float:
    """Macro per-(user, day) volume multiplier so days are no longer uniform:

      - day-of-week effect (Monday busiest, Friday lightest);
      - ±25% daily jitter;
      - month-end spike for Finance (and a smaller one for Exec/Ops);
      - occasional day off (~6%, returns 0.0 -> user absent) or busy day (~8%).

    Deterministic per (user, day) and seed, so every source for that user scales
    together and runs stay reproducible."""
    r = random.Random(_stable_seed(seed, user.username, day.toordinal()))
    roll = r.random()
    if roll < 0.06:                       # ~6% day off — user effectively absent
        return 0.0
    factor = _DOW.get(day.weekday(), 1.0)
    factor *= r.uniform(0.75, 1.25)       # ±25% daily jitter
    if roll > 0.92:                       # ~8% unusually busy day
        factor *= 1.5
    last_dom = calendar.monthrange(day.year, day.month)[1]
    if day.day >= last_dom - 2:           # last 3 days of the month
        if user.domain == "FIN":
            factor *= 1.8                 # month-end financial close
        elif user.domain in ("EXE", "OPS"):
            factor *= 1.25
    return factor
