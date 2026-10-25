"""Simulated business clock: who works when, and a diurnal weighting for event times."""
from __future__ import annotations

import random
from datetime import datetime, timezone

from ..org.model import User
from .profiles import _stable_seed


class WorkClock:
    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def works_today(self, user: User, day: datetime) -> bool:
        wd = day.weekday()
        if wd in user.work_days:
            return True
        # IT/EXE occasionally work weekends (on-call / catching up). Seeded per
        # (user, day) so the decision is reproducible across runs.
        if user.role in ("it-admin", "c-level"):
            r = random.Random(_stable_seed(self.seed, "weekend", user.username, day.toordinal()))
            return r.random() < 0.25
        return False

    def _hour_weights(self, user: User) -> list[tuple[int, float]]:
        """Diurnal curve across the user's working hours (lunch dip, ramp)."""
        hours = list(range(user.work_start, user.work_end))
        weights = []
        span = max(1, len(hours))
        for i, h in enumerate(hours):
            w = 1.0
            # ramp up at start, taper at end
            if i < 2:
                w *= 0.6
            if i > span - 3:
                w *= 0.7
            # lunch dip around 12-13 UTC-ish
            if h in (12, 13):
                w *= 0.5
            weights.append((h, w))
        return weights

    def hour_weights_map(self, user: User) -> dict[int, float]:
        return {h: w for h, w in self._hour_weights(user)}

    def sample_time(self, user: User, day: datetime, rng: random.Random) -> datetime:
        hw = self._hour_weights(user)
        hours = [h for h, _ in hw]
        weights = [w for _, w in hw]
        hour = rng.choices(hours, weights=weights, k=1)[0]
        return day.replace(
            hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59),
            microsecond=rng.randint(0, 999) * 1000, tzinfo=timezone.utc,
        )
