"""Source abstraction: a log source generates benign events and renders them
   both as a native log line (live/file/syslog path) and as an ECS document
   (backfill / _bulk path)."""
from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from ..org.model import Host, Org, User


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    fields: dict
    labels: dict = field(default_factory=dict)


class Source(ABC):
    name: str = "base"
    dataset: str = "generic"          # ECS data_stream.dataset -> logs-<dataset>-default

    @abstractmethod
    def daily_volume(self, user: User, rng: random.Random) -> int:
        """How many benign events this user produces for this source per active day."""

    @abstractmethod
    def make_event(self, user: User, host: Host, ts: datetime, org: Org,
                   rng: random.Random, persona=None) -> LogEvent | None:
        """Build one benign event. `persona` (optional) carries stable per-user
        attributes (browser, etc.) used by the live stream; None during backfill."""

    @abstractmethod
    def render_native(self, ev: LogEvent) -> str:
        """Native log line (what the real service would write)."""

    @abstractmethod
    def render_ecs(self, ev: LogEvent) -> dict:
        """ECS document equivalent (what the ingest pipeline would produce)."""

    # -- lifecycle ----------------------------------------------------------
    def bind(self, org: Org) -> None:
        """Called once by the engine after the organisation is generated, so a
        source can cache org-derived constants (domain suffix, server IPs, ...)."""
        self.org = org

    # -- live-stream hooks (defaults; sources override as needed) -----------
    def applies_to(self, user: User, host: Host) -> bool:
        """Whether this source produces activity for this user/host (e.g. OS-gated)."""
        return True

    def activity_weight(self, user: User) -> float:
        """Relative likelihood of being the source of a given activity event."""
        return 1.0

    def index(self) -> str:
        return f"logs-{self.dataset}-default"
