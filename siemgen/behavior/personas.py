"""Behavioural archetypes and per-user trait sampling.

A *persona archetype* is a DISTRIBUTION of behavioural traits (config/personas.yaml).
Every user is assigned an archetype (its domain default, with ~15% mixed to another)
and then SAMPLES its own concrete traits from that distribution, stably from its
per-user seed. So two users of the same archetype are similar-but-distinct, fixed
individuals — which is what per-user UEBA baselines need.

These traits feed the Director's state machine (see director.py). In the default
`rules` mode without a director, the existing leisure path is unaffected; this module
only adds an optional, richer source of per-user behaviour.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..org.model import User
from .profiles import _stable_seed

# Catalogue of behavioural states the Director can choose from.
STATES = ["absent", "working", "leisure", "mixed", "meeting"]


def load_personas(path: str | None) -> dict | None:
    if not path or not Path(path).exists():
        return None
    data = yaml.safe_load(Path(path).read_text())
    return data if data and data.get("archetypes") else None


@dataclass
class Traits:
    """Concrete, stable behaviour of ONE user (sampled from its archetype)."""
    archetype: str
    distractibility: float          # 0..1 — how readily the user drifts off-task
    focus_bias: float               # 0..1 — resistance to interruption (mixed gating)
    leisure_propensity: float       # expected leisure sessions per work day
    meeting_propensity: float       # 0..1 — likelihood of meetings
    weekend_work_chance: float      # 0..1 — chance of working a weekend day
    slump_hour: int                 # hour-of-day the user tends to lose focus
    preferred_leisure: list[str] = field(default_factory=list)
    risco_aup: bool = False         # AUP-risk overlay (sensitive leisure)


def _uni(rng: random.Random, rng_spec) -> float:
    """Uniform draw from a [min, max] yaml pair (or a fixed scalar)."""
    if isinstance(rng_spec, (list, tuple)):
        return rng.uniform(float(rng_spec[0]), float(rng_spec[1]))
    return float(rng_spec)


def assign_archetype(user: User, pcfg: dict, seed: int) -> str:
    """Domain default archetype, with ~`mix_fraction` of users reassigned to a
    different (random) archetype so a team is not behaviourally uniform."""
    archetypes = list(pcfg["archetypes"].keys())
    base = (pcfg.get("domain_archetype", {}) or {}).get(user.domain, archetypes[0])
    r = random.Random(_stable_seed(seed, "archetype", user.username))
    if r.random() < pcfg.get("mix_fraction", 0.15):
        others = [a for a in archetypes if a != base] or archetypes
        return r.choice(others)
    return base


def sample_traits(user: User, pcfg: dict, seed: int) -> Traits:
    """Draw this user's stable concrete traits from its archetype distribution."""
    arch = assign_archetype(user, pcfg, seed)
    spec = pcfg["archetypes"][arch]
    r = random.Random(_stable_seed(seed, "traits", user.username))

    leisure_prop = _uni(r, spec["leisure_propensity"])

    pool = list(spec.get("leisure_pool", ["youtube"]))
    pick_lo, pick_hi = spec.get("leisure_pick", [1, 1])
    k = min(len(pool), r.randint(int(pick_lo), int(pick_hi))) if pool else 0
    prefs = r.sample(pool, k=k) if k else []

    # afternoon-biased "slump" hour inside the user's working window
    ws, we = user.work_start, max(user.work_start + 1, user.work_end)
    lo = min(max(ws + 1, 13), we - 1)
    slump = r.randint(lo, max(lo, we - 1))

    # AUP-risk overlay (~risco_aup_fraction of users, any archetype)
    risco = r.random() < pcfg.get("risco_aup_fraction", 0.06)
    if risco:
        leisure_prop *= pcfg.get("risco_aup_propensity_boost", 1.8)
        if "adult" not in prefs:
            prefs = prefs + ["adult"]

    return Traits(
        archetype=arch,
        distractibility=_uni(r, spec["distractibility"]),
        focus_bias=_uni(r, spec["focus_bias"]),
        leisure_propensity=leisure_prop,
        meeting_propensity=_uni(r, spec["meeting_propensity"]),
        weekend_work_chance=_uni(r, spec["weekend_work_chance"]),
        slump_hour=slump,
        preferred_leisure=prefs,
        risco_aup=risco,
    )


def offtask_from_traits(traits: Traits, leisure_cfg: dict | None) -> dict:
    """Adapt sampled traits to the {propensity, apps} shape the leisure engine
    expects — so the director's leisure states reuse the calibrated leisure motor.
    Apps are restricted to those that actually have a leisure profile."""
    apps = traits.preferred_leisure
    if leisure_cfg and leisure_cfg.get("profiles"):
        valid = set(leisure_cfg["profiles"].keys())
        apps = [a for a in apps if a in valid] or [a for a in valid if a != "adult"][:1]
    return {"propensity": traits.leisure_propensity, "apps": apps}
