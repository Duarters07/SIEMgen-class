"""Configuration loading and small helpers."""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml


# config keys that name other files; resolved relative to the config file itself
# when they are not absolute and do not exist relative to the working directory.
_PATH_KEYS = (("leisure", "profiles"), ("behavior", "personas"), ("behavior", "work_profiles"),
              ("behavior", "llm", "cache_file"), ("elasticsearch", "ca_cert"),
              ("elasticsearch", "password_file"))


def load_config(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    _anchor_paths(cfg, path.resolve().parent.parent)
    return cfg


def _anchor_paths(cfg: dict, repo_root: Path) -> None:
    """Make `config/*.yaml` references work from any working directory: a relative
    path that is missing from the CWD but present next to the config file's parent
    (the repository root) is rewritten to that absolute location."""
    for keys in _PATH_KEYS:
        node = cfg
        for k in keys[:-1]:
            node = node.get(k) if isinstance(node, dict) else None
            if node is None:
                break
        if not isinstance(node, dict):
            continue
        val = node.get(keys[-1])
        if not val or not isinstance(val, str) or Path(val).is_absolute() or Path(val).exists():
            continue
        candidate = repo_root / val
        if candidate.exists():
            node[keys[-1]] = str(candidate)


def resolve_es_password(es_cfg: dict) -> str:
    """Resolve the Elasticsearch password, in order:
       1. `password` in the config,
       2. the ELASTIC_PASSWORD environment variable,
       3. a `password_file` (raw password, or a line `ELASTIC_PASSWORD=...`).
    This is a standalone repo that talks to the SIEM over the network — it does NOT
    read the SIEM repo's stack/.env."""
    es_cfg = es_cfg or {}
    pw = es_cfg.get("password") or ""
    if pw:
        return pw
    if os.environ.get("ELASTIC_PASSWORD"):
        return os.environ["ELASTIC_PASSWORD"]
    pf = es_cfg.get("password_file")
    if pf and Path(pf).exists():
        text = Path(pf).read_text()
        for line in text.splitlines():
            if line.startswith("ELASTIC_PASSWORD="):
                return line.split("=", 1)[1].strip()
        return text.strip()
    return ""


_REL = re.compile(r"^([+-]?\d+)\s*([smhd])$")


def parse_when(value: str | None, now: datetime) -> datetime:
    """Parse 'now', a relative offset ('-28d', '-2h'), or an ISO/absolute datetime."""
    if value is None or value == "now" or value == "":
        return now
    m = _REL.match(str(value).strip())
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        secs = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        return now + timedelta(seconds=n * secs)
    from dateutil import parser as dtparser  # lazy import

    dt = dtparser.parse(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def resolve_path(base_dir: str, path: str) -> str:
    """Prefix an (absolute) log path with base_dir so we can run off-box without root."""
    if not base_dir:
        return path
    return str(Path(base_dir) / path.lstrip("/"))
