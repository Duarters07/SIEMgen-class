"""siemgen command-line interface."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .config import load_config, parse_when, resolve_es_password
from .engine import Engine
from .org import generate_org

DEFAULT_CONFIG = "config/classroom.yaml"


def _summary(org) -> str:
    by_dom = Counter(u.domain for u in org.users)
    return (f"org '{org.name}' ({org.dns_domain} / {org.windows_domain}): {len(org.users)} users, "
            f"{len(org.hosts)} hosts, {len(org.servers)} servers | by domain: "
            + ", ".join(f"{d}:{n}" for d, n in sorted(by_dom.items())))


def _apply_overrides(cfg: dict, args) -> dict:
    """--seed / --org / --users / --out override the YAML (CLI wins)."""
    if getattr(args, "seed", None) is not None:
        cfg["seed"] = int(args.seed)
    org = cfg.setdefault("organization", {})
    if getattr(args, "org", None):
        org["name"] = args.org
    if getattr(args, "users", None):
        org["users"] = int(args.users)
    if getattr(args, "out", None):
        cfg.setdefault("output", {})["base_dir"] = args.out
    return cfg


# --------------------------------------------------------------------------- #
# generate — files only, history + live, resumable                             #
# --------------------------------------------------------------------------- #
def cmd_generate(cfg, org, args):
    from .timeline import Timeline

    seed = int(cfg.get("seed", 1337))
    gcfg = cfg.get("generate", {}) or {}
    days = int(args.days if args.days is not None else gcfg.get("days", 14))
    mode = args.mode or gcfg.get("mode", "both")
    speed = float(args.speed if args.speed is not None else gcfg.get("speed", 1.0))
    tick = float(args.tick if args.tick is not None else gcfg.get("tick", 1.0))
    out = (cfg.get("output", {}) or {}).get("base_dir") or "./logs"

    eng = Engine(cfg, org, seed)
    eng.build("generate", default_sink="file")
    if not eng.director_on:
        print("[siemgen] WARNING: behavior.director is off — the timeline is not resumable "
              "and only a full run is reproducible. Enable `behavior.director: rules`.", flush=True)
    print(_summary(org))
    print(f"[siemgen] generate -> {Path(out).resolve()}  (mode={mode}, days={days}, speed=x{speed:g})")
    print(f"[siemgen] sources: {', '.join(eng.sources) or 'none enabled'}")

    tl = Timeline(eng, out, cfg, speed=speed, tick=tick)
    try:
        if mode in ("history", "both"):
            tl.history(days)
        if mode in ("live", "both"):
            tl.live()
    except SystemExit:
        eng.close_all()
        raise                              # refused run: leave the output directory untouched
    finally:
        eng.close_all()
        tl.save_state()
    print(f"[siemgen] done: {tl.events_total} events | manifest: {Path(out) / 'MANIFEST.txt'}")


# --------------------------------------------------------------------------- #
# legacy / thesis commands                                                     #
# --------------------------------------------------------------------------- #
def cmd_gen_org(cfg, org, args):
    out = Path(args.out or "org.generated.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(org.to_dict(), indent=2))
    print(_summary(org))
    print(f"[siemgen] wrote {out}")


def cmd_backfill(cfg, org, args):
    seed = int(cfg.get("seed", 1337))
    eng = Engine(cfg, org, seed)
    eng.build("backfill")
    now = datetime.now(timezone.utc)
    bf = (cfg.get("time", {}) or {}).get("backfill", {}) or {}
    start = parse_when(args.start or bf.get("start", "-28d"), now)
    end = parse_when(args.end or bf.get("end", "now"), now)
    print(_summary(org))
    print(f"[siemgen] backfilling {start.isoformat()} .. {end.isoformat()} "
          f"(sources: {', '.join(eng.sources) or 'none enabled'})")
    n = eng.backfill(start, end)
    eng.close_all()
    print(f"[siemgen] generated {n} events | {eng.stats()}")


def cmd_stream(cfg, org, args):
    seed = int(cfg.get("seed", 1337))
    eng = Engine(cfg, org, seed)
    eng.build("stream")
    print(_summary(org))
    eng.stream()
    eng.close_all()
    print(f"[siemgen] {eng.stats()}")


def cmd_list_scenarios(cfg, org, args):
    d = Path(args.dir or "config/scenarios")
    if not d.exists():
        print(f"[siemgen] no scenarios dir at {d}")
        return
    for f in sorted(d.glob("*.yaml")):
        print(f" - {f.stem}: {f}")


def cmd_seed_registry(cfg, org, args):
    """Best-effort: push org users/hosts to siem-entity-registry for triage context."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    es = cfg.get("elasticsearch", {}) or {}
    s = requests.Session()
    s.auth = (es.get("user", "elastic"), resolve_es_password(es))
    s.verify = es.get("ca_cert", "") or bool(es.get("verify", False))
    url = es.get("url", "https://localhost:9200").rstrip("/")
    index = "siem-entity-registry"

    lines = []
    for u in org.users:
        doc = {"entity_id": u.email, "entity_type": "user", "domain": u.domain,
               "domain_tier": u.tier, "asset_criticality": "high" if u.tier <= 2 else "low",
               "host": u.primary_host, "site": u.site, "role": u.role}
        lines.append(json.dumps({"index": {"_index": index, "_id": u.email}}))
        lines.append(json.dumps(doc))
    for h in org.hosts:
        doc = {"entity_id": h.name, "entity_type": "host", "domain": h.domain,
               "asset_criticality": h.criticality, "os": h.os, "ip": h.ip, "kind": h.kind}
        lines.append(json.dumps({"index": {"_index": index, "_id": h.name}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    r = s.post(f"{url}/_bulk", data=body.encode(),
               headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    r.raise_for_status()
    print(f"[siemgen] seeded {len(org.users)} users + {len(org.hosts)} hosts into {index}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="siemgen",
        description="SIEMgen — realistic synthetic security logs of a small company, in native formats.")
    p.add_argument("-c", "--config", default=None,
                   help=f"config YAML (default: {DEFAULT_CONFIG} if present, else config/org.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write native log files: N days of history, then a live feed")
    g.add_argument("--seed", type=int, help="dataset seed (each group uses its own number)")
    g.add_argument("--org", help="company name, e.g. blue-team -> blue.local / BLUE")
    g.add_argument("--users", type=int, help="number of employees")
    g.add_argument("--out", help="output directory (default: output.base_dir, ./logs)")
    g.add_argument("--days", type=int, help="days of history before now (default 14)")
    g.add_argument("--mode", choices=["history", "live", "both"], help="phase(s) to run (default both)")
    g.add_argument("--speed", type=float, help="live time compression, 1 = real time, 12 = a day in 2 h")
    g.add_argument("--tick", type=float, help="seconds between live flushes (real time)")

    go = sub.add_parser("gen-org", help="print the organisation and write it as JSON")
    go.add_argument("--out")
    go.add_argument("--seed", type=int)
    go.add_argument("--org")
    go.add_argument("--users", type=int)

    bf = sub.add_parser("backfill", help="(thesis) bulk-load history straight into Elasticsearch")
    bf.add_argument("--start")
    bf.add_argument("--end")
    sub.add_parser("stream", help="(thesis) continuous live generation to files/syslog")
    sub.add_parser("seed-registry", help="(thesis) push org to siem-entity-registry")
    sub.add_parser("list-scenarios", help="list scenario files").add_argument("--dir")

    args = p.parse_args(argv)
    cfg_path = args.config
    if cfg_path is None:
        cfg_path = DEFAULT_CONFIG if Path(DEFAULT_CONFIG).exists() else "config/org.yaml"
    cfg = _apply_overrides(load_config(cfg_path), args)
    org = generate_org(cfg, int(cfg.get("seed", 1337)))

    dispatch = {
        "generate": cmd_generate, "gen-org": cmd_gen_org, "backfill": cmd_backfill,
        "stream": cmd_stream, "list-scenarios": cmd_list_scenarios, "seed-registry": cmd_seed_registry,
    }
    dispatch[args.cmd](cfg, org, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
