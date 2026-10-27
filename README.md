# SIEMgen-class

Synthetic security logs of a small company, in each product's **native format**, for the
practical class *Continuous monitoring and alert management* (Information Security Management).

One command gives every group its own company: about 20 people in seven departments, two weeks
of history and a live feed that keeps writing in real time. The generator never talks to a SIEM.
It only writes files; shipping them is the exercise (see
[MinimalSIEM](https://github.com/Duarters07/MinimalSIEM)).

Same seed, same company, same logs, on any machine. That is how answers are checked.

## Quick start

```bash
git clone https://github.com/Duarters07/SIEMgen-class.git && cd SIEMgen-class
cp .env.example .env            # set SIEMGEN_SEED (your group number), SIEMGEN_ORG, PUID/PGID
docker compose up -d --build
docker compose logs -f siemgen  # 14 days of history in ~30 s, then "live:" (Ctrl-C to leave)
cat logs/MANIFEST.txt           # the thirteen files and their line counts
```

Everything lands in `./logs`. Point your collector at that folder.

## Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `SIEMGEN_SEED` | `1337` | Your group number. Same seed, same company. Every group sets its own. |
| `SIEMGEN_ORG` | `acme-corp` | Company name. Gives the DNS suffix and the Windows domain (`blue-team` → `blue.local`, `BLUE`). |
| `SIEMGEN_USERS` | `20` | Employees. Each one gets a workstation. |
| `SIEMGEN_DAYS` | `14` | Days of history written before the live feed starts. |
| `SIEMGEN_MODE` | `both` | `history`, `live` or `both`. |
| `SIEMGEN_SPEED` | `1` | Live time compression. `1` is real time, `12` is one simulated day every two hours. |
| `PUID` / `PGID` | `1000` | Owner of the generated files. Use `id -u` / `id -g` so they belong to you. |

## What you get

Thirteen files under `logs/`, one per source, each in the format the real product writes:

| File | Source | Format |
|---|---|---|
| `nginx/access.log` | intranet web server | nginx combined |
| `auth.log` | Linux logins, sudo, SSH | syslog |
| `audit/audit.log` | Linux process executions | auditd |
| `suricata/eve.json` | network IDS (flows, TLS, QUIC, DNS) | EVE JSON |
| `pfsense/filterlog.log` | firewall | syslog, CSV body |
| `dnsmasq.log` | DNS resolver | syslog |
| `dhcpd.log` | DHCP leases | syslog |
| `openvpn.log` | VPN | syslog |
| `mail.log` | mail gateway (Postfix) | syslog |
| `windows/security.ndjson` | Windows Security (4624, 4625, 4688) | JSON per line |
| `windows/sysmon.ndjson` | Sysmon (1, 3, 11, 22) | JSON per line |
| `azure/signin.ndjson` | Microsoft 365 sign-ins | JSON per line |
| `nextcloud/audit.log` | private cloud | JSON per line |

`MANIFEST.txt` lists the company name, its servers and the line count of every file. It is the
ground truth for checking ingestion.

The company itself: workstations at `10.<site>.<dept>.<n>` (site 10 headquarters, 20 branch,
30 remote via VPN; dept 1 IT, 2 HR, 3 Finance, 4 Legal, 5 Operations, 6 Executives, 7 general
staff), servers at `10.10.0.x`, IT and Operations on Linux, everyone else on Windows, office hours
09–17 UTC. Each person has a profile (focused, distracted, IT admin, executive) that drives a
state machine of working, meeting, leisure, mixed and absent. The background deliberately contains
a few 401s, failed logins, blocked inbound probes and bounced mail. **There are no attacks in the
generated data** (see Level 4 below for the one you trigger yourself).

## Useful commands

```bash
# print the company: users, departments, workstations, IPs (no logs written)
docker compose run --rm siemgen gen-org --seed 42 --org blue-team

# stop and resume (the live feed continues where it stopped)
docker compose stop siemgen
docker compose up -d siemgen

# start over with a different seed or company
docker compose down
rm -rf logs                       # the run identity lives in logs/.siemgen-state.json
docker compose up -d --build
```

The state file in `logs/` records the seed, the company and the last written timestamp. Starting
the container with the same values resumes; starting it with different ones refuses with
"belongs to another run". Delete `logs/` to regenerate.

## Level 4: the simulated attack

The generated data contains **no attacks**. `incident` appends ONE short intrusion to the files of
the running company, in the same native formats, so you can check that your detection rules fire.
It only writes lines under `logs/`; nothing is sent over the network.

```bash
docker compose run --rm siemgen incident      # all at once, timestamps ending now
docker compose run --rm siemgen incident --live   # in real time, about 4 minutes
```

Write your rules **before** you run it. The scenario (`outside-login`): a forgotten port-forward
lets SSH in from the internet to the web server, an external address guesses passwords, gets in
as a real IT admin without a VPN session, reads `/etc/shadow` as root and creates a sudo account.
The company, the account and the addresses come from the run's seed (read from
`logs/.siemgen-state.json`). Instructors: `--dry-run --reveal` prints the lines and the answer
without writing anything. Running it twice writes two incidents.

## Without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
siemgen -c config/classroom.yaml generate --seed 42 --org blue-team --out ./logs
siemgen -c config/classroom.yaml gen-org  --seed 42 --org blue-team
siemgen -c config/classroom.yaml incident --out ./logs
```

Python 3.10 or newer. The same `--users`, `--days`, `--mode` and `--speed` flags as the
environment variables above.

## Layout

```
config/            classroom.yaml (profile used by Docker), personas, work and leisure profiles
docker/            Dockerfile and entrypoint (drops to PUID:PGID, maps SIEMGEN_* to flags)
siemgen/           the generator: org/ builds the company, behavior/ runs each person's day,
                   sources/ write the thirteen formats, sinks/ write files
docker-compose.yml the siemgen service; the collector service is yours to add
```

The `backfill`, `stream` and `seed-registry` subcommands belong to the research version of the
generator and are not used in class.

## License

MIT.
