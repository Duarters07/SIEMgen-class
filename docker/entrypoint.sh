#!/bin/sh
# Container entrypoint.
#
#  1. If started as root (the default), make the bind-mounted /logs writable by the
#     unprivileged account PUID:PGID (default 1000:1000 — set them to your own
#     `id -u` / `id -g` so the files on the host belong to you), then drop
#     privileges. Docker creates a missing ./logs on the host as root, which is why
#     this step exists.
#  2. Translate SIEMGEN_* environment variables into `siemgen generate` arguments.
#     Extra command-line arguments are passed through unchanged, so
#         docker compose run --rm siemgen gen-org
#     still works.
set -eu

CONFIG="${SIEMGEN_CONFIG:-/app/config/classroom.yaml}"
OUT="${SIEMGEN_OUT:-/logs}"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$OUT"
    if [ "$(stat -c %u "$OUT")" != "$PUID" ] || [ "$(stat -c %g "$OUT")" != "$PGID" ]; then
        chown "$PUID:$PGID" "$OUT" 2>/dev/null || true
        find "$OUT" -maxdepth 1 -name '.siemgen-state*' -exec chown "$PUID:$PGID" {} + 2>/dev/null || true
    fi
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups \
         env HOME=/tmp SIEMGEN_CONFIG="$CONFIG" SIEMGEN_OUT="$OUT" "$0" "$@"
fi

if [ "$#" -gt 0 ]; then
    exec siemgen -c "$CONFIG" "$@"
fi

if [ -z "${SIEMGEN_SEED:-}" ]; then
    echo "[siemgen] SIEMGEN_SEED is not set — using 1337. Every group should set its own seed" >&2
    echo "[siemgen] (e.g. SIEMGEN_SEED=42 docker compose up, or in a .env file)." >&2
fi

# Validate the environment before starting, with a message a student can act on.
fail() { echo "[siemgen] ERROR: $1" >&2; echo "[siemgen]        fix it in .env and run 'docker compose up' again." >&2; exit 1; }
is_int()  { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }
is_num()  { case "$1" in ''|*[!0-9.]*|*.*.*) return 1;; *) return 0;; esac; }
is_int "${SIEMGEN_SEED:-1337}"  || fail "SIEMGEN_SEED must be a whole number (e.g. 42), got '${SIEMGEN_SEED}'"
is_int "${SIEMGEN_USERS:-20}"   || fail "SIEMGEN_USERS must be a whole number, got '${SIEMGEN_USERS}'"
is_int "${SIEMGEN_DAYS:-14}"    || fail "SIEMGEN_DAYS must be a whole number, got '${SIEMGEN_DAYS}'"
is_num "${SIEMGEN_SPEED:-1}"    || fail "SIEMGEN_SPEED must be a number (e.g. 1 or 12), got '${SIEMGEN_SPEED}'"
case "${SIEMGEN_MODE:-both}" in history|live|both) ;; *) fail "SIEMGEN_MODE must be history, live or both, got '${SIEMGEN_MODE}'";; esac
case "${SIEMGEN_ORG:-acme-corp}" in *[!A-Za-z0-9._-]*) fail "SIEMGEN_ORG may only contain letters, digits, '-', '_' and '.', got '${SIEMGEN_ORG}'";; esac

set -- generate --out "$OUT" --seed "${SIEMGEN_SEED:-1337}"
[ -n "${SIEMGEN_ORG:-}" ]   && set -- "$@" --org   "$SIEMGEN_ORG"
[ -n "${SIEMGEN_USERS:-}" ] && set -- "$@" --users "$SIEMGEN_USERS"
[ -n "${SIEMGEN_DAYS:-}" ]  && set -- "$@" --days  "$SIEMGEN_DAYS"
[ -n "${SIEMGEN_MODE:-}" ]  && set -- "$@" --mode  "$SIEMGEN_MODE"
[ -n "${SIEMGEN_SPEED:-}" ] && set -- "$@" --speed "$SIEMGEN_SPEED"
[ -n "${SIEMGEN_TICK:-}" ]  && set -- "$@" --tick  "$SIEMGEN_TICK"

exec siemgen -c "$CONFIG" "$@"
