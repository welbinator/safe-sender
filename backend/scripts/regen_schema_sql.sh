#!/usr/bin/env bash
# F-24: regenerate db/schema.sql from a freshly migrated database so it
# can never drift away from what Alembic actually produces.
#
# Usage:
#   ./scripts/regen_schema_sql.sh                  # write into db/schema.sql
#   CHECK=1 ./scripts/regen_schema_sql.sh          # exit 1 on drift; print diff
#
# Environment:
#   PGURL=postgresql://...   use an existing PG instead of spinning one up
#                            (must be empty / safe to wipe — alembic upgrade only)
#
# Requires: psql, pg_dump. If PGURL is unset, also requires docker OR a local
# pg_ctl/initdb (Debian/Ubuntu: /usr/lib/postgresql/<ver>/bin).
set -euo pipefail

cd "$(dirname "$0")/.."   # backend/
OUT="db/schema.sql"
TMP="$(mktemp)"

PGCTL_DIR=""
DOCKER_NAME=""
cleanup() {
    [[ -n "$DOCKER_NAME" ]] && docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true
    if [[ -n "$PGCTL_DIR" ]]; then
        # find pg_ctl on PATH or in /usr/lib/postgresql/*/bin
        local pgctl
        pgctl="$(command -v pg_ctl || ls /usr/lib/postgresql/*/bin/pg_ctl 2>/dev/null | head -1)"
        [[ -n "$pgctl" ]] && "$pgctl" -D "$PGCTL_DIR" stop -m immediate >/dev/null 2>&1 || true
        rm -rf "$PGCTL_DIR"
    fi
    rm -f "$TMP"
}
trap cleanup EXIT

if [[ -z "${PGURL:-}" ]]; then
    PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        DOCKER_NAME="schema-regen-$$"
        docker run -d --rm --name "$DOCKER_NAME" \
            -e POSTGRES_PASSWORD=regen \
            -e POSTGRES_DB=regen \
            -p "127.0.0.1:${PORT}:5432" \
            postgres:16-alpine >/dev/null
        for _ in $(seq 1 30); do
            PGPASSWORD=regen psql -h 127.0.0.1 -p "$PORT" -U postgres -d regen \
                -c '\q' >/dev/null 2>&1 && break
            sleep 1
        done
        PGURL="postgresql://postgres:regen@127.0.0.1:${PORT}/regen"
    else
        # Docker-less path: spin up a throwaway cluster as the current user.
        PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
        if [[ -z "$PGBIN" || ! -x "$PGBIN/initdb" ]]; then
            echo "ERROR: need docker, or postgresql-server tools (initdb/pg_ctl) on PATH." >&2
            exit 1
        fi
        PGCTL_DIR="$(mktemp -d -t pg-regen-XXXX)"
        "$PGBIN/initdb" -D "$PGCTL_DIR" -U postgres --auth=trust \
            --no-locale --encoding=UTF8 >/dev/null 2>&1
        {
            echo "unix_socket_directories = '/tmp'"
            echo "port = $PORT"
            echo "listen_addresses = ''"
        } >> "$PGCTL_DIR/postgresql.conf"
        "$PGBIN/pg_ctl" -D "$PGCTL_DIR" -l "$PGCTL_DIR/pg.log" -o "-k /tmp" -w start >/dev/null
        psql -h /tmp -p "$PORT" -U postgres -d postgres -c "CREATE DATABASE regen;" >/dev/null
        PGURL="postgresql://postgres@/regen?host=/tmp&port=${PORT}"
    fi
fi

export DATABASE_URL="$PGURL"
alembic upgrade head >/dev/null

# --schema-only: structure, no data. --no-owner/--no-privileges keep the dump
# portable. We post-process to:
#   * drop psql comment lines (`--`)
#   * drop alembic_version table block (bookkeeping, not schema)
#   * drop `\restrict` / `\unrestrict` lines emitted by pg_dump >= 16.14
#     (they embed a random nonce, would make the dump non-deterministic)
PGURL_FOR_DUMP="$PGURL"
pg_dump "$PGURL_FOR_DUMP" \
    --schema-only --no-owner --no-privileges --no-comments \
    | grep -v '^--' \
    | grep -Ev '^\\(unrestrict|restrict)\b' \
    | awk 'BEGIN{skip=0} /CREATE TABLE.*alembic_version/{skip=1} skip && /^$/{skip=0; next} !skip' \
    > "$TMP"

if [[ "${CHECK:-0}" == "1" ]]; then
    if ! diff -u "$OUT" "$TMP"; then
        echo
        echo "ERROR: db/schema.sql is out of date." >&2
        echo "Run: ./scripts/regen_schema_sql.sh" >&2
        exit 1
    fi
    echo "schema.sql is in sync with alembic head."
else
    cp "$TMP" "$OUT"
    echo "Wrote $OUT"
fi
