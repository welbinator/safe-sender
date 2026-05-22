#!/usr/bin/env bash
# F-24: regenerate db/schema.sql from a freshly migrated database so it
# can never drift away from what Alembic actually produces.
#
# Usage:
#   ./scripts/regen_schema_sql.sh                  # write into db/schema.sql
#   CHECK=1 ./scripts/regen_schema_sql.sh          # exit 1 on drift; print diff
#
# Requires: docker (for the throwaway postgres), psql, pg_dump.
set -euo pipefail

cd "$(dirname "$0")/.."   # backend/
OUT="db/schema.sql"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Pick an unused port to avoid collisions on dev machines.
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"
NAME="schema-regen-$$"

docker run -d --rm --name "$NAME" \
    -e POSTGRES_PASSWORD=regen \
    -e POSTGRES_DB=regen \
    -p "127.0.0.1:${PORT}:5432" \
    postgres:16-alpine >/dev/null

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap 'cleanup; rm -f "$TMP"' EXIT

# Wait for postgres to accept connections.
for _ in $(seq 1 30); do
    if PGPASSWORD=regen psql -h 127.0.0.1 -p "$PORT" -U postgres -d regen \
            -c '\q' >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

export DATABASE_URL="postgresql://postgres:regen@127.0.0.1:${PORT}/regen"
alembic upgrade head >/dev/null

# --schema-only: structure, no data. --no-owner / --no-privileges keep the
# dump portable. Strip the alembic_version table — it's bookkeeping, not
# schema we care about diffing.
PGPASSWORD=regen pg_dump -h 127.0.0.1 -p "$PORT" -U postgres -d regen \
    --schema-only --no-owner --no-privileges --no-comments \
    | grep -v '^--' \
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
