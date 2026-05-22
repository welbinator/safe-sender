#!/usr/bin/env bash
#
# One-time bootstrap for an existing Postgres that already has the
# legacy schema applied (i.e. production). Tells Alembic "you're
# already at the baseline revision" without running any DDL.
#
# Run this ONCE on every existing environment after deploying the
# code that introduces Alembic. Idempotent — re-running is a no-op.
#
# Required env: DATABASE_URL
#
# After this, normal `alembic upgrade head` runs only NEW migrations.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL is required" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

# Already stamped? Bail.
if alembic current 2>/dev/null | grep -q "20260521_0001"; then
  echo "Already stamped at baseline — nothing to do."
  exit 0
fi

echo "Stamping existing database at baseline revision 20260521_0001..."
alembic stamp 20260521_0001
echo "Done. Future schema changes: alembic revision -m '...' && alembic upgrade head"
