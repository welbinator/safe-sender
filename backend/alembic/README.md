# Alembic migrations

All schema changes go through Alembic from Sprint C1 onwards.

## Layout

- `alembic.ini` (in `backend/`) — config
- `alembic/env.py` — reads `DATABASE_URL` from env
- `alembic/versions/` — migrations (one Python file per revision)
- `backend/migrations/*.sql` — **legacy, frozen.** Do not add new files
  here. They are bundled into the baseline revision `20260521_0001` and
  must remain unchanged so existing prod databases stay consistent.

## Common commands

```bash
cd backend

# Apply all pending migrations.
alembic upgrade head

# Create a new (empty) migration.
alembic revision -m "add foo column to bar"

# Show current revision.
alembic current

# Show migration history.
alembic history --verbose

# Mark an existing DB as up-to-date without running anything (used once,
# on prod, the first time we deploy Alembic — the legacy SQL is already
# applied so we just stamp the baseline revision).
alembic stamp head
```

## Production cut-over

1. Deploy this build (Alembic installed, baseline migration present).
2. On the prod DB, run `alembic stamp 20260521_0001` once. This records
   the baseline as applied without re-running it.
3. From now on every release runs `alembic upgrade head` before the app
   starts (or via a deploy hook).
