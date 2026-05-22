"""Reconcile alembic_version on a database that was bootstrapped from
``schema.sql`` instead of by running migrations (F-23).

Symptom
-------
Prod's database was created by piping the legacy ``schema.sql`` directly
into psql, then we adopted Alembic later. ``alembic_version`` either
doesn't exist or doesn't contain the row that says "this schema is at
revision X".  Running ``alembic upgrade head`` from that state re-runs
every migration, which fails because the tables already exist.

Fix
---
Tell Alembic the schema already matches the latest revision (HEAD)
without actually executing any migration SQL. That writes the row to
``alembic_version`` and makes future ``upgrade head`` calls no-ops up
until new migrations are added.

Usage
-----
On the prod app server, with ``DATABASE_URL`` exported::

    cd backend
    python scripts/alembic_reconcile.py

The script is idempotent. If ``alembic_version`` is already at HEAD,
it prints the row and exits 0. If it's at a different revision, it
*refuses* to clobber it — that case needs a human to decide whether to
``alembic upgrade`` or ``alembic stamp`` to a specific revision.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make backend root importable when run from backend/ or from scripts/.
_HERE = Path(__file__).resolve().parent
_BACKEND_ROOT = _HERE.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from db_url import normalize_database_url  # noqa: E402


def _cfg() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    return cfg


def _head_revision(cfg: Config) -> str:
    return ScriptDirectory.from_config(cfg).get_current_head()


def _current_db_revision(sync_url: str) -> str | None:
    engine = create_engine(sync_url)
    with engine.connect() as conn:
        exists = conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'alembic_version'"
            )
        ).scalar()
        if not exists:
            return None
        row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
        return row[0] if row else None


def main() -> int:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        print("ERROR: DATABASE_URL is required", file=sys.stderr)
        return 2
    sync_url = normalize_database_url(raw, driver="postgresql")

    cfg = _cfg()
    head = _head_revision(cfg)
    current = _current_db_revision(sync_url)

    if current == head:
        print(f"alembic_version already at HEAD ({head}); nothing to do")
        return 0

    if current is not None:
        print(
            f"REFUSING TO RECONCILE: alembic_version is at {current!r}, "
            f"HEAD is {head!r}. This is not a fresh-from-schema.sql DB. "
            f"Run `alembic upgrade head` or `alembic stamp <rev>` manually.",
            file=sys.stderr,
        )
        return 1

    print(f"alembic_version missing; stamping to HEAD {head}")
    command.stamp(cfg, "head")
    after = _current_db_revision(sync_url)
    print(f"Done. alembic_version now reads {after!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
