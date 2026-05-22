"""Alembic environment.

Reads DATABASE_URL from env. Converts asyncpg URLs to psycopg2 sync form
(Alembic itself uses sync SQLAlchemy). Migrations are plain SQL — no
autogenerate / no ORM model metadata.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the backend root importable so we can share db_url normalization
# with the rest of the app. env.py runs from backend/, so the parent
# directory of this file's parent is what we need on sys.path.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from db_url import normalize_database_url  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _sync_db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL is required to run Alembic migrations")
    # Force the psycopg2-compatible sync scheme. normalize_database_url
    # also percent-encodes any reserved characters in the password so
    # psycopg2's strict URL parser doesn't choke on unencoded '@', ':',
    # etc. that asyncpg's lenient parser tolerates.
    return normalize_database_url(raw, driver="postgresql")


def run_migrations_offline() -> None:
    context.configure(
        url=_sync_db_url(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = _sync_db_url()
    engine = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
