"""Alembic environment.

Reads DATABASE_URL from env. Converts asyncpg URLs to psycopg2 sync form
(Alembic itself uses sync SQLAlchemy). Migrations are plain SQL — no
autogenerate / no ORM model metadata.
"""

import os
import re
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _sync_db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL is required to run Alembic migrations")
    # Strip async drivers — Alembic runs sync.
    url = re.sub(r"^postgres(ql)?\+asyncpg://", "postgresql://", raw)
    url = re.sub(r"^postgres://", "postgresql://", url)
    return url


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
