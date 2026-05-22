"""
conftest.py — Sprint 3+ test setup.

Spins up a real Postgres instance (via the `pgserver` Python package which ships
its own postgres binaries — no system packages, no docker required) for the
session, applies the canonical schema + all migrations, and seeds the env vars
required by the FastAPI app *before* it is imported.

Why this design:
  * `backend/main.py` and friends fail-fast at import time on missing/weak
    DATABASE_URL, JWT_SECRET, INTERNAL_SHARED_SECRET — so env must be set
    before `from main import app`.
  * TestClient fires FastAPI's startup event in its own anyio event loop,
    which is where the asyncpg pool is created. We must NOT pre-create a
    pool here (would be in the wrong event loop → InterfaceError).
  * pgserver works in WSL/CI without docker; binaries come bundled.

Tests that genuinely need a live SMTP container or external services live in
`backend/tests/integration/` and are skipped by the default pytest run (see
`backend/pytest.ini`).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Strong placeholder secrets (>=32 chars, no weak-password substrings) — these
# satisfy the H-3 / JWT / INTERNAL_SHARED_SECRET startup guards.
# ---------------------------------------------------------------------------
_STRONG_JWT = "T3st-jwt-" + "x" * 48
_STRONG_INTERNAL = "T3st-int-" + "x" * 48
_STRONG_ADMIN = "T3st-adm-" + "x" * 48
_STRONG_DB_PW = "T3stPg-S3cure-x9-" + "y" * 24  # avoids 'changeme/secret/etc'


# ---------------------------------------------------------------------------
# pgserver bootstrap (session scope)
# ---------------------------------------------------------------------------
def _find_pgbin() -> Path:
    """Locate the bundled postgres binaries shipped with pgserver."""
    import pgserver  # noqa: F401  (ensures package is importable)

    pgmod = Path(sys.modules["pgserver"].__file__).parent
    binpath = pgmod / "pginstall" / "bin"
    if not (binpath / "postgres").exists():
        raise RuntimeError(f"pgserver postgres binary not found at {binpath}")
    return binpath


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def _pg_server():
    """Start a throwaway Postgres for the test session and yield its DSN."""
    pgbin = _find_pgbin()
    datadir = Path(tempfile.mkdtemp(prefix="ss-pgtest-"))
    port = _free_port()

    # initdb (trust auth — local sandbox only)
    subprocess.run(
        [
            str(pgbin / "initdb"),
            "-D",
            str(datadir),
            "-U",
            "postgres",
            "--auth=trust",
            "--auth-local=trust",
            "--encoding=utf8",
        ],
        check=True,
        capture_output=True,
    )

    logfile = datadir / "pg.log"
    subprocess.run(
        [
            str(pgbin / "pg_ctl"),
            "-D",
            str(datadir),
            "-o",
            f"-h 127.0.0.1 -p {port} -k {datadir}",
            "-l",
            str(logfile),
            "-w",
            "start",
        ],
        check=True,
        capture_output=True,
    )

    # Create app role + db with a strong password (URL-safe).
    db_name = "sendersafety_test"
    app_user = "ss_test"
    psql = [str(pgbin / "psql"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c"]
    subprocess.run(psql + [f"CREATE USER {app_user} WITH PASSWORD '{_STRONG_DB_PW}' SUPERUSER;"], check=True, capture_output=True)
    subprocess.run(psql + [f"CREATE DATABASE {db_name} OWNER {app_user};"], check=True, capture_output=True)

    # Apply schema + migrations in order.
    repo_root = Path(__file__).resolve().parents[1]  # backend/
    schema = repo_root / "db" / "schema.sql"
    migrations_dir = repo_root / "migrations"
    psql_db = [
        str(pgbin / "psql"), "-h", "127.0.0.1", "-p", str(port),
        "-U", app_user, "-d", db_name, "-v", "ON_ERROR_STOP=1", "-f",
    ]
    subprocess.run(psql_db + [str(schema)], check=True, capture_output=True)
    # pgserver doesn't ship contrib extensions (no pgcrypto). Shim
    # `gen_random_bytes(int)` with a pure-SQL equivalent so migration 008
    # (which uses `gen_random_bytes(32)` as a column default) applies cleanly.
    # Production Postgres still uses the real pgcrypto.
    pgcrypto_shim = (
        "CREATE OR REPLACE FUNCTION gen_random_bytes(n int) RETURNS bytea "
        "LANGUAGE sql VOLATILE AS $$ "
        "SELECT decode(string_agg(lpad(to_hex((random()*255)::int), 2, '0'), ''), 'hex') "
        "FROM generate_series(1, n); $$;"
    )
    subprocess.run(psql_db[:-1] + ["-c", pgcrypto_shim], check=True, capture_output=True)

    for sql_file in sorted(migrations_dir.glob("*.sql")):
        raw = sql_file.read_text()
        # Strip CREATE EXTENSION pgcrypto — shim above provides the function.
        scrubbed = "\n".join(
            line for line in raw.splitlines()
            if "CREATE EXTENSION" not in line.upper() or "PGCRYPTO" not in line.upper()
        )
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as tf:
            tf.write(scrubbed)
            tmp_path = tf.name
        try:
            subprocess.run(psql_db + [tmp_path], check=True, capture_output=True)
        finally:
            os.unlink(tmp_path)

    dsn = f"postgresql://{app_user}:{_STRONG_DB_PW}@127.0.0.1:{port}/{db_name}"

    yield {"dsn": dsn, "datadir": datadir, "port": port, "pgbin": pgbin}

    # Teardown
    try:
        subprocess.run(
            [str(pgbin / "pg_ctl"), "-D", str(datadir), "-m", "fast", "stop"],
            check=False, capture_output=True, timeout=10,
        )
    except Exception:
        pass
    shutil.rmtree(datadir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Env vars — must be set BEFORE `main` is imported by anything.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def _seed_env(_pg_server):
    os.environ["DATABASE_URL"] = _pg_server["dsn"]
    os.environ["JWT_SECRET"] = _STRONG_JWT
    os.environ["INTERNAL_SHARED_SECRET"] = _STRONG_INTERNAL
    os.environ["ADMIN_API_KEY"] = _STRONG_ADMIN
    os.environ["ADMIN_SECRET"] = _STRONG_ADMIN  # Sprint C1 admin panel auth
    os.environ["ALLOW_TEST_TOKENS"] = "1"
    # Ensure cookie can be set over http TestClient (no TLS).
    os.environ["COOKIE_INSECURE"] = "1"
    # Stop welcome-email background tasks from doing anything externally —
    # boto3 will still try to read creds; we set a region but no creds, so
    # the background task will fail silently (handler swallows exceptions).
    os.environ.setdefault("AWS_REGION", "us-east-1")
    # Tests don't enforce Google Workspace `hd`.
    os.environ.setdefault("WORKSPACE_ONLY", "0")
    yield


# ---------------------------------------------------------------------------
# TestClient — session-scoped so FastAPI startup (asyncpg pool) runs once.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def client(_seed_env):
    # Make `backend/` importable as a top-level package root regardless of cwd.
    backend_dir = str(Path(__file__).resolve().parents[1])
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    # Clear any cached imports that captured env vars at import time.
    for mod in ("main", "auth_utils", "internal_auth"):
        sys.modules.pop(mod, None)
    for mod in list(sys.modules):
        if mod.startswith("routers"):
            sys.modules.pop(mod, None)

    from fastapi.testclient import TestClient
    from main import app

    with TestClient(app) as c:
        yield c
