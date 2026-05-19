"""
Test setup: initialise the asyncpg pool directly so TestClient tests have a
live DB connection without relying on the startup event (which requires the
entrypoint's DNS resolution to have already run).
"""
import asyncio
import os

import asyncpg
import pytest
from urllib.parse import urlparse


@pytest.fixture(scope="session", autouse=True)
def init_db_pool():
    import main

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://sendersafety:changeme@postgres:5432/sendersafety",
    )
    _u = urlparse(db_url)

    async def _setup():
        return await asyncpg.create_pool(
            host=_u.hostname,
            port=_u.port or 5432,
            user=_u.username,
            password=_u.password,
            database=_u.path.lstrip("/"),
            min_size=2,
            max_size=5,
            ssl=False,
            timeout=10,
        )

    loop = asyncio.new_event_loop()
    pool = loop.run_until_complete(_setup())
    main._pool = pool  # inject directly — bypasses the startup event
    yield
    loop.run_until_complete(pool.close())
    loop.close()
