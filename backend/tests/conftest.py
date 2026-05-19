"""
Test setup: initialise a real asyncpg pool and inject it via FastAPI's
dependency_overrides so TestClient never needs the startup event to run.
"""
import asyncio
import os
from urllib.parse import urlparse

import asyncpg
import pytest


@pytest.fixture(scope="session", autouse=True)
def override_db_pool():
    from main import app
    from deps import get_pool as _app_get_pool

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://sendersafety:S3cur3P@ss2024@postgres:5432/sendersafety",
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

    # Override the FastAPI dependency so every request gets our pool directly
    def _get_pool_override():
        return pool

    app.dependency_overrides[_app_get_pool] = _get_pool_override

    yield

    app.dependency_overrides.clear()
    loop.run_until_complete(pool.close())
    loop.close()
