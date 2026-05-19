"""
conftest.py — Sprint 3 test setup.

TestClient fires the FastAPI startup event in its own anyio event loop,
which creates the asyncpg pool correctly in that loop.  We must NOT
pre-create a pool here (different loop → InterfaceError).

DATABASE_URL is already set in the container environment with a raw IP
(written by entrypoint.py), so startup succeeds without DNS resolution.
"""
# Nothing to do — just let TestClient handle startup/shutdown naturally.
