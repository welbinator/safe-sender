"""Shared repository helpers."""
from __future__ import annotations

from typing import Any, Optional, Union

import asyncpg

# A "connection-like" — either a pool (autocommit per call) or a
# checked-out connection / transaction. asyncpg's pool exposes the same
# fetch/fetchrow/fetchval/execute methods as a connection, so callers
# can pass either.
ConnLike = Union[asyncpg.Pool, asyncpg.Connection]


def _as_dict(row: Optional[asyncpg.Record]) -> Optional[dict[str, Any]]:
    return dict(row) if row is not None else None


def _as_dicts(rows: list[asyncpg.Record]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


class BaseRepository:
    """Holds the asyncpg connection-like and provides dict conversion.

    Subclasses are stateless beyond `self.conn`; safe to construct one
    per request.
    """

    __slots__ = ("conn",)

    def __init__(self, conn: ConnLike) -> None:
        self.conn = conn
