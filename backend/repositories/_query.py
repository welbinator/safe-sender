"""Tiny query-builder helpers used by repositories.

Purpose
-------
F-33 — keep WHERE-clause construction *uniform* and remove manual ``idx``
bookkeeping. Hand-rolled ``idx += 1`` loops in every repo are how off-by-one
parameter mismatches and accidental ``f"... {user_input} ..."`` slip in.

This module exposes one type:

* :class:`WhereBuilder` — append ``(fragment_with_placeholder, value)`` pairs;
  it allocates the next ``$N`` for you and yields ``(sql, params, next_idx)``.

Design notes
------------
* Only **literal** SQL fragments are accepted. Callers pass a *format string*
  with a single ``{}`` (or ``{p}``) marker; we substitute the placeholder we
  allocate. We never embed values into SQL.
* Builder is single-use. After ``finish()`` it raises on further appends —
  prevents accidental "build twice, get two sets of params" bugs.
* ``join`` is fixed to ``AND``. If you ever need ``OR`` groups, build a sub-
  builder and pass its ``sql`` as a single fragment.
"""
from __future__ import annotations

from typing import Any, Iterable


class WhereBuilder:
    """Compose a parameterised SQL WHERE clause without juggling ``$N``."""

    __slots__ = ("_fragments", "_params", "_next_idx", "_finished")

    def __init__(self, *, start_idx: int = 1) -> None:
        if start_idx < 1:
            raise ValueError("start_idx must be >= 1 (asyncpg uses $1-based)")
        self._fragments: list[str] = []
        self._params: list[Any] = []
        self._next_idx: int = start_idx
        self._finished: bool = False

    # ---- building ------------------------------------------------------

    def append(self, fragment: str, value: Any) -> None:
        """Add ``fragment`` with one bound param.

        ``fragment`` must contain exactly one ``{}`` marker which we
        replace with the next ``$N``. Example::

            wb.append("l.outcome = {}", "blocked")
            # -> "l.outcome = $3"
        """
        if self._finished:
            raise RuntimeError("WhereBuilder already finished")
        if fragment.count("{}") != 1:
            raise ValueError(
                f"fragment must contain exactly one '{{}}' marker: {fragment!r}"
            )
        placeholder = f"${self._next_idx}"
        self._fragments.append(fragment.format(placeholder))
        self._params.append(value)
        self._next_idx += 1

    def append_raw(self, fragment: str, *values: Any) -> None:
        """Add a fragment containing N ``{}`` markers, one param each."""
        if self._finished:
            raise RuntimeError("WhereBuilder already finished")
        count = fragment.count("{}")
        if count != len(values):
            raise ValueError(
                f"fragment has {count} markers but {len(values)} values"
            )
        placeholders = tuple(f"${self._next_idx + i}" for i in range(count))
        self._fragments.append(fragment.format(*placeholders))
        self._params.extend(values)
        self._next_idx += count

    def append_static(self, fragment: str) -> None:
        """Add a value-free fragment (e.g. ``"l.deleted_at IS NULL"``)."""
        if self._finished:
            raise RuntimeError("WhereBuilder already finished")
        if "{" in fragment or "$" in fragment:
            raise ValueError(
                "append_static fragment must contain no placeholders; "
                "use append/append_raw if you need params"
            )
        self._fragments.append(fragment)

    def extend(self, pairs: Iterable[tuple[str, Any]]) -> None:
        for f, v in pairs:
            self.append(f, v)

    # ---- finishing -----------------------------------------------------

    @property
    def next_idx(self) -> int:
        """Next ``$N`` index a caller may use for trailing LIMIT/OFFSET."""
        return self._next_idx

    def finish(self, *, default_if_empty: str = "TRUE") -> tuple[str, list[Any]]:
        """Return ``(where_sql, params)`` and lock the builder.

        Empty builders return ``default_if_empty`` so callers can always
        splice ``f"WHERE {where}"`` without conditionals.
        """
        self._finished = True
        if not self._fragments:
            return default_if_empty, []
        return " AND ".join(self._fragments), list(self._params)
