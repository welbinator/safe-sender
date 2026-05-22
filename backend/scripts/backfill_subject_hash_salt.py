"""Backfill / verify per-customer ``subject_hash_salt`` (F-25).

Background
----------
Migration ``008_sprint_b_privacy.sql`` added the column with
``DEFAULT gen_random_bytes(32)`` so every row should already have a
random 32-byte value.  In practice the audit found rows that were
inserted around the same time as the migration ran (or restored from
an older dump) where the salt is missing, all-zeros, or shorter than
32 bytes.  Those customers' subject hashes are effectively unsalted.

What this script does
---------------------
1. Counts customers whose salt is NULL, shorter than 32 bytes, or all
   zero bytes.
2. For each, generates a fresh ``os.urandom(32)`` and UPDATEs the row
   inside a single transaction. Logs the customer id (NOT the salt
   itself) for audit.
3. Re-checks afterwards and exits non-zero if any bad rows remain.

Side effects
------------
Re-salting a customer invalidates every existing ``subject_hash`` in
``scan_logs`` for that customer — those hashes were derived with the
old (broken) salt.  We don't rewrite scan_logs; historical hashes just
become opaque and uncomparable.  That is the correct behaviour: the
whole point of a per-customer salt is that nothing outside the
customer's own future scans can correlate against the hash.

Usage
-----
On the app server with DATABASE_URL exported::

    cd backend
    python scripts/backfill_subject_hash_salt.py            # dry-run
    python scripts/backfill_subject_hash_salt.py --apply    # write

The script is idempotent — running it twice with --apply is safe.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Make backend root importable.
_HERE = Path(__file__).resolve().parent
_BACKEND_ROOT = _HERE.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

import asyncpg  # noqa: E402

from db_url import normalize_database_url  # noqa: E402

ZERO_32 = b"\x00" * 32

_BAD_ROW_SQL = """
    SELECT id, COALESCE(octet_length(subject_hash_salt), 0) AS len, subject_hash_salt
    FROM customers
    WHERE subject_hash_salt IS NULL
       OR octet_length(subject_hash_salt) <> 32
       OR subject_hash_salt = $1
"""


async def _connect() -> asyncpg.Connection:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL is required")
    url = normalize_database_url(raw, driver="postgresql+asyncpg").replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    return await asyncpg.connect(url)


async def _run(apply: bool) -> int:
    conn = await _connect()
    try:
        bad = await conn.fetch(_BAD_ROW_SQL, ZERO_32)
        if not bad:
            print("OK: every customer row already has a 32-byte non-zero salt.")
            return 0

        print(f"Found {len(bad)} customer(s) with a missing/invalid salt:")
        for row in bad:
            reason = "NULL" if row["subject_hash_salt"] is None else (
                "all-zero" if bytes(row["subject_hash_salt"]) == ZERO_32
                else f"len={row['len']}"
            )
            print(f"  - {row['id']}  ({reason})")

        if not apply:
            print("\nDRY RUN — pass --apply to repair. No rows changed.")
            return 0

        async with conn.transaction():
            for row in bad:
                new_salt = os.urandom(32)
                await conn.execute(
                    "UPDATE customers SET subject_hash_salt = $1 WHERE id = $2",
                    new_salt,
                    row["id"],
                )
                print(f"  repaired {row['id']}")

        # Re-verify under the same connection.
        remaining = await conn.fetch(_BAD_ROW_SQL, ZERO_32)
        if remaining:
            print(
                f"ERROR: {len(remaining)} row(s) still bad after backfill",
                file=sys.stderr,
            )
            return 1
        print(f"\nDone. Repaired {len(bad)} row(s).")
        return 0
    finally:
        await conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Backfill subject_hash_salt (F-25)")
    p.add_argument("--apply", action="store_true", help="Write the new salts.")
    args = p.parse_args()
    return asyncio.run(_run(args.apply))


if __name__ == "__main__":
    sys.exit(main())
