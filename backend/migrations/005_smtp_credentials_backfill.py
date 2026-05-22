#!/usr/bin/env python3
"""
One-time backfill: generate SMTP credentials for existing customers
that don't have them yet. Run once after deploying Sprint 7.

By default, plaintext passwords are NOT printed to stdout (audit F-09).
The customer must rotate via the admin "Reset SMTP Password" flow to
obtain a one-shot plaintext.

To restore the legacy behavior (print plaintext to stdout — e.g. for
a one-off ops backfill where the operator will hand-deliver creds),
set BACKFILL_REVEAL_PASSWORDS=1.

Usage:
    python 005_smtp_credentials_backfill.py
    BACKFILL_REVEAL_PASSWORDS=1 python 005_smtp_credentials_backfill.py
"""
import asyncio
import os
import secrets

import asyncpg
import bcrypt
from dotenv import load_dotenv

load_dotenv("/opt/safe-sender/.env")

DB_DSN = os.environ["DATABASE_URL"]
REVEAL = os.environ.get("BACKFILL_REVEAL_PASSWORDS", "0") == "1"


async def main():
    conn = await asyncpg.connect(DB_DSN)
    rows = await conn.fetch(
        "SELECT id, domain, email FROM customers WHERE smtp_username IS NULL"
    )
    if not rows:
        print("No customers need backfill.")
        return

    print(f"Backfilling {len(rows)} customer(s)...")
    if REVEAL:
        print("WARNING: BACKFILL_REVEAL_PASSWORDS=1 — plaintext will be printed.\n")
    else:
        print(
            "Plaintext passwords suppressed (set BACKFILL_REVEAL_PASSWORDS=1 to show).\n"
            "Customers must rotate via admin to obtain credentials.\n"
        )

    for row in rows:
        username = "ss_" + secrets.token_hex(8)
        password = secrets.token_urlsafe(16)
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        await conn.execute(
            "UPDATE customers SET smtp_username=$1, smtp_password_hash=$2 WHERE id=$3",
            username, password_hash, row["id"]
        )
        print(f"Customer: {row['email']} ({row['domain']})")
        print(f"  SMTP Username: {username}")
        if REVEAL:
            print(f"  SMTP Password: {password}")
        print()

    await conn.close()
    if REVEAL:
        print("Done. Save the passwords above — they won't be shown again.")
    else:
        print("Done. Have customers rotate via admin to receive plaintext.")


asyncio.run(main())
