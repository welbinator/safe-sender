#!/usr/bin/env python3
"""
One-time backfill: generate SMTP credentials for existing customers
that don't have them yet. Run once after deploying Sprint 7.

Usage: python 005_smtp_credentials_backfill.py
"""
import asyncio
import os
import secrets

import asyncpg
import bcrypt
from dotenv import load_dotenv

load_dotenv("/opt/safe-sender/.env")

DB_DSN = os.environ["DATABASE_URL"]


async def main():
    conn = await asyncpg.connect(DB_DSN)
    rows = await conn.fetch(
        "SELECT id, domain, email FROM customers WHERE smtp_username IS NULL"
    )
    if not rows:
        print("No customers need backfill.")
        return

    print(f"Backfilling {len(rows)} customer(s)...\n")
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
        print(f"  SMTP Password: {password}")
        print()

    await conn.close()
    print("Done. Save the passwords above — they won't be shown again.")


asyncio.run(main())
