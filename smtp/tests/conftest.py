"""
SMTP service test setup.

`smtp/main.py` fail-fasts at import time when INTERNAL_SHARED_SECRET is
missing or weak (<32 chars). Tests don't actually need a real secret —
they mock the HTTP layer — but they do need *something* importable.
Set strong placeholder env vars before any test module imports `main`.
"""
import os
import sys
from pathlib import Path as _Path

# S-L4 — shared safesender_crypto package import path for non-Docker test runs.
sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "shared"))

_STRONG = "T3st-smtp-" + "x" * 48
os.environ.setdefault("INTERNAL_SHARED_SECRET", _STRONG)
os.environ.setdefault("AWS_REGION", "us-east-1")
