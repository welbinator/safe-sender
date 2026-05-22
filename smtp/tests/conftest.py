"""
SMTP service test setup.

`smtp/main.py` fail-fasts at import time when INTERNAL_SHARED_SECRET is
missing or weak (<32 chars). Tests don't actually need a real secret —
they mock the HTTP layer — but they do need *something* importable.
Set strong placeholder env vars before any test module imports `main`.
"""
import os

_STRONG = "T3st-smtp-" + "x" * 48
os.environ.setdefault("INTERNAL_SHARED_SECRET", _STRONG)
os.environ.setdefault("AWS_REGION", "us-east-1")
