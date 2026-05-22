"""DATABASE_URL normalization.

Why this exists: production passwords routinely contain characters that
have reserved meaning in URLs (``@``, ``:``, ``/``, ``#``, ``?``, ``%``,
``&``, ``=``, ``+``, space). ``urllib.parse.urlparse`` is lenient and
splits the userinfo on the *rightmost* ``@``, so most code paths
(asyncpg via explicit kwargs in ``main.py``) work fine even with an
unencoded ``@`` in the password.

psycopg2 — used transitively by Alembic — is *not* lenient: it parses
the URL itself and splits userinfo on the *leftmost* ``@``, which turns
a password like ``pass@ss2024`` into hostname ``ss2024`` and breaks
``alembic upgrade``.

The proper fix is to be tolerant on input (accept either encoded or
unencoded reserved characters in the password) and strict on output
(emit a fully percent-encoded URL that every PostgreSQL driver parses
the same way). This module does exactly that — call
``normalize_database_url(raw)`` once at startup and pass the result
to whatever needs a URL string.

Note on the parser: we intentionally do NOT use ``urlparse`` here.
Its leftmost-``@`` behavior is the very bug we're working around in
psycopg2 (they implement the same splitting). We hand-parse with
``rsplit('@', 1)`` so an unencoded ``@`` in the password is treated
as part of the password, matching what a human writing ``.env`` would
expect.
"""

from __future__ import annotations

from urllib.parse import quote


_DRIVER_PREFIXES = (
    "postgresql+asyncpg://",
    "postgresql+psycopg2://",
    "postgresql://",
    "postgres://",
)


def normalize_database_url(raw: str, *, driver: str | None = None) -> str:
    """Return a fully percent-encoded PostgreSQL URL.

    - Accepts URLs whose password contains unencoded reserved characters
      (``@``, ``:``, etc.) and emits them percent-encoded.
    - Accepts URLs whose password is already percent-encoded and leaves
      them alone (idempotent).
    - If ``driver`` is given, swaps the scheme to that driver (e.g. pass
      ``"postgresql"`` to strip ``+asyncpg`` for sync consumers like
      Alembic/psycopg2).

    Raises ``ValueError`` if ``raw`` is empty or has no recognized scheme.
    """
    if not raw:
        raise ValueError("DATABASE_URL is empty")

    scheme = None
    rest = None
    for prefix in _DRIVER_PREFIXES:
        if raw.startswith(prefix):
            scheme = prefix[:-3]  # strip "://"
            rest = raw[len(prefix):]
            break
    if rest is None:
        raise ValueError(f"Unrecognized PostgreSQL URL scheme in: {raw[:32]}...")

    if driver:
        scheme = driver

    # Split userinfo from host. PostgreSQL URLs put userinfo before the
    # *last* ``@`` — anything earlier is a literal in the password.
    if "@" not in rest:
        # No userinfo. Just return as-is with possibly-swapped driver.
        return f"{scheme}://{rest}"

    userinfo, hostpart = rest.rsplit("@", 1)

    # Split username:password on the first ``:`` only — passwords can
    # contain ``:`` (e.g. base64), usernames cannot.
    if ":" in userinfo:
        user, password = userinfo.split(":", 1)
    else:
        user, password = userinfo, ""

    # Percent-encode each component. ``safe=""`` forces encoding of
    # every reserved char. This is idempotent: ``quote("%40")`` is
    # ``"%2540"`` only if we encoded an already-encoded string, so we
    # avoid that by checking whether the password looks already-encoded.
    user_q = quote(user, safe="")
    password_q = _encode_password(password)

    return f"{scheme}://{user_q}:{password_q}@{hostpart}"


def _encode_password(password: str) -> str:
    """Percent-encode a password, idempotently.

    If ``password`` contains a ``%`` followed by two hex digits, we
    assume it's already encoded and only encode characters that aren't
    safe in URLs (i.e. leave existing escapes alone). Otherwise we
    encode aggressively.
    """
    import re

    looks_encoded = bool(re.search(r"%[0-9A-Fa-f]{2}", password))
    if looks_encoded:
        # Leave existing %XX escapes alone; only encode raw reserved chars.
        # safe="%" keeps existing escapes intact.
        return quote(password, safe="%")
    return quote(password, safe="")
