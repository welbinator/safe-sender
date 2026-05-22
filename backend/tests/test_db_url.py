"""Tests for db_url normalization.

These exist because we hit a real production deploy bug where a password
containing an unencoded '@' broke psycopg2 (used by Alembic) while
asyncpg shrugged it off. The fix tolerates both forms on input and
emits a strictly-encoded URL on output.
"""

import pytest

from db_url import normalize_database_url


class TestNormalizeDatabaseUrl:
    def test_simple_url_passes_through(self):
        url = "postgresql://user:pass@host:5432/db"
        assert normalize_database_url(url) == "postgresql://user:pass@host:5432/db"

    def test_unencoded_at_in_password(self):
        # The real-world bug: password contains a literal '@'.
        # psycopg2's parser would split on the first '@' and choke.
        url = "postgresql://user:pa@ss@host:5432/db"
        result = normalize_database_url(url)
        assert result == "postgresql://user:pa%40ss@host:5432/db"

    def test_already_encoded_at_is_idempotent(self):
        url = "postgresql://user:pa%40ss@host:5432/db"
        result = normalize_database_url(url)
        # Should NOT double-encode to %2540
        assert result == "postgresql://user:pa%40ss@host:5432/db"

    def test_multiple_unencoded_specials(self):
        url = "postgresql://user:p@ss/w#rd@host:5432/db"
        result = normalize_database_url(url)
        assert result == "postgresql://user:p%40ss%2Fw%23rd@host:5432/db"

    def test_driver_swap_strips_asyncpg(self):
        url = "postgresql+asyncpg://user:pass@host:5432/db"
        result = normalize_database_url(url, driver="postgresql")
        assert result == "postgresql://user:pass@host:5432/db"

    def test_driver_swap_with_unencoded_at(self):
        # The exact production bug shape.
        url = "postgresql+asyncpg://user:p@ss@host:5432/db"
        result = normalize_database_url(url, driver="postgresql")
        assert result == "postgresql://user:p%40ss@host:5432/db"

    def test_postgres_scheme_normalized(self):
        url = "postgres://user:pass@host:5432/db"
        result = normalize_database_url(url, driver="postgresql")
        assert result == "postgresql://user:pass@host:5432/db"

    def test_no_password(self):
        url = "postgresql://user@host:5432/db"
        result = normalize_database_url(url)
        assert result == "postgresql://user:@host:5432/db"

    def test_no_userinfo(self):
        url = "postgresql://host:5432/db"
        result = normalize_database_url(url)
        assert result == "postgresql://host:5432/db"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            normalize_database_url("")

    def test_unrecognized_scheme_raises(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            normalize_database_url("mysql://user:pass@host/db")

    def test_colon_in_password(self):
        # Passwords can contain ':' — only split on the first one.
        url = "postgresql://user:pa:ss@host:5432/db"
        result = normalize_database_url(url)
        # The ':' in the password gets encoded.
        assert result == "postgresql://user:pa%3Ass@host:5432/db"

    def test_query_string_preserved(self):
        url = "postgresql://user:pass@host:5432/db?sslmode=require"
        result = normalize_database_url(url)
        assert result == "postgresql://user:pass@host:5432/db?sslmode=require"
