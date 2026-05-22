"""Unit tests for repositories._query.WhereBuilder (F-33)."""
import pytest

from repositories._query import WhereBuilder


def test_empty_builder_returns_default():
    wb = WhereBuilder()
    where, params = wb.finish()
    assert where == "TRUE"
    assert params == []


def test_empty_builder_custom_default():
    wb = WhereBuilder()
    where, _ = wb.finish(default_if_empty="1=1")
    assert where == "1=1"


def test_single_filter_allocates_dollar_one():
    wb = WhereBuilder()
    wb.append("c.id = {}", 42)
    where, params = wb.finish()
    assert where == "c.id = $1"
    assert params == [42]
    assert wb.next_idx == 2


def test_multiple_filters_allocate_sequential_indices():
    wb = WhereBuilder()
    wb.append("c.id = {}", 1)
    wb.append("c.name ILIKE {}", "%foo%")
    wb.append("c.active = {}", True)
    where, params = wb.finish()
    assert where == "c.id = $1 AND c.name ILIKE $2 AND c.active = $3"
    assert params == [1, "%foo%", True]
    assert wb.next_idx == 4


def test_start_idx_offsets_placeholders():
    wb = WhereBuilder(start_idx=5)
    wb.append("x = {}", "y")
    where, params = wb.finish()
    assert where == "x = $5"
    assert params == ["y"]
    assert wb.next_idx == 6


def test_start_idx_below_one_rejected():
    with pytest.raises(ValueError):
        WhereBuilder(start_idx=0)


def test_append_rejects_zero_markers():
    wb = WhereBuilder()
    with pytest.raises(ValueError):
        wb.append("c.active = TRUE", None)


def test_append_rejects_multiple_markers():
    wb = WhereBuilder()
    with pytest.raises(ValueError):
        wb.append("c.x = {} AND c.y = {}", 1)


def test_append_raw_supports_multi_marker():
    wb = WhereBuilder()
    wb.append_raw("c.x BETWEEN {} AND {}", 10, 20)
    where, params = wb.finish()
    assert where == "c.x BETWEEN $1 AND $2"
    assert params == [10, 20]
    assert wb.next_idx == 3


def test_append_raw_validates_marker_count():
    wb = WhereBuilder()
    with pytest.raises(ValueError):
        wb.append_raw("c.x = {}", 1, 2)


def test_append_static_no_params():
    wb = WhereBuilder()
    wb.append("c.id = {}", 1)
    wb.append_static("c.deleted_at IS NULL")
    where, params = wb.finish()
    assert where == "c.id = $1 AND c.deleted_at IS NULL"
    assert params == [1]
    assert wb.next_idx == 2


def test_append_static_rejects_placeholders():
    wb = WhereBuilder()
    with pytest.raises(ValueError):
        wb.append_static("c.x = $1")
    with pytest.raises(ValueError):
        wb.append_static("c.x = {}")


def test_extend_appends_many():
    wb = WhereBuilder()
    wb.extend([("a = {}", 1), ("b = {}", 2)])
    where, params = wb.finish()
    assert where == "a = $1 AND b = $2"
    assert params == [1, 2]


def test_finish_locks_builder():
    wb = WhereBuilder()
    wb.append("x = {}", 1)
    wb.finish()
    with pytest.raises(RuntimeError):
        wb.append("y = {}", 2)
    with pytest.raises(RuntimeError):
        wb.append_raw("y = {}", 2)
    with pytest.raises(RuntimeError):
        wb.append_static("y IS NULL")


def test_values_are_never_embedded_in_sql():
    """The whole point of F-33: nothing user-supplied lands in the SQL text."""
    wb = WhereBuilder()
    nasty = "'; DROP TABLE customers; --"
    wb.append("c.name = {}", nasty)
    where, params = wb.finish()
    assert nasty not in where
    assert where == "c.name = $1"
    assert params == [nasty]
