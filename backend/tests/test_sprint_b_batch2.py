"""Sprint B Batch 2 unit tests — C12 (HMAC subject hash) + C15 (subject normalization).

C16 (per-customer suppression) is covered by integration tests and the live
checks in the outbound-email-filter skill — it requires the backend + DB.

We can't import smtp/main.py directly here (it pulls aiosmtpd / boto3 which
aren't in the backend test venv), so we extract the C12/C15 implementations
by AST-loading the relevant functions into a synthetic module.
"""
from __future__ import annotations

import ast
import types
from pathlib import Path

SMTP_MAIN = Path(__file__).resolve().parents[2] / "smtp" / "main.py"


def _load_helpers() -> types.ModuleType:
    """Pull _normalize_subject / _hash_subject / _decode_salt + their deps
    out of smtp/main.py and exec them in an isolated module — avoids the
    aiosmtpd/boto3 import chain.
    """
    source = SMTP_MAIN.read_text()
    tree = ast.parse(source)
    wanted_funcs = {"_normalize_subject", "_hash_subject", "_decode_salt"}
    wanted_names = {"_KEEP_CONTROL"}
    kept: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted_funcs:
            kept.append(node)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id in wanted_names:
                    kept.append(node)
                    break
    module_ast = ast.Module(body=kept, type_ignores=[])
    mod = types.ModuleType("smtp_main_helpers")
    # Inject deps the functions reference at top level.
    import hashlib, hmac, logging, re as _stdlib_re, unicodedata
    mod.hashlib = hashlib
    mod.hmac = hmac
    mod.unicodedata = unicodedata
    mod._stdlib_re = _stdlib_re
    mod.logger = logging.getLogger("test_sprint_b_batch2")
    exec(compile(module_ast, str(SMTP_MAIN), "exec"), mod.__dict__)
    return mod


smtp_main = _load_helpers()


# ---------------------------------------------------------------------------
# C15: subject normalization
# ---------------------------------------------------------------------------

def test_normalize_strips_zero_width_joiners():
    """ZWJ (U+200D), ZWSP (U+200B), ZWNJ (U+200C) must be stripped."""
    raw = "Inv\u200boice\u200d Pa\u200cyment"
    assert smtp_main._normalize_subject(raw) == "invoice payment"


def test_normalize_strips_bidi_marks():
    """RTL/LTR override characters must be stripped — common spoof vector."""
    raw = "\u202eINVOICE\u202c"
    assert smtp_main._normalize_subject(raw) == "invoice"


def test_normalize_strips_bom_and_format():
    raw = "\ufeffHello\u2066World\u2069"
    assert smtp_main._normalize_subject(raw) == "helloworld"


def test_normalize_collapses_whitespace_and_casefolds():
    raw = "   PAY\tNOW\n\n  please  "
    assert smtp_main._normalize_subject(raw) == "pay now please"


def test_normalize_nfkc_collapses_compatibility_forms():
    # Fullwidth letters should collapse to ASCII under NFKC.
    raw = "\uff29\uff2e\uff36"  # IＮV (fullwidth I N V)
    assert smtp_main._normalize_subject(raw) == "inv"


def test_normalize_empty_string():
    assert smtp_main._normalize_subject("") == ""


def test_normalize_strips_control_chars_keeps_tab_and_space():
    raw = "hello\x00\x01\x02world\tagain"
    assert smtp_main._normalize_subject(raw) == "helloworld again"


# ---------------------------------------------------------------------------
# C12: HMAC subject hashing
# ---------------------------------------------------------------------------

def test_hash_is_64_hex_chars():
    h = smtp_main._hash_subject("test", b"\x00" * 32)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_same_subject_different_salts_produce_different_hashes():
    """The whole point of C12 — cross-customer privacy of the log table."""
    salt_a = b"a" * 32
    salt_b = b"b" * 32
    h_a = smtp_main._hash_subject("Invoice attached", salt_a)
    h_b = smtp_main._hash_subject("Invoice attached", salt_b)
    assert h_a != h_b


def test_normalization_makes_spoofed_subjects_collide():
    """Two visually-equal subjects with different invisible chars must hash equal."""
    salt = b"x" * 32
    plain = smtp_main._hash_subject("Invoice", salt)
    spoofed = smtp_main._hash_subject("Inv\u200boice", salt)  # ZWSP
    assert plain == spoofed


def test_decode_salt_zero_fallback_on_missing():
    assert smtp_main._decode_salt(None) == b"\x00" * 32
    assert smtp_main._decode_salt("") == b"\x00" * 32


def test_decode_salt_zero_fallback_on_bad_hex():
    # Invalid hex must not crash the SMTP path — we fail open to zero salt.
    assert smtp_main._decode_salt("not-hex-zz") == b"\x00" * 32


def test_decode_salt_round_trips_valid_hex():
    expected = bytes(range(32))
    assert smtp_main._decode_salt(expected.hex()) == expected
