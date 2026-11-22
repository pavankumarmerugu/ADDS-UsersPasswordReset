from __future__ import annotations

import pytest

from app.config import PolicyConfig
from app.policy import validate

POLICY = PolicyConfig(min_length=12, min_character_classes=3)


def check(new, *, username="jdoe", old="OldPassw0rd!", confirm=None):
    return validate(
        username=username,
        old_password=old,
        new_password=new,
        confirm_password=new if confirm is None else confirm,
        policy=POLICY,
    )


def test_accepts_a_compliant_password():
    assert check("Correct-Horse9").ok


def test_rejects_short_password():
    result = check("Ab1!xyz")
    assert not result.ok
    assert any("at least 12" in e for e in result.errors)


def test_rejects_mismatched_confirmation():
    result = check("Correct-Horse9", confirm="Correct-Horse8")
    assert not result.ok
    assert any("do not match" in e for e in result.errors)


def test_rejects_reuse_of_current_password():
    result = check("OldPassw0rd!", old="OldPassw0rd!")
    assert not result.ok
    assert any("different from your current" in e for e in result.errors)


def test_rejects_password_containing_username():
    result = check("jdoe-Passw0rd9", username="jdoe")
    assert not result.ok
    assert any("must not contain your username" in e for e in result.errors)


def test_requires_three_character_classes():
    result = check("abcdefghijklmnop")
    assert not result.ok
    assert any("character types" in e for e in result.errors)


@pytest.mark.parametrize("symbol", ["#", "~", "^", "*", "(", "£", "€"])
def test_accepts_symbols_the_original_tool_rejected(symbol):
    """The original allowed only !&/?%:_@$ and silently refused the rest."""
    assert check(f"Valid{symbol}Passw0rd").ok


def test_accepts_long_passphrase_with_spaces():
    assert check("correct horse battery Staple 7").ok


def test_handles_empty_new_password_without_crashing():
    result = check("")
    assert not result.ok


def test_unicode_normalisation_counts_length_consistently():
    composed = "Café-Passw0rd"            # é as one code point
    decomposed = "Café-Passw0rd"    # e + combining acute
    assert check(composed).ok == check(decomposed).ok
