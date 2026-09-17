from datetime import date

import pytest

from vaptframework.core.authorization import Authorization, AuthorizationError


def auth(**over):
    base = dict(
        authorized_by="Sirish (VahanSpace)",
        engagement="VAPT-2026-Q3",
        valid_from="2026-09-01",
        valid_until="2026-12-31",
        allow_active_testing=True,
        allow_destructive=False,
        contact="sirish@example.com",
    )
    base.update(over)
    return Authorization.from_dict(base)


TODAY = date(2026, 9, 17)


def test_valid_within_window():
    assert auth().is_valid(TODAY) is True


def test_unsigned_is_invalid():
    a = auth(authorized_by="")
    assert a.is_valid(TODAY) is False
    assert "unsigned" in a.reason_invalid(TODAY)


def test_placeholder_signer_is_invalid():
    assert auth(authorized_by="TBD").is_valid(TODAY) is False


def test_expired_is_invalid():
    a = auth(valid_until="2026-09-10")
    assert a.is_valid(TODAY) is False
    assert "expired" in a.reason_invalid(TODAY)


def test_not_yet_valid():
    a = auth(valid_from="2026-10-01")
    assert a.is_valid(TODAY) is False


def test_active_gate_blocks_when_disabled():
    a = auth(allow_active_testing=False)
    with pytest.raises(AuthorizationError):
        a.assert_active_allowed(TODAY)
    assert a.active_allowed(TODAY) is False


def test_active_gate_allows_when_enabled_and_valid():
    auth().assert_active_allowed(TODAY)  # no raise
    assert auth().active_allowed(TODAY) is True


def test_destructive_requires_both_flags():
    assert auth(allow_destructive=False).destructive_allowed(TODAY) is False
    assert auth(allow_destructive=True).destructive_allowed(TODAY) is True


def test_destructive_blocked_if_active_blocked():
    a = auth(allow_active_testing=False, allow_destructive=True)
    assert a.destructive_allowed(TODAY) is False


def test_active_blocked_when_unsigned_even_if_flag_true():
    a = auth(authorized_by="", allow_active_testing=True)
    with pytest.raises(AuthorizationError):
        a.assert_active_allowed(TODAY)
