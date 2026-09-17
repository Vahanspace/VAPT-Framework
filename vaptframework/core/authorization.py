"""Authorization gating — the second guardrail.

Passive work (reading your own source code, inspecting response headers you already
received) needs only a scope. Anything *active* — sending crafted requests, fuzzing,
injection probes, port scanning — additionally requires a valid Authorization record: a
machine-readable rules-of-engagement artifact stating who authorized the test, for which
targets, and for how long.

The Authorization is deliberately conservative:
  * active testing is off unless ``allow_active_testing`` is explicitly true,
  * destructive testing (data mutation/deletion, DoS) is off unless ``allow_destructive``
    is explicitly true AND active testing is on,
  * the record must be within its validity window,
  * an unsigned / placeholder record is treated as invalid.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Optional


class AuthorizationError(Exception):
    """Raised when an action is attempted without adequate authorization."""


_PLACEHOLDERS = {"", "tbd", "todo", "changeme", "none", "n/a", "xxx"}


def _parse_date(value) -> Optional[date]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(str(value)).date()
    except ValueError:
        # A placeholder/garbage date (e.g. "YYYY-MM-DD") is treated as "no valid date"
        # rather than crashing. Combined with the unsigned check this fails closed.
        return None


@dataclass
class Authorization:
    authorized_by: str = ""            # named human who signed off
    engagement: str = ""               # engagement / ticket reference
    valid_from: Optional[date] = None
    valid_until: Optional[date] = None
    allow_active_testing: bool = False
    allow_destructive: bool = False
    contact: str = ""                  # who to reach to stop the test
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Authorization":
        return cls(
            authorized_by=str(data.get("authorized_by", "")).strip(),
            engagement=str(data.get("engagement", "")).strip(),
            valid_from=_parse_date(data.get("valid_from")),
            valid_until=_parse_date(data.get("valid_until")),
            allow_active_testing=bool(data.get("allow_active_testing", False)),
            allow_destructive=bool(data.get("allow_destructive", False)),
            contact=str(data.get("contact", "")).strip(),
            notes=str(data.get("notes", "")).strip(),
        )

    # -- validity ------------------------------------------------------------
    def _signed(self) -> bool:
        return self.authorized_by.strip().lower() not in _PLACEHOLDERS

    def is_valid(self, today: Optional[date] = None) -> bool:
        today = today or date.today()
        if not self._signed():
            return False
        if self.valid_from and today < self.valid_from:
            return False
        if self.valid_until and today > self.valid_until:
            return False
        return True

    def reason_invalid(self, today: Optional[date] = None) -> Optional[str]:
        today = today or date.today()
        if not self._signed():
            return "authorization is unsigned (authorized_by is empty/placeholder)"
        if self.valid_from and today < self.valid_from:
            return f"authorization not yet valid (starts {self.valid_from})"
        if self.valid_until and today > self.valid_until:
            return f"authorization expired on {self.valid_until}"
        return None

    # -- gates ---------------------------------------------------------------
    def assert_active_allowed(self, today: Optional[date] = None) -> None:
        reason = self.reason_invalid(today)
        if reason:
            raise AuthorizationError(reason)
        if not self.allow_active_testing:
            raise AuthorizationError("active testing is not authorized (allow_active_testing is false)")

    def assert_destructive_allowed(self, today: Optional[date] = None) -> None:
        self.assert_active_allowed(today)
        if not self.allow_destructive:
            raise AuthorizationError("destructive testing is not authorized (allow_destructive is false)")

    def active_allowed(self, today: Optional[date] = None) -> bool:
        try:
            self.assert_active_allowed(today)
            return True
        except AuthorizationError:
            return False

    def destructive_allowed(self, today: Optional[date] = None) -> bool:
        try:
            self.assert_destructive_allowed(today)
            return True
        except AuthorizationError:
            return False
