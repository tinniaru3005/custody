"""Quarantined / typed reader support.

Untrusted content (a web page, an inbound email) must not be able to steer where data
goes. But agents still need small, well-typed facts out of it: a ticket number, a
quantity, a date, one value from a fixed list. The quarantined reader extracts such a
value, validates it against a narrow type, and records it as a ``Datum:Typed`` with:

- ``quarantined = true``      it came out of untrusted content through the reader
- ``value_type``              the validated type (int, number, bool, date, enum, ...)
- ``max_risk = "low"``        the highest action risk tier it may influence

The Guard treats an untrusted provenance path that passes through such a node as a
*limited* path: acceptable for low-risk actions, still a violation for high-risk ones.
Free-form types (email addresses, URLs, arbitrary text) are refused: those are exactly
the values an attacker would use to redirect data.

Validation is deterministic and done here, not by a model. Which value the extractor
picked is still the extractor's choice; that implicit channel is out of scope (see
docs/guard.md, threat model).
"""
from __future__ import annotations

import re
from datetime import date
from typing import Dict, Optional
from collections.abc import Callable, Sequence


class QuarantineViolation(ValueError):
    """The value does not fit the requested type, or the type is not allowed."""


def _int(v: str, _: Optional[Sequence[str]]) -> str:
    if not re.fullmatch(r"[+-]?\d{1,18}", v):
        raise QuarantineViolation(f"{v!r} is not an integer")
    return str(int(v))


def _number(v: str, _: Optional[Sequence[str]]) -> str:
    if not re.fullmatch(r"[+-]?\d{1,15}(\.\d{1,6})?", v):
        raise QuarantineViolation(f"{v!r} is not a number")
    return v.lstrip("+")


def _bool(v: str, _: Optional[Sequence[str]]) -> str:
    low = v.lower()
    if low in ("true", "yes", "1"):
        return "true"
    if low in ("false", "no", "0"):
        return "false"
    raise QuarantineViolation(f"{v!r} is not a boolean")


def _date(v: str, _: Optional[Sequence[str]]) -> str:
    try:
        return date.fromisoformat(v).isoformat()
    except ValueError as exc:
        raise QuarantineViolation(f"{v!r} is not an ISO date") from exc


def _enum(v: str, allowed: Optional[Sequence[str]]) -> str:
    if not allowed:
        raise QuarantineViolation("enum values need allowed_values")
    if v not in allowed:
        raise QuarantineViolation(f"{v!r} is not one of {list(allowed)}")
    return v


def _ticket_id(v: str, _: Optional[Sequence[str]]) -> str:
    if not re.fullmatch(r"[A-Z][A-Z0-9]{1,9}-\d{1,7}", v):
        raise QuarantineViolation(f"{v!r} is not a ticket id like OPS-123")
    return v


def _currency(v: str, _: Optional[Sequence[str]]) -> str:
    if not re.fullmatch(r"\d{1,12}(\.\d{1,2})?", v):
        raise QuarantineViolation(f"{v!r} is not an amount like 199.00")
    return v


VALIDATORS: Dict[str, Callable[[str, Optional[Sequence[str]]], str]] = {
    "int": _int,
    "number": _number,
    "bool": _bool,
    "date": _date,
    "enum": _enum,
    "ticket_id": _ticket_id,
    "currency": _currency,
}

# Never allowed as typed values: they can name a destination or carry instructions.
FORBIDDEN_TYPES = frozenset({"email", "url", "text", "string", "address", "host", "channel"})


def validate_typed_value(value: str, value_type: str,
                         allowed_values: Optional[Sequence[str]] = None) -> str:
    """Return the canonical form of ``value`` or raise QuarantineViolation."""
    if value_type in FORBIDDEN_TYPES:
        raise QuarantineViolation(
            f"type {value_type!r} is free-form and cannot leave quarantine as a typed value")
    validator = VALIDATORS.get(value_type)
    if validator is None:
        raise QuarantineViolation(f"unknown typed-value type {value_type!r}")
    if not isinstance(value, str):
        value = str(value)
    return validator(value.strip(), allowed_values)
