"""Exact-value attribution (label-creep mitigation).

Without it, every LLM output inherits *everything* that was in the model's context: a
channel name the user typed becomes "influenced by the web page" merely because the page
was also in context, and over a few turns every value ends up untrusted and secret
("label creep").

Rule: when an action argument exactly matches a value that a *trusted* Datum supplied
(the user's message, a vault secret, a clean earlier output), the argument is attributed
to that supplier only. The other context items are kept as ``attribution: "context"``
edges for audit, and the Guard does not follow them.

"Exactly matches" means one of:
- the argument's fingerprint equals the supplier's fingerprint (whole-value match; this
  is the only way to match secrets, whose raw values are never stored), or
- the argument appears in the supplier's text as a whole token: not glued to other
  word, address or path characters (``#security`` matches "post to #security." but
  ``board@acme.example`` does not match inside ``board@acme.example.evil``).

A supplier is *trusted* if it has no provenance path to an untrusted Source without an
endorsed Datum on it. The check is the same Cypher traversal the Guard uses.
"""
from __future__ import annotations

import re

MIN_TOKEN_LEN = 3
_BEFORE = r"(?<![\w@.\-/#+:])"
_AFTER = r"(?![\w@/\-#]|[.:]\w)"


def value_supplied_by(value: str, text: str) -> bool:
    """True if ``value`` appears in ``text`` exactly, as a whole token."""
    value = value.strip()
    if not value or text is None:
        return False
    if text.strip() == value:
        return True
    if len(value) < MIN_TOKEN_LEN:
        return False
    return re.search(_BEFORE + re.escape(value) + _AFTER, text) is not None
