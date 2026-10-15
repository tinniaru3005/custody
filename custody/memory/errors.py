"""Errors raised by the shared-memory layer."""
from __future__ import annotations


class MemoryQuarantined(PermissionError):
    """The memory is in quarantine (Warden containment) and cannot be retrieved normally."""
