"""core/errors.py — exceptions."""

from __future__ import annotations

from .lineage import Violation


class TaintViolationError(Exception):
    """Raised (enforce mode only) when a consequential sink call carries untrusted-origin
    data to a non-allowlisted destination. Carries the Violation and its rendered trace."""

    def __init__(self, violation: Violation, rendered: str):
        self.violation = violation
        self.rendered = rendered
        super().__init__(rendered)
