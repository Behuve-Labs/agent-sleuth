"""Framework-agnostic core engine. Never imports an agent framework (§11.3)."""

from .errors import TaintViolationError
from .fingerprint import extract_values, fingerprint, normalize
from .lineage import Violation, check
from .policy import IFCPolicy
from .store import TaintStore
from .trace import render
from .values import TaintedValue, Trust

__all__ = [
    "TaintViolationError",
    "extract_values",
    "fingerprint",
    "normalize",
    "Violation",
    "check",
    "IFCPolicy",
    "TaintStore",
    "render",
    "TaintedValue",
    "Trust",
]
