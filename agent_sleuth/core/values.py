"""core/values.py — the atom.

Every piece of data the system tracks is a labeled value (§4.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Trust(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass
class TaintedValue:
    """A single tracked value plus its provenance label.

    Attributes:
        value: the raw extracted value (string for free-text extractables, or the
            leaf value for structured returns).
        trust: TRUSTED or UNTRUSTED.
        source: which tool produced this value.
        trace_id: id that ties this value to a lineage across hops.
        created_at: wall-clock time the value was recorded (ordering / display).
        field_path: for structured returns, the path to the leaf (e.g.
            ``results[0].email``). ``None`` for free-text extractables.
        step: the tool-call step index within the run (for "fetch_url at step 2").
    """

    value: Any
    trust: Trust
    source: str
    trace_id: str
    created_at: float
    field_path: str | None = None
    step: int | None = None

    def is_tainted(self) -> bool:
        return self.trust == Trust.UNTRUSTED
