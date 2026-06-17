"""core/store.py — the provenance store (§4.3).

Holds labels and lineage across tool calls *within a single agent run*. The LLM's context
window is stateful, so the label store must match that statefulness. Two levels of
granularity, both implemented:

1. Value-level lineage (primary, the wedge): content-addressed fingerprint -> TaintedValue.
2. Run-level taint (coarse fallback / strict mode): once any untrusted data enters the run,
   the whole run is considered tainted.

``reset()`` is called at the start of every run — taint does not bleed across independent
agent invocations.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import fingerprint
from .values import TaintedValue, Trust


@dataclass
class StoreEvent:
    """An ordered record of one tool's labeled output, for trace rendering."""

    step: int
    source: str
    trust: Trust
    values: list[TaintedValue]


class TaintStore:
    def __init__(self) -> None:
        self._store: dict[str, TaintedValue] = {}
        self._run_taint_level: Trust = Trust.TRUSTED
        self._events: list[StoreEvent] = []
        self._step: int = 0

    def next_step(self) -> int:
        """Advance and return the current tool-call step index (1-based)."""
        self._step += 1
        return self._step

    @property
    def step(self) -> int:
        return self._step

    def label(self, values: list[TaintedValue], *, source: str, trust: Trust) -> None:
        """Record a tool's extracted values into the store and the event log."""
        for v in values:
            fp = fingerprint(v.value if isinstance(v.value, str) else str(v.value))
            # First writer wins for a given fingerprint, but untrusted always dominates
            # (conservative: a value seen as untrusted stays untrusted).
            existing = self._store.get(fp)
            if existing is None or (existing.trust == Trust.TRUSTED and v.is_tainted()):
                self._store[fp] = v
        if trust == Trust.UNTRUSTED:
            self._run_taint_level = Trust.UNTRUSTED
        self._events.append(
            StoreEvent(step=values[0].step if values else self._step,
                       source=source, trust=trust, values=values)
        )

    def get(self, fp: str) -> TaintedValue | None:
        return self._store.get(fp)

    def untrusted_values(self) -> list[TaintedValue]:
        return [v for v in self._store.values() if v.is_tainted()]

    def get_run_trust(self) -> Trust:
        return self._run_taint_level

    def is_run_tainted(self) -> bool:
        return self._run_taint_level == Trust.UNTRUSTED

    def events(self) -> list[StoreEvent]:
        return list(self._events)

    def reset(self) -> None:
        """Fresh taint state per run."""
        self._store.clear()
        self._run_taint_level = Trust.TRUSTED
        self._events.clear()
        self._step = 0
