"""engine.py — framework-agnostic ingress/egress glue shared by all adapters.

The adapters (decorator, LangChain callback, future MCP proxy) are thin: they translate
framework events into two calls on the Engine:

- ``on_tool_call(name, args)`` — ingress: lineage-check a pending sink call. Raises in
  enforce mode, records a (non-blocking) violation in audit mode.
- ``on_tool_result(name, output)`` — egress: fingerprint + label the tool output.

The Engine owns no framework imports, keeping ``core/`` and this glue dependency-free.
"""

from __future__ import annotations

import logging
from typing import Any

from .core.errors import TaintViolationError
from .core.fingerprint import extract_values
from .core.lineage import Violation, check
from .core.policy import IFCPolicy
from .core.store import TaintStore
from .core.trace import render
from .core.values import Trust

logger = logging.getLogger("agent_sleuth")


class Engine:
    def __init__(self, policy: IFCPolicy, store: TaintStore):
        self.policy = policy
        self.store = store
        self.violations: list[Violation] = []
        self.query: str | None = None
        # Optional callback for confirm mode: (violation, rendered) -> bool (allow?).
        self.confirm_callback = None

    def set_query(self, query: str | None) -> None:
        self.query = query

    def on_tool_call(self, name: str, args: dict[str, Any]) -> Violation | None:
        """Ingress check for a pending tool call. Returns the Violation if one fired."""
        violation = check(name, args, self.store, self.policy, self.query)
        if violation is None:
            return None

        if self.policy.mode == "enforce":
            violation.blocked = True
            rendered = render(violation)
            self.violations.append(violation)
            logger.warning(rendered)
            raise TaintViolationError(violation, rendered)

        if self.policy.mode == "confirm":
            rendered = render(violation)
            allow = True
            if self.confirm_callback is not None:
                allow = bool(self.confirm_callback(violation, rendered))
            violation.blocked = not allow
            self.violations.append(violation)
            logger.warning(rendered)
            if not allow:
                raise TaintViolationError(violation, rendered)
            return violation

        # audit (default): log + record, never block.
        violation.blocked = False
        rendered = render(violation)
        self.violations.append(violation)
        logger.info(rendered)
        return violation

    def on_tool_result(self, name: str, output: Any, *, trace_id: str | None = None) -> None:
        """Egress: fingerprint + label a tool's output."""
        trust = Trust.UNTRUSTED if self.policy.is_untrusted_source(name) else Trust.TRUSTED
        step = self.store.next_step()
        values = extract_values(
            output,
            source=name,
            trust=trust,
            trace_id=trace_id or f"{name}:{step}",
            step=step,
        )
        if values:
            self.store.label(values, source=name, trust=trust)
