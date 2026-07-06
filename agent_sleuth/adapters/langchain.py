"""adapters/langchain.py — the LangChain interception layer (§4.6).

Integration is a ``BaseCallbackHandler`` the developer passes in — zero changes to their
agent. ``on_tool_end`` fingerprints + labels output (egress); ``on_tool_start`` runs the
ingress lineage check (enforce raises, audit logs).

LangChain is imported lazily so ``core/`` and the rest of the library stay dependency-free
(§11.3, Friction 3 §6). If langchain-core is not installed, importing the handler raises a
clear error; the rest of agent_sleuth still works.

Stability hazard (§4.6, §6): pin to the stable callback interface; the core engine is
framework-agnostic so adding CrewAI / ADK / raw agents never touches the engine.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from ..core.errors import TaintViolationError
from ..engine import Engine

logger = logging.getLogger("agent_sleuth")

try:  # pragma: no cover - import shim
    from langchain_core.callbacks import BaseCallbackHandler

    _HAS_LANGCHAIN = True
except Exception:  # pragma: no cover
    _HAS_LANGCHAIN = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Fallback base so the module imports without langchain-core installed."""


def _parse_input(input_str: str, inputs: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve a tool's call args from LangChain's on_tool_start payload.

    Newer LangChain passes structured ``inputs``; older versions pass an ``input_str``
    (often a JSON object, sometimes a bare string). Handle both.
    """
    if inputs:
        return dict(inputs)
    s = (input_str or "").strip()
    if s[:1] in ("{", "["):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    return {"input": input_str}


def _extract_content(output: Any) -> Any:
    """LangChain may wrap output in a ToolMessage; pull the content if present."""
    return getattr(output, "content", output)


class IFCCallbackHandler(BaseCallbackHandler):
    """Sync LangChain callback handler driving the Sleuth engine at the tool boundary."""

    # LangChain's callback manager swallows handler exceptions unless raise_error is True;
    # without this, an enforce-mode TaintViolationError would be logged but the sink tool
    # would STILL execute. We re-raise only our intentional violation (see _start); any
    # internal Sleuth error is caught and swallowed so it never breaks the host agent.
    raise_error: bool = True

    def __init__(self, engine: Engine):
        if not _HAS_LANGCHAIN:
            raise ImportError(
                "IFCCallbackHandler requires langchain-core. "
                "Install with: pip install 'agent_sleuth[langchain]'"
            )
        self.engine = engine
        # Map LangChain run_id -> tool name so on_tool_end knows which tool produced output.
        self._run_tools: dict[UUID, str] = {}

    def _start(self, serialized, input_str, run_id, inputs):
        name = (serialized or {}).get("name", "tool")
        if run_id is not None:
            self._run_tools[run_id] = name
        try:
            # Raises TaintViolationError in enforce mode (and confirm-deny) to halt the call.
            self.engine.on_tool_call(name, _parse_input(input_str, inputs))
        except TaintViolationError:
            raise  # intended enforcement block — let it propagate to halt the tool
        except Exception:  # internal Sleuth bug: never break the host agent
            logger.exception("agent_sleuth: internal error in ingress check; allowing call")

    def _end(self, output, run_id, kwargs):
        name = self._run_tools.pop(run_id, None) if run_id is not None else None
        name = name or kwargs.get("name") or "tool"
        try:
            self.engine.on_tool_result(name, _extract_content(output))
        except Exception:  # egress labeling never intentionally raises
            logger.exception("agent_sleuth: internal error labeling tool output; skipping")

    # --- ingress -----------------------------------------------------------------
    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        # Raises TaintViolationError in enforce mode to halt the call.
        self._start(serialized, input_str, run_id, inputs)

    # --- egress ------------------------------------------------------------------
    def on_tool_end(self, output: Any, *, run_id: UUID | None = None, **kwargs: Any) -> None:
        self._end(output, run_id, kwargs)


class AsyncIFCCallbackHandler(IFCCallbackHandler):
    """Async LangChain callback handler. Delegates to the same synchronous core (§ async).

    The engine's work is pure-Python and non-blocking, so async callbacks simply await the
    shared sync logic.
    """

    async def on_tool_start(  # type: ignore[override]
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._start(serialized, input_str, run_id, inputs)

    async def on_tool_end(  # type: ignore[override]
        self, output: Any, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        self._end(output, run_id, kwargs)
