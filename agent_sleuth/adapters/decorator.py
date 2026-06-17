"""adapters/decorator.py — @tracked_tool for raw/custom agents (§4.9, v0 step 1).

Wraps a plain tool function so that, with no agent framework, every call runs the ingress
lineage check (raise in enforce, log in audit) and every return is fingerprinted + labeled.

Usage::

    sleuth = Sleuth(agent=None, ...)        # owns the engine
    fetch_url = sleuth.track(fetch_url)     # or: @sleuth.tracked_tool
    send_email = sleuth.track(send_email)

The standalone ``tracked_tool(engine)`` decorator factory is also exported for users who
construct an Engine directly.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from ..engine import Engine


def _call_args(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Best-effort bind positional+keyword args into a name->value dict for the checker."""
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        # Fall back to kwargs plus positional-by-index.
        merged = dict(kwargs)
        for i, a in enumerate(args):
            merged[f"arg{i}"] = a
        return merged


def tracked_tool(engine: Engine, name: str | None = None) -> Callable[[Callable], Callable]:
    """Decorator factory: bind a tool function to an Engine for ingress/egress tracking."""

    def decorate(fn: Callable) -> Callable:
        tool_name = name or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = _call_args(fn, args, kwargs)
            engine.on_tool_call(tool_name, call_args)  # may raise in enforce mode
            result = fn(*args, **kwargs)
            engine.on_tool_result(tool_name, result)
            return result

        wrapper.__sleuth_tool_name__ = tool_name  # type: ignore[attr-defined]
        return wrapper

    return decorate
