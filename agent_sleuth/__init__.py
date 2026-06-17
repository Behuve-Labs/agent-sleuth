"""Agent Sleuth — prevents untrusted data from triggering consequential actions in your agent.

In-process information-flow-control for LLM agents. Value-level provenance lineage tracked
at the tool-I/O boundary: deterministic, classifier-free, zero extra LLM calls on the
common path. See AGENT_SLEUTH_ARCHITECTURE.MD.
"""

from .core.errors import TaintViolationError
from .core.policy import IFCPolicy
from .core.values import TaintedValue, Trust
from .engine import Engine
from .runtime import Sleuth

__all__ = [
    "Sleuth",
    "Engine",
    "Trust",
    "TaintedValue",
    "IFCPolicy",
    "TaintViolationError",
    "tracked_tool",
]

try:
    from importlib.metadata import version as _version
    __version__ = _version("agent_sleuth")
except Exception:
    __version__ = "0.0.1"


def tracked_tool(engine, name=None):
    """Decorator factory for raw tools (re-exported from adapters.decorator)."""
    from .adapters.decorator import tracked_tool as _tt

    return _tt(engine, name=name)
