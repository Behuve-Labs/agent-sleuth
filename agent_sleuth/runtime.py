"""runtime.py — Sleuth, the public developer-facing API (§4.8).

The single thing the developer imports. Constructs the policy (from explicit lists or
name-based defaults), owns the store and engine, resets per run, and exposes ``violations``
and ``report()``.

Three-line integration (§0)::

    from agent_sleuth import Sleuth

    agent = Sleuth(agent=your_agent, untrusted=[...], consequential=[...], mode="audit")
    result = agent.run("summarize my emails and send a report to my boss")
    print(agent.report())
"""

from __future__ import annotations

from typing import Any, Callable

from .core.errors import TaintViolationError
from .core.lineage import Violation
from .core.policy import IFCPolicy
from .core.store import TaintStore
from .core.trace import render
from .engine import Engine


class Sleuth:
    def __init__(
        self,
        agent: Any = None,
        untrusted: list[str] | None = None,
        consequential: list[str] | None = None,
        destinations: list[str] | None = None,
        mode: str = "audit",
        policy: IFCPolicy | None = None,
        strict: bool = False,
        confirm_callback: Callable[[Violation, str], bool] | None = None,
    ):
        if policy is not None:
            self.policy = policy
        elif untrusted is None and consequential is None:
            # Pure name-based defaults (§4.4): most developers never touch the lists.
            self.policy = IFCPolicy.from_defaults(mode=mode)
            self.policy.destination_allowlist = destinations or []
            self.policy.strict = strict
        else:
            self.policy = IFCPolicy(
                untrusted_sources=untrusted or [],
                consequential_actions=consequential or [],
                destination_allowlist=destinations or [],
                mode=mode,
                strict=strict,
            )
        self.store = TaintStore()
        self.engine = Engine(self.policy, self.store)
        self.engine.confirm_callback = confirm_callback
        self.agent = agent

    # --- adapter wiring ----------------------------------------------------------
    @property
    def handler(self):
        """A fresh LangChain callback handler bound to this Sleuth's engine."""
        from .adapters.langchain import IFCCallbackHandler

        return IFCCallbackHandler(self.engine)

    def track(self, fn: Callable, name: str | None = None) -> Callable:
        """Wrap a raw tool function with @tracked_tool bound to this engine."""
        from .adapters.decorator import tracked_tool

        return tracked_tool(self.engine, name=name)(fn)

    # --- run ---------------------------------------------------------------------
    def run(self, query: str, **kwargs: Any) -> Any:
        """Reset taint state, stash the trusted query, run the wrapped agent under the
        callback handler. Catches TaintViolationError in enforce/confirm and returns its
        rendered trace so the caller sees a clean blocked result."""
        self.reset(query)
        if self.agent is None:
            raise ValueError("Sleuth.run requires an agent; for raw tools use .track().")
        try:
            callbacks = kwargs.pop("callbacks", []) or []
            callbacks = [*callbacks, self.handler]
            return self.agent.run(query, callbacks=callbacks, **kwargs)
        except TaintViolationError as e:
            return e.rendered

    def reset(self, query: str | None = None) -> None:
        """Fresh taint state per run (§4.3). Optionally set the trusted query."""
        self.store.reset()
        self.engine.violations = []
        self.engine.set_query(query)

    # --- reporting ---------------------------------------------------------------
    @property
    def violations(self) -> list[dict]:
        return [v.to_dict() for v in self.engine.violations]

    def report(self) -> str:
        """Human-readable summary: '✓ none' or enumerated rendered traces."""
        vs = self.engine.violations
        if not vs:
            return "Agent Sleuth: ✓ no violations detected."
        header = f"Agent Sleuth: {len(vs)} violation(s) detected\n"
        body = "\n\n".join(render(v) for v in vs)
        return header + "\n" + body
