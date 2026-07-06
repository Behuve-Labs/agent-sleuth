"""core/trace.py — the "why blocked" provenance trace (§4.7).

This is not a nice-to-have, it is the marketing (§8). On every violation we render the
lineage chain from source to sink in a form that is genuinely readable and shareable. A
screenshot of a caught attack is the entire early growth strategy.
"""

from __future__ import annotations

from .lineage import Violation


def _short(s: str, limit: int = 80) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def render(violation: Violation) -> str:
    """Render a violation as a readable source→sink lineage chain."""
    v = violation
    verb = "BLOCKED" if v.blocked else "WOULD BLOCK"

    # v1 non-lineage violations (denylist / out-of-plan integrity) have no untrusted-value
    # provenance chain — render them as a policy decision, not a source→sink flow.
    if v.source_tool in ("(denylist)", "(plan-allowlist)"):
        lines = [f"{verb}: {v.sink_tool}() refused by policy"]
        if v.destination:
            lines.append(f"  Destination: {_short(v.destination)}")
        lines.append(f"  Reason: {v.reason}")
        lines.append(
            f"  Action: {'blocked, call halted' if v.blocked else 'logged (audit mode), call allowed'}"
        )
        return "\n".join(lines)

    src = v.source_tool
    if v.source_step is not None:
        src += f" (step {v.source_step}, untrusted)"
    else:
        src += " (untrusted)"
    if v.source_field_path:
        src += f" field {v.source_field_path}"

    sink_field = v.sink_field or "?"
    lineage = (f"{v.source_tool}"
               + (f" (step {v.source_step})" if v.source_step is not None else "")
               + f" → value \"{_short(v.matched_value)}\""
               + f" → {v.sink_tool}.{sink_field}")

    action = "blocked, call halted" if v.blocked else "logged (audit mode), call allowed"

    lines = [
        f"{verb}: {v.sink_tool}() called with tainted inputs",
        f"  Taint source: {src}",
        f"  Injected value detected in argument: {sink_field}=\"{_short(v.sink_arg_value)}\"",
        f"  Lineage: {lineage}",
    ]
    if v.destination:
        lines.append(f"  Destination: {_short(v.destination)} (not allowlisted)")
    lines.append(f"  Reason: {v.reason}")
    lines.append(f"  Action: {action}")
    return "\n".join(lines)
