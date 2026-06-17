"""core/lineage.py — the matching engine (§4.5).

Given a pending sink call (tool name + arguments) and the provenance store, decide whether
the call carries untrusted-origin values to a non-allowlisted destination. The check is
deterministic: verbatim substring match or structured-field equality against untrusted
fingerprints — never an LLM judging intent (§11.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fingerprint import MIN_VALUE_LEN, fingerprint, normalize
from .policy import IFCPolicy
from .store import TaintStore


@dataclass
class Violation:
    """A detected untrusted-origin → sink flow, carrying the full lineage chain."""

    sink_tool: str
    sink_field: str | None
    sink_arg_value: str
    matched_value: str
    source_tool: str
    source_step: int | None
    source_field_path: str | None
    destination: str | None
    mode: str
    reason: str = "untrusted-origin value reached a consequential sink"
    blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_tool": self.sink_tool,
            "sink_field": self.sink_field,
            "sink_arg_value": self.sink_arg_value,
            "matched_value": self.matched_value,
            "source_tool": self.source_tool,
            "source_step": self.source_step,
            "source_field_path": self.source_field_path,
            "destination": self.destination,
            "mode": self.mode,
            "reason": self.reason,
            "blocked": self.blocked,
        }


def _iter_arg_values(args: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten sink args into (field_name, text) pairs for matching."""
    out: list[tuple[str, str]] = []

    def rec(field_name: str, val: Any) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                rec(f"{field_name}.{k}" if field_name else str(k), v)
        elif isinstance(val, (list, tuple)):
            for i, v in enumerate(val):
                rec(f"{field_name}[{i}]", v)
        elif val is not None:
            out.append((field_name, val if isinstance(val, str) else str(val)))

    for k, v in args.items():
        rec(k, v)
    return out


def check(
    tool_name: str,
    args: dict[str, Any],
    store: TaintStore,
    policy: IFCPolicy,
    query: str | None = None,
) -> Violation | None:
    """Run the v0 lineage algorithm. Returns a Violation or None (allow)."""
    # 1. Not consequential → allow.
    if not policy.is_consequential(tool_name):
        return None

    # 2. Destination allowlisted (config) or in trusted query → allow.
    destination = policy.resolve_destination(tool_name, args)
    if policy.is_allowed_destination(destination, query):
        return None

    arg_values = _iter_arg_values(args)
    untrusted = store.untrusted_values()

    # 3. For each value in the sink args, test value-lineage against untrusted fingerprints.
    for tv in untrusted:
        src_text = tv.value if isinstance(tv.value, str) else str(tv.value)
        src_fp = fingerprint(src_text)
        src_norm = normalize(src_text)
        if len(src_norm) < MIN_VALUE_LEN:
            continue
        for field_name, arg_text in arg_values:
            arg_norm = normalize(arg_text)
            # Structured-field equality (exact) or verbatim substring containment.
            if fingerprint(arg_text) == src_fp or src_norm in arg_norm:
                return Violation(
                    sink_tool=tool_name,
                    sink_field=field_name,
                    sink_arg_value=arg_text,
                    matched_value=src_text,
                    source_tool=tv.source,
                    source_step=tv.step,
                    source_field_path=tv.field_path,
                    destination=destination,
                    mode=policy.mode,
                )

    # 5. Strict / run-level mode: no untrusted value present but run is tainted → violation.
    if policy.strict and store.is_run_tainted():
        return Violation(
            sink_tool=tool_name,
            sink_field=None,
            sink_arg_value="",
            matched_value="(run-level taint)",
            source_tool="(run)",
            source_step=None,
            source_field_path=None,
            destination=destination,
            mode=policy.mode,
            reason="strict mode: consequential sink fired in a tainted run",
        )

    return None
