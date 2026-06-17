"""core/policy.py — the policy (§4.4).

Classifies tools as untrusted sources / consequential sinks, resolves a sink's destination
field, and decides whether a destination is allowed (configurable allowlist + the §13
implicit "appears verbatim in the trusted query" notion).

Defaults from tool-name conventions make config trivial (Friction 1, §6): most developers
never touch the lists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .fingerprint import normalize

# Name-based heuristics (§4.4). A tool counts as the category if its name contains any keyword.
UNTRUSTED_KEYWORDS = ("read", "fetch", "search", "get", "browse", "retrieve", "load")
CONSEQUENTIAL_KEYWORDS = ("send", "write", "delete", "post", "update", "create", "execute", "run")

# Default destination-field map (tool name substring -> arg field holding the destination).
DEFAULT_DESTINATION_FIELDS: dict[str, str] = {
    "send_email": "to",
    "email": "to",
    "http_post": "url",
    "post": "url",
    "write_file": "path",
    "write": "path",
    "slack": "channel",
}

# Field-name heuristics tried (in order) when no explicit map entry matches.
DESTINATION_FIELD_HEURISTICS = ("to", "recipient", "recipients", "url", "endpoint",
                                "path", "channel", "destination", "dest", "address")


def _matches_keyword(tool_name: str, keywords: tuple[str, ...]) -> bool:
    name = tool_name.lower()
    return any(k in name for k in keywords)


@dataclass
class IFCPolicy:
    untrusted_sources: list[str] = field(default_factory=list)
    consequential_actions: list[str] = field(default_factory=list)
    destination_allowlist: list[str] = field(default_factory=list)
    destination_fields: dict[str, str] = field(default_factory=dict)
    mode: str = "audit"  # "audit" | "enforce" | "confirm"
    strict: bool = False  # run-level taint enforcement (coarse, §4.3)
    use_name_heuristics: bool = True

    def is_untrusted_source(self, tool_name: str) -> bool:
        if tool_name in self.untrusted_sources:
            return True
        if self.use_name_heuristics and _matches_keyword(tool_name, UNTRUSTED_KEYWORDS):
            return True
        return False

    def is_consequential(self, tool_name: str) -> bool:
        if tool_name in self.consequential_actions:
            return True
        if self.use_name_heuristics and _matches_keyword(tool_name, CONSEQUENTIAL_KEYWORDS):
            return True
        return False

    def resolve_destination(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Identify the destination value in a sink call's args.

        Tries the explicit destination_fields map (default + developer overrides), then
        the field-name heuristics.
        """
        merged = {**DEFAULT_DESTINATION_FIELDS, **self.destination_fields}
        # Exact tool match first, then substring match on tool name.
        for key in (tool_name, *(k for k in merged if k in tool_name.lower())):
            fieldname = merged.get(key)
            if fieldname and fieldname in args:
                return _as_text(args[fieldname])
        for fieldname in DESTINATION_FIELD_HEURISTICS:
            if fieldname in args:
                return _as_text(args[fieldname])
        return None

    def is_allowed_destination(self, dest: str | None, query: str | None = None) -> bool:
        """A destination is allowed if it is on the configurable allowlist (§4.4) or
        appears verbatim in the trusted query (§13 implicit notion)."""
        if not dest:
            return False
        norm_dest = normalize(dest, casefold=True)
        for allowed in self.destination_allowlist:
            if normalize(allowed, casefold=True) == norm_dest:
                return True
        if query and norm_dest and norm_dest in normalize(query, casefold=True):
            return True
        return False

    @classmethod
    def from_defaults(cls, mode: str = "audit") -> "IFCPolicy":
        """Policy driven purely by name heuristics + empty allowlist."""
        return cls(mode=mode, use_name_heuristics=True)


def _as_text(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)
