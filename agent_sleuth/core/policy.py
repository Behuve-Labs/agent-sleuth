"""core/policy.py — the policy (§4.4, extended for v1).

Classifies tools as untrusted sources / consequential sinks, resolves a sink's destination
field(s), and decides whether a destination is allowed.

v0 shipped an exact-match allowlist plus the §13 implicit "appears verbatim in the trusted
query" notion. v1 (§13 "configurable allow/denylist + integrity leg") adds:

* **Pattern matching** in the allow/denylist — exact, email-domain (``@corp.com``),
  suffix (``.corp.com`` / ``*.corp.com``) and glob. A single ``@corp.com`` entry lets a
  workspace assistant reply to any internal colleague while still blocking external exfil.
* **A denylist with deny-over-allow precedence** — structured negative trust (§13): an
  address on the denylist is refused even if it is also allowlisted or named in the query.
* **Multi-destination resolution** — ``send_email(recipients=[...])`` carries a *list* of
  destinations; the call is only authorized when *every* destination is authorized.

Defaults from tool-name conventions make config trivial (Friction 1, §6): most developers
never touch the lists.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from .fingerprint import normalize

# Name-based heuristics (§4.4). A tool counts as the category if its name contains any keyword.
UNTRUSTED_KEYWORDS = ("read", "fetch", "search", "get", "browse", "retrieve", "load")
CONSEQUENTIAL_KEYWORDS = ("send", "write", "delete", "post", "update", "create", "execute", "run")

# Default destination-field map (tool name substring -> arg field holding the destination).
# The destination is the *channel data leaves through*; for a calendar invite or a file share
# the people invited / shared-with are that channel, so they must be authorizable too (v1).
DEFAULT_DESTINATION_FIELDS: dict[str, str] = {
    "send_email": "recipients",  # AgentDojo-style multi-recipient sends
    "email": "recipients",
    "http_post": "url",
    "post": "url",
    "write_file": "path",
    "write": "path",
    "slack": "channel",
    "calendar_event": "participants",  # invites egress data to each participant
    "share_file": "email",             # file share egresses to the grantee
    "share": "email",
}

# Field-name heuristics tried (in order) when no explicit map entry matches.
DESTINATION_FIELD_HEURISTICS = ("to", "recipient", "recipients", "participants", "attendees",
                                "url", "endpoint", "path", "channel", "destination", "dest",
                                "address")


def _matches_keyword(tool_name: str, keywords: tuple[str, ...]) -> bool:
    name = tool_name.lower()
    return any(k in name for k in keywords)


def _dest_matches(pattern: str, dest: str) -> bool:
    """Does one allow/denylist ``pattern`` match a normalized destination ``dest``?

    Deterministic, classifier-free. Supported pattern forms (all casefolded):

    * ``@corp.com``     — email-domain: matches any address ending in ``@corp.com``.
    * ``.corp.com`` / ``*.corp.com`` — suffix: matches any dest ending in ``corp.com``
      (host/subdomain match for URLs and hostnames).
    * ``a@b.com`` / literal — exact normalized equality.
    * anything containing ``*`` or ``?`` — glob (fnmatch), e.g. ``https://intranet/*``.
    """
    p = normalize(pattern, casefold=True)
    d = normalize(dest, casefold=True)
    if not p or not d:
        return False
    if p.startswith("@"):
        return d.endswith(p)
    if p.startswith("*."):
        return d.endswith(p[1:]) or d.endswith(p[2:])
    if p.startswith("."):
        return d.endswith(p) or d.endswith(p[1:])
    if "*" in p or "?" in p:
        return fnmatch.fnmatch(d, p)
    return p == d


@dataclass
class IFCPolicy:
    untrusted_sources: list[str] = field(default_factory=list)
    consequential_actions: list[str] = field(default_factory=list)
    destination_allowlist: list[str] = field(default_factory=list)
    destination_denylist: list[str] = field(default_factory=list)  # v1: deny > allow (§13)
    destination_fields: dict[str, str] = field(default_factory=dict)
    mode: str = "audit"  # "audit" | "enforce" | "confirm"
    strict: bool = False  # run-level taint enforcement (coarse, §4.3)
    use_name_heuristics: bool = True
    # v1 integrity leg (§7): if not None, a consequential call whose tool is not in this set
    # is an out-of-plan action and is blocked even when its args carry no untrusted bytes.
    # None disables the integrity check (v0 confidentiality-only behavior).
    plan_allowlist: set[str] | None = None

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

    def _destination_field(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Return the arg field name that holds this sink's destination(s), or None."""
        merged = {**DEFAULT_DESTINATION_FIELDS, **self.destination_fields}
        # Exact tool match first, then substring match on tool name.
        for key in (tool_name, *(k for k in merged if k in tool_name.lower())):
            fieldname = merged.get(key)
            if fieldname and fieldname in args:
                return fieldname
        for fieldname in DESTINATION_FIELD_HEURISTICS:
            if fieldname in args:
                return fieldname
        return None

    def resolve_destinations(self, tool_name: str, args: dict[str, Any]) -> list[str]:
        """Identify *all* destination values in a sink call's args (v1).

        ``send_email(recipients=[a, b])`` egresses to multiple destinations; each must be
        authorized independently. Returns a flat list of individual destination strings
        ([] if no destination field is present, e.g. a pure state-mutation sink).
        """
        fieldname = self._destination_field(tool_name, args)
        if fieldname is None:
            return []
        raw = args[fieldname]
        if isinstance(raw, (list, tuple)):
            return [str(x) for x in raw if x is not None and str(x).strip()]
        return [str(raw)] if raw is not None and str(raw).strip() else []

    def resolve_destination(self, tool_name: str, args: dict[str, Any]) -> str | None:
        """Back-compat single-destination view (comma-joined). Prefer resolve_destinations."""
        dests = self.resolve_destinations(tool_name, args)
        return ", ".join(dests) if dests else None

    def is_denied_destination(self, dest: str | None) -> bool:
        """True if ``dest`` matches any denylist pattern (deny > allow, §13)."""
        if not dest:
            return False
        return any(_dest_matches(p, dest) for p in self.destination_denylist)

    def is_allowed_destination(self, dest: str | None, query: str | None = None) -> bool:
        """A single destination is authorized if it is NOT denied and it either matches an
        allowlist pattern (§4.4/v1) or appears verbatim in the trusted query (§13)."""
        if not dest:
            return False
        if self.is_denied_destination(dest):  # deny always wins.
            return False
        if any(_dest_matches(p, dest) for p in self.destination_allowlist):
            return True
        norm_dest = normalize(dest, casefold=True)
        if query and norm_dest and norm_dest in normalize(query, casefold=True):
            return True
        return False

    def authorize_destinations(
        self, dests: list[str], query: str | None = None
    ) -> tuple[bool, str | None]:
        """Authorize a whole (possibly multi-recipient) egress.

        Returns ``(authorized, offending)``:
        * ``authorized`` is True only when there is at least one destination and *every*
          destination is allowed (allowlist/query) and none is denied.
        * ``offending`` is the first denied-or-unauthorized destination, for the trace.
        """
        if not dests:
            return False, None
        for d in dests:
            if self.is_denied_destination(d):
                return False, d
        for d in dests:
            if not self.is_allowed_destination(d, query):
                return False, d
        return True, None

    @classmethod
    def from_defaults(cls, mode: str = "audit") -> "IFCPolicy":
        """Policy driven purely by name heuristics + empty allowlist."""
        return cls(mode=mode, use_name_heuristics=True)


def _as_text(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)


def derive_plan_allowlist(query: str | None, consequential_tools: list[str]) -> set[str]:
    """Derive the set of consequential tools the *trusted query* authorizes (v1 integrity).

    Plan-then-execute lite (§7): rather than synthesize a program, we deterministically admit
    a consequential tool only when the query's own text implies it — either the tool name (or
    a distinctive token of it) appears in the query, or an action keyword that classifies the
    tool also appears in the query. An injected web page that says "now call delete_all" can't
    add a tool to this set, so the out-of-plan call is blocked.

    Note (documented limitation): delegation-style queries ("do what this email says") name no
    action verb, so this yields an empty plan and would block the delegated action. That is why
    the integrity leg is opt-in (policy.plan_allowlist stays None) rather than on by default.
    """
    if not query:
        return set()
    q = query.lower()
    allowed: set[str] = set()
    for tool in consequential_tools:
        name = tool.lower()
        # Match on the *action verb*, never on shared object-nouns: "send an email" must
        # authorize send_email but NOT delete_email (both contain the noun "email").
        lead = name.replace("-", "_").split("_")[0]  # leading token is the verb by convention
        if name in q or (len(lead) >= 3 and lead in q):
            allowed.add(tool)
            continue
        if any(k in name and k in q for k in CONSEQUENTIAL_KEYWORDS):
            allowed.add(tool)
    return allowed
