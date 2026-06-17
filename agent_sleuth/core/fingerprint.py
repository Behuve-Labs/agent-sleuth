"""core/fingerprint.py — turning tool outputs into trackable values (§4.2).

This is the heart of the value-level approach. On every tool return we extract the
*specific values* worth tracking rather than labeling the whole blob:

- Structured returns (dict / list / JSON-string) are tracked per-field.
- Free text is indexed by high-value extractables (emails, URLs, tokens, phones, IDs)
  pulled with regex, plus the whole normalized blob as a coarse substring candidate.

Matching is deterministic and classifier-free (design principle §11.1): no model is ever
asked "is this an injection?". The only question is "did this exact untrusted-origin value
appear in a sink argument?".
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

from .values import TaintedValue, Trust

# Minimum length (in characters) for a substring/extractable to count as a trackable
# "value". Too short → spurious matches; this is the §12 open decision, resolved at 6.
MIN_VALUE_LEN = 6

# Ordered extractable inventory (§4.2, §12). Order matters: more specific patterns first
# so e.g. a token inside a URL is captured by the URL rule. Each entry is (kind, regex).
_EXTRACTABLE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("token", re.compile(r"\b(?:sk|pk|ghp|gho|ghs|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    # Long hex / base64-ish secret blobs (API keys, hashes) — >= 20 chars.
    ("secret", re.compile(r"\b[A-Za-z0-9+/=_-]{20,}\b")),
    ("phone", re.compile(r"\+?\d[\d\s().-]{7,}\d")),
]

# Kinds whose values are case-insensitive identifiers and may be casefolded when
# normalized. Free text keeps its original case to avoid over-matching.
_CASEFOLD_KINDS = {"email", "url", "uuid"}

_WS = re.compile(r"\s+")


def normalize(s: str, *, casefold: bool = False) -> str:
    """Normalize a string for content-addressing: trim, collapse whitespace runs."""
    out = _WS.sub(" ", s.strip())
    return out.casefold() if casefold else out


def fingerprint(s: str, *, casefold: bool = False) -> str:
    """Content-addressed key for a value: SHA-256 of its normalized form."""
    return hashlib.sha256(normalize(s, casefold=casefold).encode("utf-8")).hexdigest()


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Yield (field_path, leaf_value) for a nested dict/list structure."""
    leaves: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            leaves.extend(_flatten(v, path))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            leaves.extend(_flatten(v, f"{prefix}[{i}]"))
    else:
        leaves.append((prefix, obj))
    return leaves


def _coerce_structured(output: Any) -> Any | None:
    """Return a dict/list if output is one (or a JSON string encoding one), else None."""
    if isinstance(output, (dict, list, tuple)):
        return output
    if isinstance(output, str):
        text = output.strip()
        if text[:1] in ("{", "["):
            try:
                return json.loads(text)
            except (ValueError, TypeError):
                return None
    return None


def extract_values(
    output: Any,
    *,
    source: str,
    trust: Trust,
    trace_id: str,
    step: int | None = None,
) -> list[TaintedValue]:
    """Extract the specific trackable values from a tool's output.

    Structured outputs are tracked per leaf field; free text is indexed by regex
    extractables (plus the whole normalized blob). Returns one TaintedValue per value.
    """
    now = time.time()
    values: list[TaintedValue] = []
    seen: set[str] = set()

    def add(val: Any, field_path: str | None) -> None:
        if val is None:
            return
        text = val if isinstance(val, str) else str(val)
        if len(normalize(text)) < MIN_VALUE_LEN:
            return
        fp = fingerprint(text)
        if fp in seen:
            return
        seen.add(fp)
        values.append(
            TaintedValue(
                value=text,
                trust=trust,
                source=source,
                trace_id=trace_id,
                created_at=now,
                field_path=field_path,
                step=step,
            )
        )

    structured = _coerce_structured(output)
    if structured is not None:
        for path, leaf in _flatten(structured):
            add(leaf, path or None)
            # Leaf strings may themselves embed extractables (e.g. a body field).
            if isinstance(leaf, str):
                for _kind, pat in _EXTRACTABLE_PATTERNS:
                    for m in pat.findall(leaf):
                        add(m, path or None)
    else:
        text = output if isinstance(output, str) else str(output)
        for _kind, pat in _EXTRACTABLE_PATTERNS:
            for m in pat.findall(text):
                add(m, None)
        # Coarse fallback: the whole normalized blob, for verbatim substring lineage.
        add(text, None)

    return values
