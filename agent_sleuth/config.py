"""config.py — optional YAML config loading (§4, §12).

Produces an IFCPolicy from a YAML file; falls back to name-based defaults when absent.
PyYAML is an optional dependency: ``pip install 'agent_sleuth[config]'``.

Example config::

    mode: audit
    untrusted_sources: [read_email, fetch_url, search_web]
    consequential_actions: [send_email, write_file, post_slack]
    destination_allowlist: [me@myco.com]
    destination_fields:
        post_slack: channel
    strict: false
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .core.policy import IFCPolicy


def policy_from_dict(data: dict[str, Any]) -> IFCPolicy:
    return IFCPolicy(
        untrusted_sources=list(data.get("untrusted_sources", []) or []),
        consequential_actions=list(data.get("consequential_actions", []) or []),
        destination_allowlist=list(data.get("destination_allowlist", []) or []),
        destination_fields=dict(data.get("destination_fields", {}) or {}),
        mode=data.get("mode", "audit"),
        strict=bool(data.get("strict", False)),
        use_name_heuristics=bool(data.get("use_name_heuristics", True)),
    )


def load_policy(path: str | Path) -> IFCPolicy:
    """Load an IFCPolicy from a YAML file. Returns name-based defaults if the file is
    missing. Raises ImportError if PyYAML is not installed and a real file is present."""
    p = Path(path)
    if not p.exists():
        return IFCPolicy.from_defaults()
    try:
        import yaml
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "Loading a config file requires PyYAML. "
            "Install with: pip install 'agent_sleuth[config]'"
        ) from e
    data = yaml.safe_load(p.read_text()) or {}
    return policy_from_dict(data)
