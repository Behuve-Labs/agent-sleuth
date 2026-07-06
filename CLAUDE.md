# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
pip install -e '.[dev,langchain,config]'

# Run all tests
pytest

# Run a single test file
pytest tests/test_e2e.py

# Run a single test by name
pytest tests/test_e2e.py::test_decorator_enforce_blocks

# Lint
ruff check agent_sleuth/ tests/

# Run the AgentDojo benchmark
PYTHONPATH=. python benchmarks/agentdojo/run.py

# Run the quickstart example
PYTHONPATH=. python examples/quickstart.py
```

## Architecture

Agent Sleuth is an **in-process IFC (information-flow-control) library** that prevents untrusted tool outputs (web pages, emails, retrieved docs) from reaching consequential sinks (send_email, write_file, post_slack) inside an LLM agent. The mechanism is **value-level provenance lineage tracked at the tool I/O boundary** — not taint-tracking through the model's forward pass.

### Why boundary-lineage, not taint-through-LLM

Classical taint analysis collapses to "everything downstream of one web fetch is tainted" when applied to an LLM (taint explosion). Agent Sleuth avoids this by tracking only the **specific values** that cross the tool boundary: fingerprinting untrusted tool outputs and checking whether those exact values appear verbatim or as structured fields in later sink call arguments. This is deterministic and classifier-free.

### Data flow

1. **Untrusted tool returns** → `Engine.on_tool_result()` → `fingerprint.extract_values()` extracts specific strings/emails/URLs/tokens from the output → stored in `TaintStore` with source + trust label.
2. **Consequential tool called** → `Engine.on_tool_call()` → `lineage.check()` tests whether any sink argument contains an untrusted-origin fingerprint → returns a `Violation` or `None`.
3. On violation: **audit** logs it, **enforce** raises `TaintViolationError`, **confirm** routes to a callback.

### Module map

```
agent_sleuth/
├── core/
│   ├── values.py       # TaintedValue + Trust enum — the tracked atom
│   ├── fingerprint.py  # extract_values(): per-field structured + regex extractables
│   ├── store.py        # TaintStore: content-addressed fingerprint → TaintedValue map
│   ├── policy.py       # IFCPolicy: source/sink classification, destination allowlist
│   ├── lineage.py      # check(): the matching engine — returns Violation or None
│   ├── trace.py        # render(): human-readable "why blocked" lineage chain
│   └── errors.py       # TaintViolationError
├── adapters/
│   ├── decorator.py    # tracked_tool: wraps raw functions, calls engine.on_tool_call/result
│   └── langchain.py    # IFCCallbackHandler: translates LangChain callbacks to engine calls
├── engine.py           # Engine: framework-agnostic ingress/egress glue shared by all adapters
├── runtime.py          # Sleuth: the public API — constructs policy/store/engine, exposes .run()/.report()
├── config.py           # YAML config loading (optional dep)
└── __init__.py         # exports: Sleuth, TaintViolationError, Trust, IFCPolicy
```

### Key design invariants

- **`core/` is zero-dependency.** It never imports LangChain or any agent framework. Adapters translate framework events into `Engine.on_tool_call()` / `Engine.on_tool_result()` calls.
- **No classifier on the enforcement path.** The lineage check is always a deterministic string/fingerprint match — never an LLM call.
- **`audit` is the default mode.** Logs violations, never blocks. Developers switch to `enforce` once they trust the policy.
- **`TaintStore.reset()` is called per run.** Taint does not bleed across independent agent invocations.

### Known v0 non-goals (document, don't fix)

- **Laundering**: base64/paraphrase/transform of a secret defeats verbatim matching. Planned for v2+ as opt-in constrained-decoding quarantine.
- **Pure control-flow hijack**: a sink call whose arguments carry no untrusted bytes (e.g. "now call delete_all"). Planned for v1 via a plan-allowlist.
