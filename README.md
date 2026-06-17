# Agent Sleuth

> **Prevents untrusted data from triggering consequential actions in your agent.**

Agent Sleuth is an in-process **information-flow-control (IFC)** library for LLM agents. It
stops untrusted data (web pages, email bodies, tool outputs, retrieved documents) from
driving **consequential actions** (sending email, writing files, posting to external
services).

The mechanism is **value-level provenance lineage tracked at the tool-I/O boundary** — *not*
taint-tracking through the model's forward pass. When an untrusted tool returns data, we
fingerprint the specific values in it. When a later consequential ("sink") call's arguments
carry those fingerprinted values — verbatim or via structured-field tracking — that is a
**deterministic, classifier-free provenance edge**. A small policy fires: untrusted-origin
value reaching a non-allowlisted external sink → **block or confirm**.

- **Deterministic, not a classifier.** The guarantee is a value-lineage match, never an LLM judging intent.
- **Zero extra LLM calls** on the common path.
- **Drop-in.** Three lines, zero changes to your agent.
- **Audit-mode first.** Observe for a week, then switch to enforce.

## Install

```bash
pip install agent_sleuth                 # core, zero agent-framework deps
pip install 'agent_sleuth[langchain]'    # + LangChain callback handler
pip install 'agent_sleuth[config]'       # + YAML config loading
pip install 'agent_sleuth[dev]'          # + pytest/ruff
```

## Three-line integration (raw / custom agent)

```python
from agent_sleuth import Sleuth

sleuth = Sleuth(
    untrusted=["read_email", "fetch_url", "search_web"],
    consequential=["send_email", "write_file", "post_slack"],
    destinations=["me@myco.com"],   # your own channels = trusted egress
    mode="audit",                   # → "enforce" once you trust it
)
sleuth.reset(query="summarize my emails and send a report to my boss")

# wrap your tools (or pass sleuth.handler to a LangChain agent — see below)
fetch_url  = sleuth.track(fetch_url)
send_email = sleuth.track(send_email)

# ... run your agent ...
print(sleuth.report())
```

You can also skip the explicit lists entirely — `Sleuth()` uses **name-based defaults**
(tools containing `read/fetch/search/get/...` are untrusted; `send/write/post/delete/...`
are consequential).

## LangChain (zero changes to your agent)

```python
from agent_sleuth import Sleuth

sleuth = Sleuth(agent=your_langchain_agent, mode="audit")
result = sleuth.run("summarize my emails and send a report to my boss")
print(sleuth.report())
```

`Sleuth.run()` resets taint state, stashes the trusted query, and attaches the
`IFCCallbackHandler` to your agent — no edits to your chain.

## What a caught attack looks like

```
BLOCKED: send_email() called with tainted inputs
  Taint source: fetch_url (step 2, untrusted)
  Injected value detected in argument: to="attacker@evil.com"
  Lineage: fetch_url (step 2) → value "attacker@evil.com" → send_email.to
  Destination: attacker@evil.com (not allowlisted)
  Reason: untrusted-origin value reached a consequential sink
  Action: blocked, call halted
```

## Modes

- `audit` (default): detect + log + render the trace; **never block**.
- `enforce`: raise `TaintViolationError` and halt the offending sink call.
- `confirm`: surface the violation to a callback for an allow/deny decision before dispatch.

## Honest coverage envelope (v0)

> Sound on the verbatim/structured-exfil class. Zero extra LLM calls on the common path.
> Drop-in. **Laundering** (base64/paraphrase of a secret) and **pure control-flow hijack**
> (a sink call whose arguments carry no untrusted bytes) are explicitly **out of scope for
> v0** — documented non-goals, not bugs. Control-flow integrity (the plan-allowlist) and a
> configurable allow/denylist with deny-over-allow precedence land in v1.

| Attack class | v0 |
|---|---|
| Verbatim exfiltration (untrusted value appears literally in sink arg) | ✅ deterministic |
| Structured exfiltration (untrusted field → sink field) | ✅ deterministic |
| Legit egress to your own channel (destination allowlist) | ✅ allowed (no false positive) |
| Control-flow hijack (out-of-plan sink, no untrusted bytes) | ❌ v1 (plan-allowlist) |
| Laundering (base64 / paraphrase / transform) | ❌ v2+ (opt-in quarantine) |

## Benchmark

```bash
PYTHONPATH=. python benchmarks/agentdojo/run.py
```

A self-contained reproduction of AgentDojo-style indirect-injection tasks (real AgentDojo
needs a live LLM + API keys; see the harness docstring for the thin real-AgentDojo wiring).
Reports ASR (attack success rate) and utility per mode.

## Develop

```bash
pip install -e '.[dev,langchain,config]'
pytest
```

See `AGENT_SLEUTH_ARCHITECTURE.MD` for the full design.
