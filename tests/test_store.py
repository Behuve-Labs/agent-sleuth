from agent_sleuth.core.fingerprint import extract_values
from agent_sleuth.core.store import TaintStore
from agent_sleuth.core.values import Trust


def test_reset_clears_state():
    store = TaintStore()
    vals = extract_values("attacker@evil.com here", source="fetch", trust=Trust.UNTRUSTED,
                          trace_id="t", step=store.next_step())
    store.label(vals, source="fetch", trust=Trust.UNTRUSTED)
    assert store.is_run_tainted()
    assert store.untrusted_values()
    store.reset()
    assert not store.is_run_tainted()
    assert store.untrusted_values() == []
    assert store.step == 0


def test_untrusted_dominates_existing_trusted_label():
    store = TaintStore()
    trusted = extract_values("shared-value-123456", source="trusted_tool",
                             trust=Trust.TRUSTED, trace_id="t", step=store.next_step())
    store.label(trusted, source="trusted_tool", trust=Trust.TRUSTED)
    untrusted = extract_values("shared-value-123456", source="fetch_url",
                               trust=Trust.UNTRUSTED, trace_id="t2", step=store.next_step())
    store.label(untrusted, source="fetch_url", trust=Trust.UNTRUSTED)
    assert any(v.is_tainted() for v in store.untrusted_values())
