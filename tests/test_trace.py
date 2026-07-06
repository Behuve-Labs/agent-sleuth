from agent_sleuth.core.lineage import Violation
from agent_sleuth.core.trace import render


def _v(blocked=False):
    return Violation(
        sink_tool="send_email",
        sink_field="to",
        sink_arg_value="attacker@evil.com",
        matched_value="attacker@evil.com",
        source_tool="fetch_url",
        source_step=2,
        source_field_path=None,
        destination="attacker@evil.com",
        mode="audit",
        blocked=blocked,
    )


def test_render_audit_says_would_block():
    out = render(_v(blocked=False))
    assert "WOULD BLOCK" in out
    assert "fetch_url" in out
    assert "attacker@evil.com" in out
    assert "audit mode" in out


def test_render_enforce_says_blocked():
    out = render(_v(blocked=True))
    assert "BLOCKED" in out
    assert "blocked, call halted" in out


def test_render_lineage_chain_present():
    out = render(_v())
    assert "Lineage:" in out
    assert "step 2" in out


def test_render_destination_shown():
    out = render(_v())
    assert "Destination:" in out
    assert "not allowlisted" in out
