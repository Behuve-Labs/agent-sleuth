"""Tests for v1 additions: pattern allow/denylist, multi-destination authorization,
denylist precedence, and the opt-in plan-allowlist integrity leg."""

from agent_sleuth import Sleuth
from agent_sleuth.core.lineage import check
from agent_sleuth.core.policy import IFCPolicy, derive_plan_allowlist
from agent_sleuth.core.store import TaintStore
from agent_sleuth.core.values import Trust


# --- pattern matching in the allowlist ---------------------------------------------------

def test_domain_pattern_allow():
    p = IFCPolicy(consequential_actions=["send_email"], destination_allowlist=["@corp.com"])
    assert p.is_allowed_destination("alice@corp.com")
    assert not p.is_allowed_destination("attacker@gmail.com")


def test_suffix_and_glob_patterns():
    p = IFCPolicy(destination_allowlist=[".corp.com", "https://intranet/*"])
    assert p.is_allowed_destination("https://mail.corp.com")
    assert p.is_allowed_destination("https://intranet/page")
    assert not p.is_allowed_destination("https://evil.com/page")


# --- denylist precedence (deny > allow, deny > query) -------------------------------------

def test_denylist_beats_allowlist_and_query():
    p = IFCPolicy(destination_allowlist=["@corp.com"], destination_denylist=["mole@corp.com"])
    assert p.is_denied_destination("mole@corp.com")
    assert not p.is_allowed_destination("mole@corp.com")  # denied even though @corp.com allowed
    assert not p.is_allowed_destination("mole@corp.com", query="email mole@corp.com")


# --- multi-destination authorization -----------------------------------------------------

def test_multi_recipient_all_must_be_authorized():
    p = IFCPolicy(consequential_actions=["send_email"], destination_allowlist=["@corp.com"])
    assert p.resolve_destinations("send_email", {"recipients": ["a@corp.com", "b@corp.com"]}) == \
        ["a@corp.com", "b@corp.com"]
    ok, off = p.authorize_destinations(["a@corp.com", "b@corp.com"])
    assert ok and off is None
    ok, off = p.authorize_destinations(["a@corp.com", "x@evil.com"])
    assert not ok and off == "x@evil.com"


def test_allowlisted_recipient_allows_tainted_body():
    """A send to an allowlisted recipient is not a violation even with tainted content."""
    store = TaintStore()
    store.label(
        [__tv("secret-project-report", Trust.UNTRUSTED, "read_email")],
        source="read_email", trust=Trust.UNTRUSTED,
    )
    p = IFCPolicy(consequential_actions=["send_email"], destination_allowlist=["@corp.com"])
    args = {"recipients": ["boss@corp.com"], "body": "secret-project-report"}
    assert check("send_email", args, store, p) is None  # allowed
    # same body to an external recipient → blocked
    args2 = {"recipients": ["attacker@gmail.com"], "body": "secret-project-report"}
    assert check("send_email", args2, store, p) is not None


# --- plan-allowlist integrity leg --------------------------------------------------------

def test_derive_plan_uses_verb_not_object_noun():
    plan = derive_plan_allowlist("send an email to Bob", ["send_email", "delete_email"])
    assert plan == {"send_email"}  # 'delete_email' shares the noun 'email' but not the verb


def test_plan_mode_blocks_out_of_plan_call():
    s = Sleuth(consequential=["send_email", "delete_email"], mode="enforce", plan_mode=True)
    s.reset(query="send an email to Bob")
    # delete_email was never authorized by the query → out-of-plan block, no untrusted bytes needed
    v = check("delete_email", {"email_id": "42"}, s.store, s.policy)
    assert v is not None and "out-of-plan" in v.reason
    # send_email is in plan → allowed (no taint present)
    assert check("send_email", {"recipients": ["bob@corp.com"]}, s.store, s.policy) is None


def __tv(value, trust, source):
    from agent_sleuth.core.values import TaintedValue
    import time
    return TaintedValue(value=value, trust=trust, source=source, trace_id="t",
                        created_at=time.time(), field_path=None, step=1)
