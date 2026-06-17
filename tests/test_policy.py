from agent_sleuth.core.policy import IFCPolicy


def test_name_heuristics():
    p = IFCPolicy.from_defaults()
    assert p.is_untrusted_source("fetch_url")
    assert p.is_untrusted_source("read_email")
    assert p.is_consequential("send_email")
    assert p.is_consequential("write_file")
    assert not p.is_consequential("summarize")


def test_explicit_lists_override_when_heuristics_off():
    p = IFCPolicy(untrusted_sources=["x"], consequential_actions=["y"],
                  use_name_heuristics=False)
    assert p.is_untrusted_source("x")
    assert not p.is_untrusted_source("fetch_url")
    assert p.is_consequential("y")
    assert not p.is_consequential("send_email")


def test_resolve_destination_map_and_heuristic():
    p = IFCPolicy.from_defaults()
    assert p.resolve_destination("send_email", {"to": "a@b.com", "body": "x"}) == "a@b.com"
    assert p.resolve_destination("post_slack", {"channel": "#ops"}) == "#ops"
    # heuristic fallback for unknown tool
    assert p.resolve_destination("notify", {"recipient": "c@d.com"}) == "c@d.com"


def test_allowlist_and_query_destination():
    p = IFCPolicy.from_defaults()
    p.destination_allowlist = ["me@myco.com"]
    assert p.is_allowed_destination("me@myco.com")
    assert p.is_allowed_destination("ME@MYCO.COM")  # casefold
    assert not p.is_allowed_destination("attacker@evil.com")
    # §13 implicit: destination appears verbatim in the trusted query
    assert p.is_allowed_destination("boss@myco.com", query="email a report to boss@myco.com")
