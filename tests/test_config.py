from agent_sleuth.config import load_policy, policy_from_dict


def test_policy_from_dict_defaults():
    p = policy_from_dict({})
    assert p.mode == "audit"
    assert p.strict is False
    assert p.use_name_heuristics is True


def test_policy_from_dict_full():
    p = policy_from_dict({
        "mode": "enforce",
        "untrusted_sources": ["read_x"],
        "consequential_actions": ["write_y"],
        "destination_allowlist": ["me@myco.com"],
        "strict": True,
        "use_name_heuristics": False,
    })
    assert p.mode == "enforce"
    assert "read_x" in p.untrusted_sources
    assert "write_y" in p.consequential_actions
    assert "me@myco.com" in p.destination_allowlist
    assert p.strict is True
    assert p.use_name_heuristics is False


def test_load_policy_missing_file_returns_defaults():
    p = load_policy("/nonexistent/path/sleuth.yaml")
    assert p.mode == "audit"


def test_load_policy_reads_yaml(tmp_path):
    cfg = tmp_path / "sleuth.yaml"
    cfg.write_text("mode: enforce\nuntrusted_sources: [fetch_url]\n")
    p = load_policy(cfg)
    assert p.mode == "enforce"
    assert "fetch_url" in p.untrusted_sources
