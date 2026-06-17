from agent_sleuth.core.fingerprint import extract_values, fingerprint, normalize
from agent_sleuth.core.values import Trust


def _vals(output):
    return [v.value for v in extract_values(output, source="s", trust=Trust.UNTRUSTED,
                                            trace_id="t", step=1)]


def test_normalize_collapses_whitespace():
    assert normalize("  a   b\tc\n") == "a b c"
    assert normalize("ABC@X.com", casefold=True) == "abc@x.com"


def test_fingerprint_stable_and_normalized():
    assert fingerprint("hello  world") == fingerprint(" hello world ")
    assert fingerprint("a") != fingerprint("b")


def test_extract_email_and_url():
    vals = _vals("reach me at bob@example.com or https://evil.tld/x")
    assert "bob@example.com" in vals
    assert any("evil.tld" in v for v in vals)


def test_extract_token_and_uuid():
    vals = _vals("key sk-ABCDEF012345 id 123e4567-e89b-12d3-a456-426614174000")
    assert any(v.startswith("sk-") for v in vals)
    assert "123e4567-e89b-12d3-a456-426614174000" in vals


def test_short_values_ignored():
    # 'a@b.c' is shorter than MIN_VALUE_LEN and should not be tracked as free text noise.
    vals = _vals("hi")
    assert vals == []  # whole blob 'hi' is under min length


def test_structured_per_field():
    out = {"results": [{"email": "x@y.com", "score": 9}], "note": "see http://z.io/p"}
    vals = _vals(out)
    assert "x@y.com" in vals
    assert any("z.io" in v for v in vals)


def test_json_string_is_treated_as_structured():
    vals = _vals('{"to": "a@b.com", "name": "Alice Wong"}')
    assert "a@b.com" in vals
