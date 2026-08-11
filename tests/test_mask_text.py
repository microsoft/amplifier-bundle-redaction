"""Unit tests for the public redaction primitives: mask_text and scrub.

These cover the public API extracted so consumer apps can depend on the vetted
masker directly instead of vendoring a private copy. Each secret/PII pattern
category is exercised, rule gating is verified, and idempotence is asserted.
"""

from redaction import mask_text
from redaction import scrub

SECRET = "[REDACTED:SECRET]"
PII = "[REDACTED:PII]"

# Representative samples for each existing pattern category.
#
# All secret-shaped values below are assembled from fragments (never one
# contiguous literal in source) so they can't be flagged by source-level
# secret scanners / push-protection, while the runtime-assembled value
# still matches the corresponding SECRET_PATTERNS regex exactly the same.
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
SLACK_KEY = "xoxb" + "-123456789012-ABCDEFabcdef"
GOOGLE_KEY = "AIza" + "B" * 35
JWT = (
    "eyJ"
    + "hbGciOiJIUzI1NiJ9"
    + "."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    + "."
    + "dozjgNryP4J3jVmNHl0w5N"
)
EMAIL = "alice@example.com"
PHONE = "+1 (555) 123-4567"


class TestMaskTextSecrets:
    def test_aws_access_key(self):
        assert mask_text(f"key={AWS_KEY}") == f"key={SECRET}"

    def test_slack_key(self):
        assert mask_text(f"t={SLACK_KEY}") == f"t={SECRET}"

    def test_google_key(self):
        out = mask_text(f"g={GOOGLE_KEY}")
        assert GOOGLE_KEY not in out
        assert SECRET in out

    def test_jwt(self):
        assert mask_text(f"bearer {JWT}") == f"bearer {SECRET}"


class TestMaskTextPII:
    def test_email(self):
        assert mask_text(f"contact {EMAIL}") == f"contact {PII}"

    def test_phone(self):
        out = mask_text(f"call {PHONE}")
        assert "555" not in out
        assert PII in out


class TestRuleGating:
    def test_default_rules_apply_both(self):
        out = mask_text(f"{AWS_KEY} and {EMAIL}")
        assert AWS_KEY not in out
        assert EMAIL not in out
        assert SECRET in out
        assert PII in out

    def test_secrets_only_leaves_pii(self):
        out = mask_text(f"{AWS_KEY} and {EMAIL}", rules=("secrets",))
        assert SECRET in out
        assert EMAIL in out  # PII rule disabled
        assert PII not in out

    def test_pii_only_leaves_secrets(self):
        out = mask_text(f"{AWS_KEY} and {EMAIL}", rules=("pii-basic",))
        assert PII in out
        assert AWS_KEY in out  # secrets rule disabled
        assert SECRET not in out

    def test_no_rules_masks_nothing(self):
        text = f"{AWS_KEY} and {EMAIL}"
        assert mask_text(text, rules=()) == text

    def test_unknown_rule_ignored(self):
        text = f"{AWS_KEY} and {EMAIL}"
        assert mask_text(text, rules=("bogus",)) == text

    def test_accepts_list_rules(self):
        # Sequence[str] — list is a valid input, not only the default tuple.
        out = mask_text(f"k={AWS_KEY}", rules=["secrets"])
        assert out == f"k={SECRET}"


class TestNonMatchingAndIdempotence:
    def test_clean_text_unchanged(self):
        text = "nothing sensitive here, just words 42"
        assert mask_text(text) == text

    def test_empty_string(self):
        assert mask_text("") == ""

    def test_idempotent(self):
        text = f"{AWS_KEY} / {EMAIL} / {JWT}"
        once = mask_text(text)
        twice = mask_text(once)
        assert once == twice


class TestScrubPublic:
    def test_masks_strings_in_nested_structure(self):
        obj = {"a": [f"k={AWS_KEY}", {"b": EMAIL}], "n": 3}
        out = scrub(obj)
        assert out["a"][0] == f"k={SECRET}"
        assert out["a"][1]["b"] == PII
        assert out["n"] == 3  # non-str scalar untouched

    def test_default_allowlist_protects_timestamp(self):
        obj = {"timestamp": "2026-02-20T14:30:00Z", "msg": EMAIL}
        out = scrub(obj)
        assert out["timestamp"] == "2026-02-20T14:30:00Z"
        assert out["msg"] == PII

    def test_explicit_allowlist_exempts_path(self):
        obj = {"keep": EMAIL, "drop": EMAIL}
        out = scrub(obj, allowlist={"keep"})
        assert out["keep"] == EMAIL
        assert out["drop"] == PII

    def test_returns_copy_not_mutating_input(self):
        obj = {"msg": EMAIL}
        scrub(obj)
        assert obj["msg"] == EMAIL  # original untouched


def test_all_exports_public_names():
    import redaction as mod

    assert set(mod.__all__) == {
        "SECRET_PATTERNS",
        "PII_PATTERNS",
        "DEFAULT_ALLOWLIST",
        "IDENTIFIER_KEYS",
        "DATETIME_KEYS",
        "DEFAULT_RULES",
        "mask_text",
        "scrub",
        "RedactionConfig",
        "Redactor",
    }
