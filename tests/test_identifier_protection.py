"""Regression tests for issue #386 / I6: PII filter corrupts node_ids at ingest.

The downstream Context Intelligence graph composes ``node_id`` from event
fields (``session_id`` + ``timestamp`` + ``tool_call_id``). Two mechanisms
combine to corrupt those join keys, and this suite covers both fixes plus the
key-based protection that backstops them:

* **Key-based protection** (depth-independent): identifier/datetime-named fields
  are exempt from PII masking but still secret-scrubbed, at any nesting depth.
* **Guarded phone regex** (Proposal 3): lookbehind/lookahead stops the phone
  pattern from matching inside UUIDs / hex ids / ISO timestamps, so those are no
  longer corrupted even in free-form fields.
* **Allowlist precedence** (Proposal 2): an exact-path allowlist entry wins
  first and returns the field byte-identical.
* **PII-bearing id exclusion**: person-identifying id-shaped keys (``user_id``)
  are deliberately NOT protected and remain fully scrubbed.
"""

from redaction import DATETIME_KEYS
from redaction import DEFAULT_ALLOWLIST
from redaction import IDENTIFIER_KEY_PATTERNS
from redaction import RedactionConfig
from redaction import Redactor
from redaction import mask_text
from redaction import scrub

RULES = ["secrets", "pii-basic"]

# A bare epoch-ms run still matches the *guarded* phone regex, so it is a value
# that WOULD be corrupted without key protection -- making the protection tests
# load-bearing rather than incidentally passing on the regex fix.
EPOCH = "1740060600000"
# An email is unambiguous PII (email regex, unaffected by the phone-regex fix).
EMAIL = "id@example.com"
# A UUID / ISO timestamp is no longer matched by the guarded phone regex.
UUID_ID = "550e8400-e29b-41d4-a716-446655440000"
ISO_TS = "2026-02-20T14:30:00Z"


class TestProtectionIsLoadBearing:
    """Values that WOULD be redacted survive under a protected key."""

    def test_epoch_redacted_when_unprotected(self):
        result = scrub({"not_an_identifier": EPOCH}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["not_an_identifier"]

    def test_email_redacted_when_unprotected(self):
        result = scrub({"not_an_identifier": EMAIL}, RULES, DEFAULT_ALLOWLIST)
        assert result["not_an_identifier"] == "[REDACTED:PII]"

    def test_epoch_survives_under_protected_key(self):
        result = scrub({"sub_session_id": EPOCH}, RULES, DEFAULT_ALLOWLIST)
        assert result["sub_session_id"] == EPOCH

    def test_email_survives_under_protected_key(self):
        # A protected id key is PII-exempt (documented trade-off for non-excluded
        # id keys); the email passes through rather than being masked.
        result = scrub({"sub_session_id": EMAIL}, RULES, DEFAULT_ALLOWLIST)
        assert result["sub_session_id"] == EMAIL


class TestIdentifierProtection:
    """Identifier keys survive redaction at any nesting depth."""

    def test_sub_session_id_survives_nested(self):
        event = {"data": {"sub_session_id": EPOCH, "message": f"call {EMAIL}"}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["sub_session_id"] == EPOCH
        assert result["data"]["message"] == "call [REDACTED:PII]"

    def test_identifier_survives_deeply_nested(self):
        event = {"a": {"b": {"delegation": {"parent_session_id": EPOCH}}}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["a"]["b"]["delegation"]["parent_session_id"] == EPOCH

    def test_various_id_fields_survive_nested(self):
        # Nested under `data` so the bare-key allowlist does not apply and the
        # KEY-based protection is what preserves them. Includes the fields Salil
        # + the maintainer called out (contributor_id, src_id, dst_id, child_id).
        ids = {
            "session_id": EPOCH,
            "parent_id": EPOCH,
            "node_id": f"{UUID_ID}__llm_response__{EPOCH}",
            "orchestrator_run_id": EPOCH,
            "tool_call_id": EPOCH,
            "tool_use_id": EPOCH,
            "request_id": EPOCH,
            "parallel_group_id": EPOCH,
            "root_session_id": EPOCH,
            "contributor_id": EPOCH,
            "src_id": EPOCH,
            "dst_id": EPOCH,
            "child_id": EPOCH,
        }
        result = scrub({"data": ids}, RULES, DEFAULT_ALLOWLIST)
        for key, value in ids.items():
            assert result["data"][key] == value, f"{key} must survive redaction"

    def test_plural_id_list_survives(self):
        event = {"source_session_ids": [EPOCH, "1740060600001"]}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["source_session_ids"] == [EPOCH, "1740060600001"]


class TestDatetimeProtection:
    """Datetime join-key fields survive at any depth -- exact keys only."""

    def test_datetime_keys_survive_nested(self):
        names = [
            "timestamp",
            "ts",
            "created_at",
            "completed_at",
            "started_at",
            "ended_at",
        ]
        event = {"env": {name: EPOCH for name in names}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        for name in names:
            assert result["env"][name] == EPOCH, f"{name} must survive redaction"

    def test_unlisted_datetime_key_is_not_protected(self):
        """Datetime protection is by EXACT key, not a broad ``*_at`` glob.

        ``updated_at`` is deliberately NOT in DATETIME_KEYS, so a corruptible
        value in it is still redacted.
        """
        assert "updated_at" not in DATETIME_KEYS
        result = scrub({"updated_at": EPOCH}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["updated_at"]


class TestPiiBearingIdExcluded:
    """Person-identifying id-shaped keys stay fully scrubbed (maintainer ask)."""

    def test_user_id_email_is_redacted(self):
        result = scrub({"user_id": "alice@contoso.com"}, RULES, DEFAULT_ALLOWLIST)
        assert result["user_id"] == "[REDACTED:PII]"

    def test_excluded_person_id_keys_are_redacted(self):
        for key in ("user_id", "author_id", "account_id", "owner_id", "customer_id"):
            result = scrub({key: "alice@contoso.com"}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:PII]", f"{key} must stay scrubbed"

    def test_join_key_id_still_protected_for_contrast(self):
        event = {"data": {"sub_session_id": EMAIL, "user_id": EMAIL}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["sub_session_id"] == EMAIL  # join key: exempt
        assert result["data"]["user_id"] == "[REDACTED:PII]"  # person id: scrubbed


class TestAllowlistPrecedence:
    """Proposal 2: exact-path allowlist wins before protected-key handling."""

    FAKE_SECRET = "sk-ant-" + "A" * 24

    def test_allowlisted_identifier_returns_byte_identical(self):
        # session_id is allowlisted AND identifier-shaped. It must return
        # byte-identical -- NOT secret-masked by the protected-key branch.
        result = scrub({"session_id": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["session_id"] == self.FAKE_SECRET

    def test_allowlisted_timestamp_returns_byte_identical(self):
        result = scrub({"timestamp": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["timestamp"] == self.FAKE_SECRET


class TestSecretsStillScrubbed:
    """Leak-safety: protected keys are PII-exempt but NOT secret-exempt."""

    FAKE_SECRET = "sk-ant-" + "A" * 24

    def test_secret_in_id_named_field_is_still_redacted(self):
        result = scrub({"credential_id": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["credential_id"] == "[REDACTED:SECRET]"

    def test_secret_in_nested_id_field_is_still_redacted(self):
        event = {"auth": {"token_id": self.FAKE_SECRET}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["auth"]["token_id"] == "[REDACTED:SECRET]"

    def test_epoch_id_survives_but_secret_id_does_not(self):
        event = {"request_id": EPOCH, "session_key_id": self.FAKE_SECRET}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["request_id"] == EPOCH
        assert result["session_key_id"] == "[REDACTED:SECRET]"


class TestNoOverProtection:
    """The guard must not stop redacting genuine secrets/PII."""

    def test_non_identifier_fields_still_redacted(self):
        event = {
            "phone": "+1 (425) 555-0142",
            "email": "alice@example.com",
            "message": "reach me at bob@example.com",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["phone"] == "[REDACTED:PII]"
        assert result["email"] == "[REDACTED:PII]"
        assert "[REDACTED:PII]" in result["message"]

    def test_bare_id_key_is_not_pattern_matched(self):
        # A bare "id" key does not match *_id and stays subject to scrub.
        result = scrub({"id": "alice@example.com"}, RULES, DEFAULT_ALLOWLIST)
        assert result["id"] == "[REDACTED:PII]"


class TestPhoneRegexPrecision:
    """Proposal 3: guarded phone regex -- corruption shapes intact, phones caught."""

    def test_identifier_and_timestamp_shapes_are_not_corrupted(self):
        intact = [
            "Session 0000000000000000-608b9a3ba1a64704 failed at 2026-08-10T14:27:33Z",
            "2026-08-10T19:59:33.123456+00:00",
            "commit a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "0000000000000000-d82b608b9a3ba1a64704_self",
            UUID_ID,
            ISO_TS,
        ]
        for text in intact:
            assert mask_text(text) == text, f"must be left intact: {text!r}"

    def test_real_phone_numbers_still_redacted(self):
        phones = [
            "call me at +1 (425) 555-0142",
            "425-555-0142",
            "+44 20 7946 0958",
            "phone: 4255550142",
        ]
        for text in phones:
            assert "[REDACTED:PII]" in mask_text(text), f"must redact phone: {text!r}"


class TestRedactorExtensions:
    """Redactor config extends -- never replaces -- the protected class."""

    def test_extra_datetime_keys_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_datetime_keys=frozenset({"polled_at"}))
        )
        result = redactor.scrub({"polled_at": EPOCH, "sub_session_id": EPOCH})
        assert result["polled_at"] == EPOCH  # protected by extension
        assert result["sub_session_id"] == EPOCH  # protected by default

    def test_extra_identifier_patterns_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_identifier_key_patterns=("correlation*",))
        )
        result = redactor.scrub({"correlation_ref": EPOCH})
        assert result["correlation_ref"] == EPOCH

    def test_defaults_still_apply_with_empty_config(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"sub_session_id": EPOCH, "message": EMAIL})
        assert result["sub_session_id"] == EPOCH
        assert result["message"] == "[REDACTED:PII]"

    def test_user_id_still_excluded_under_redactor(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"user_id": "alice@contoso.com"})
        assert result["user_id"] == "[REDACTED:PII]"


def test_constants_are_exported():
    assert "*_id" in IDENTIFIER_KEY_PATTERNS
    assert "timestamp" in DATETIME_KEYS
