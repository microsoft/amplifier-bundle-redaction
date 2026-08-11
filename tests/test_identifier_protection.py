"""Regression tests for issue #386 / I6: PII filter corrupts node_ids at ingest.

The downstream Context Intelligence graph composes ``node_id`` and lineage edges
from a small set of event fields (``session_id`` / ``parent(_session)_id`` /
``sub_session_id`` / ``tool_call_id`` / ``timestamp``). This suite covers:

* **Exact identifier-key protection** (depth-independent): ONLY the enumerated
  join-key identifiers (``IDENTIFIER_KEYS``) and datetime keys (``DATETIME_KEYS``)
  are exempt from PII masking -- at any nesting depth -- while still being
  secret-scrubbed. There is deliberately NO ``*_id`` glob: an id-shaped business
  field that is not a graph join key (``user_id``, ``request_id``,
  ``contact_email_id`` ...) is scrubbed normally.
* **Guarded phone regex**: lookbehind/lookahead stops the phone pattern from
  matching inside UUIDs / hex ids / ISO timestamps in free-form fields.
* **Allowlist precedence**: an exact-path allowlist entry wins first and returns
  the field byte-identical.
* **Fail-loud, not fail-silent**: an unrecognised id field is redacted (a visible,
  addable graph gap) rather than blanket-exempted (a silent PII leak).
"""

from redaction import DATETIME_KEYS
from redaction import DEFAULT_ALLOWLIST
from redaction import IDENTIFIER_KEYS
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

# The full set of protected graph join-key identifiers (evidence-grounded:
# present in event payloads AND consumed as join keys by the CI server).
PROTECTED_IDS = [
    "session_id",
    "parent_id",
    "parent",
    "parent_session_id",
    "sub_session_id",
    "tool_call_id",
    "tool_use_id",
    "parallel_group_id",
    "step_id",
]


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


class TestIdentifierProtection:
    """The enumerated identifier keys survive redaction at any nesting depth."""

    def test_sub_session_id_survives_nested(self):
        event = {"data": {"sub_session_id": EPOCH, "message": f"call {EMAIL}"}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["sub_session_id"] == EPOCH
        assert result["data"]["message"] == "call [REDACTED:PII]"

    def test_identifier_survives_deeply_nested(self):
        event = {"a": {"b": {"delegation": {"parent_session_id": EPOCH}}}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["a"]["b"]["delegation"]["parent_session_id"] == EPOCH

    def test_all_protected_join_keys_survive_nested(self):
        # Nested under `data` so the exact-path allowlist does not apply and the
        # KEY-based protection is what preserves them. Corruptible epoch value.
        ids = {key: EPOCH for key in PROTECTED_IDS}
        result = scrub({"data": ids}, RULES, DEFAULT_ALLOWLIST)
        for key in PROTECTED_IDS:
            assert result["data"][key] == EPOCH, f"{key} must survive redaction"

    def test_tool_call_ids_survive_realistic_shapes(self):
        # The tool-call identifiers as they actually appear in events.
        event = {
            "data": {
                "tool_call_id": "toolu_01A9fe4b7c2d3e4f5a6b7c8d",
                "tool_use_id": "toolu_01A9fe4b7c2d3e4f5a6b7c8d",
            }
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["tool_call_id"] == "toolu_01A9fe4b7c2d3e4f5a6b7c8d"
        assert result["data"]["tool_use_id"] == "toolu_01A9fe4b7c2d3e4f5a6b7c8d"


class TestNonJoinIdFieldsAreScrubbed:
    """The tightening (issue #386 review): id-shaped fields that are NOT graph
    join keys are scrubbed normally -- there is no ``*_id`` glob to exempt them.
    """

    def test_non_join_id_fields_with_pii_are_redacted(self):
        # None of these are graph join keys, so PII in them is still redacted.
        for key in (
            "request_id",
            "contributor_id",
            "root_session_id",
            "order_id",
            "contact_email_id",
            "process_id",
            "call_id",
        ):
            result = scrub({key: EMAIL}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:PII]", f"{key} must be scrubbed"

    def test_non_join_id_fields_with_epoch_are_redacted(self):
        # A corruptible bare-digit value in a non-join id field is still masked.
        result = scrub({"request_id": EPOCH}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["request_id"]

    def test_node_id_is_not_a_protected_event_key(self):
        # node_id is COMPOSED server-side and never appears in event payloads, so
        # it is deliberately NOT in IDENTIFIER_KEYS. If one shows up carrying PII
        # it is scrubbed like any other field.
        assert "node_id" not in IDENTIFIER_KEYS
        result = scrub({"node_id": EMAIL}, RULES, DEFAULT_ALLOWLIST)
        assert result["node_id"] == "[REDACTED:PII]"

    def test_plural_id_list_is_not_protected(self):
        # No "*_ids" glob: a plural id list that is not an enumerated join key is
        # scrubbed element-wise.
        event = {"source_session_ids": [EPOCH, "1740060600001"]}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert all("[REDACTED:PII]" in v for v in result["source_session_ids"])


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


class TestPersonIdKeysStayScrubbed:
    """Person-identifying id-shaped keys are simply absent from IDENTIFIER_KEYS,
    so they scrub normally -- no exclusion blocklist to maintain.
    """

    def test_person_id_keys_are_redacted(self):
        for key in ("user_id", "author_id", "account_id", "owner_id", "customer_id"):
            assert key not in IDENTIFIER_KEYS
            result = scrub({key: "alice@contoso.com"}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:PII]", f"{key} must stay scrubbed"

    def test_join_key_vs_person_id_contrast(self):
        event = {"data": {"sub_session_id": EMAIL, "user_id": EMAIL}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["sub_session_id"] == EMAIL  # join key: PII-exempt
        assert result["data"]["user_id"] == "[REDACTED:PII]"  # person id: scrubbed


class TestAllowlistPrecedence:
    """Exact-path allowlist wins before protected-key handling."""

    FAKE_SECRET = "sk-ant-" + "A" * 24

    def test_allowlisted_identifier_returns_byte_identical(self):
        # session_id is allowlisted AND identifier-named. It must return
        # byte-identical -- NOT secret-masked by the protected-key branch.
        result = scrub({"session_id": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["session_id"] == self.FAKE_SECRET

    def test_allowlisted_timestamp_returns_byte_identical(self):
        result = scrub({"timestamp": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["timestamp"] == self.FAKE_SECRET


class TestSecretsStillScrubbed:
    """Leak-safety: protected keys are PII-exempt but NOT secret-exempt."""

    FAKE_SECRET = "sk-ant-" + "A" * 24

    def test_secret_in_protected_id_field_is_still_redacted(self):
        # A protected join key that (mis-)carries a secret is still SECRET-masked.
        result = scrub({"tool_call_id": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["tool_call_id"] == "[REDACTED:SECRET]"

    def test_secret_in_nested_protected_field_is_still_redacted(self):
        event = {"auth": {"sub_session_id": self.FAKE_SECRET}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["auth"]["sub_session_id"] == "[REDACTED:SECRET]"

    def test_epoch_id_survives_but_secret_id_does_not(self):
        event = {"sub_session_id": EPOCH, "parent_session_id": self.FAKE_SECRET}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["sub_session_id"] == EPOCH
        assert result["parent_session_id"] == "[REDACTED:SECRET]"


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

    def test_bare_id_key_is_not_protected(self):
        # A bare "id" key is not an enumerated join key and stays subject to scrub.
        assert "id" not in IDENTIFIER_KEYS
        result = scrub({"id": "alice@example.com"}, RULES, DEFAULT_ALLOWLIST)
        assert result["id"] == "[REDACTED:PII]"


class TestPhoneRegexPrecision:
    """Guarded phone regex -- corruption shapes intact, real phones caught."""

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
    """Redactor config extends -- never replaces -- the protected set."""

    def test_extra_datetime_keys_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_datetime_keys=frozenset({"polled_at"}))
        )
        result = redactor.scrub({"polled_at": EPOCH, "sub_session_id": EPOCH})
        assert result["polled_at"] == EPOCH  # protected by extension
        assert result["sub_session_id"] == EPOCH  # protected by default

    def test_extra_identifier_keys_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_identifier_keys=frozenset({"correlation_ref"}))
        )
        result = redactor.scrub({"correlation_ref": EPOCH})
        assert result["correlation_ref"] == EPOCH

    def test_defaults_still_apply_with_empty_config(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"sub_session_id": EPOCH, "message": EMAIL})
        assert result["sub_session_id"] == EPOCH
        assert result["message"] == "[REDACTED:PII]"

    def test_person_id_still_scrubbed_under_redactor(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"user_id": "alice@contoso.com"})
        assert result["user_id"] == "[REDACTED:PII]"


def test_constants_are_exported():
    assert "session_id" in IDENTIFIER_KEYS
    assert "tool_call_id" in IDENTIFIER_KEYS
    assert "timestamp" in DATETIME_KEYS
    # The tightening: broad id-shaped fields are NOT blanket-protected.
    assert "node_id" not in IDENTIFIER_KEYS
    assert "user_id" not in IDENTIFIER_KEYS
    assert "request_id" not in IDENTIFIER_KEYS
