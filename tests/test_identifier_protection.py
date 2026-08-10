"""Regression tests for issue #386 / I6: PII filter corrupts node_ids at ingest.

The downstream Context Intelligence graph composes ``node_id`` from event
fields (``session_id`` + ``timestamp`` + ``tool_call_id``). The PII "phone"
regex ``\\+?\\d[\\d\\s().-]{7,}\\d`` matches digit/hyphen runs inside UUIDs and
ISO timestamps, and ``scrub()`` masks any string whose *exact dotted path* is
not allowlisted. So identifier/lineage fields that are NOT in the flat
allowlist (``sub_session_id`` is the proven gap), or that appear NESTED rather
than at the envelope root, were masked to ``[REDACTED:PII]`` BEFORE node_id
composition -- permanently corrupting graph join keys.

The fix protects the identifier/datetime *class* by KEY semantics at every
nesting depth (``IDENTIFIER_KEY_PATTERNS`` fnmatch globs + exact
``DATETIME_KEYS``), rather than enumerating one exact path at a time.
"""

from redaction import DATETIME_KEYS
from redaction import DEFAULT_ALLOWLIST
from redaction import IDENTIFIER_KEY_PATTERNS
from redaction import RedactionConfig
from redaction import Redactor
from redaction import scrub

RULES = ["secrets", "pii-basic"]

# A UUID whose numeric tail ("446655440000") satisfies the phone regex, and an
# ISO timestamp whose date ("2026-02-20") does too. Both are real join-key
# values that the redactor corrupts when the field is not protected.
UUID_ID = "550e8400-e29b-41d4-a716-446655440000"
ISO_TS = "2026-02-20T14:30:00Z"


class TestBugIsReal:
    """Prove the corrupting patterns actually fire on unprotected fields."""

    def test_uuid_triggers_phone_regex_when_unprotected(self):
        result = scrub({"not_an_identifier": UUID_ID}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["not_an_identifier"], (
            "UUID join key must trigger the phone regex when not protected "
            f"(proves the bug is real), got: {result['not_an_identifier']!r}"
        )

    def test_iso_timestamp_triggers_phone_regex_when_unprotected(self):
        result = scrub({"random_time": ISO_TS}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["random_time"], (
            "ISO timestamp must trigger the phone regex when not protected "
            f"(proves the bug is real), got: {result['random_time']!r}"
        )


class TestIdentifierProtection:
    """Identifier keys survive redaction at any nesting depth."""

    def test_sub_session_id_survives_top_level(self):
        """The proven allowlist gap: sub_session_id at the envelope root."""
        result = scrub({"sub_session_id": UUID_ID}, RULES, DEFAULT_ALLOWLIST)
        assert result["sub_session_id"] == UUID_ID

    def test_sub_session_id_survives_nested(self):
        """The positional-allowlist gap: same id, nested one level down."""
        event = {"data": {"sub_session_id": UUID_ID, "message": "call bob@x.com"}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["sub_session_id"] == UUID_ID
        # ...while a genuine PII field beside it is still masked.
        assert result["data"]["message"] == "call [REDACTED:PII]"

    def test_identifier_survives_deeply_nested(self):
        event = {"a": {"b": {"delegation": {"parent_session_id": UUID_ID}}}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["a"]["b"]["delegation"]["parent_session_id"] == UUID_ID

    def test_various_id_fields_survive(self):
        event = {
            "session_id": UUID_ID,
            "parent_id": UUID_ID,
            "node_id": f"{UUID_ID}__llm_response__1740060600000",
            "orchestrator_run_id": UUID_ID,
            "tool_call_id": "1740060600000",
            "prompt_id": "1740060600000",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        for key, value in event.items():
            assert result[key] == value, f"{key} must survive redaction"

    def test_plural_id_list_survives(self):
        event = {"source_session_ids": [UUID_ID, "1740060600000"]}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["source_session_ids"] == [UUID_ID, "1740060600000"]


class TestDatetimeProtection:
    """Datetime join-key fields survive at any depth -- exact keys only."""

    def test_timestamp_and_ts_survive_nested(self):
        event = {"env": {"timestamp": ISO_TS, "ts": ISO_TS}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["env"]["timestamp"] == ISO_TS
        assert result["env"]["ts"] == ISO_TS

    def test_named_datetime_fields_survive(self):
        # Grounded in real CI events + server node properties that flow into
        # event payloads (session/run/step timestamps).
        names = [
            "started_at",
            "ended_at",
            "response_at",
            "occurred_at",
            "data_occurred_at",
            "resumed_at",
            "completed_at",
            "cancelled_at",
            "loop_completed_at",
            "last_loop_iteration_at",
            "last_ts",
        ]
        event = {"run": {name: ISO_TS for name in names}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        for name in names:
            assert result["run"][name] == ISO_TS, f"{name} must survive redaction"

    def test_unlisted_at_field_is_not_protected(self):
        """Datetime protection is by EXACT key, not a broad ``*_at`` glob.

        A field like ``updated_at`` is deliberately NOT in DATETIME_KEYS, so it
        is redacted like any other field -- this locks the decision to enumerate
        datetime keys rather than wildcard-match every ``*_at``.
        """
        assert "updated_at" not in DATETIME_KEYS
        result = scrub({"updated_at": ISO_TS}, RULES, DEFAULT_ALLOWLIST)
        assert "[REDACTED:PII]" in result["updated_at"]


class TestSecretsStillScrubbed:
    """Leak-safety: protected keys are PII-exempt but NOT secret-exempt.

    A field named like an identifier that actually carries a credential must
    still be masked -- we never relax secret scrubbing (issue #386 caution).
    """

    FAKE_SECRET = "sk-ant-" + "A" * 24  # matches SECRET_PATTERNS (sk-ant-...)

    def test_secret_in_id_named_field_is_still_redacted(self):
        result = scrub({"credential_id": self.FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["credential_id"] == "[REDACTED:SECRET]"

    def test_secret_in_nested_id_field_is_still_redacted(self):
        event = {"auth": {"token_id": self.FAKE_SECRET}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["auth"]["token_id"] == "[REDACTED:SECRET]"

    def test_phone_shaped_id_survives_but_secret_id_does_not(self):
        # The whole point: opaque/phone-shaped ids survive, secrets never do.
        event = {"request_id": UUID_ID, "session_key_id": self.FAKE_SECRET}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["request_id"] == UUID_ID
        assert result["session_key_id"] == "[REDACTED:SECRET]"


class TestNoOverProtection:
    """The guard must not stop redacting genuine secrets/PII."""

    def test_non_identifier_fields_still_redacted(self):
        event = {
            "phone": "+1 (555) 123-4567",
            "email": "alice@example.com",
            "message": "reach me at bob@example.com",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["phone"] == "[REDACTED:PII]"
        assert result["email"] == "[REDACTED:PII]"
        assert "[REDACTED:PII]" in result["message"]

    def test_bare_id_key_is_not_pattern_matched(self):
        """A bare ``id`` key does not match ``*_id`` and stays subject to scrub."""
        # "id" carrying an email must still be masked; only *_id / *_ids match.
        result = scrub({"id": "alice@example.com"}, RULES, DEFAULT_ALLOWLIST)
        assert result["id"] == "[REDACTED:PII]"


class TestRedactorExtensions:
    """Redactor config extends -- never replaces -- the protected class."""

    def test_extra_datetime_keys_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_datetime_keys=frozenset({"created_at"}))
        )
        result = redactor.scrub({"created_at": ISO_TS, "sub_session_id": UUID_ID})
        assert result["created_at"] == ISO_TS  # protected by extension
        assert result["sub_session_id"] == UUID_ID  # protected by default

    def test_extra_identifier_patterns_are_protected(self):
        redactor = Redactor(
            RedactionConfig(extra_identifier_key_patterns=("correlation*",))
        )
        result = redactor.scrub({"correlation_ref": UUID_ID})
        assert result["correlation_ref"] == UUID_ID

    def test_defaults_still_apply_with_empty_config(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"sub_session_id": UUID_ID, "message": "a@b.com"})
        assert result["sub_session_id"] == UUID_ID
        assert result["message"] == "[REDACTED:PII]"


def test_constants_are_exported():
    assert "*_id" in IDENTIFIER_KEY_PATTERNS
    assert "timestamp" in DATETIME_KEYS
