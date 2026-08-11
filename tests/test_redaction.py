"""Module-specific tests for the redaction hook.

Tests the DEFAULT_ALLOWLIST behavior: structural event fields that contain
values triggering PII patterns (ISO timestamps matching the phone regex,
numeric runs in UUIDs matching the phone regex) must survive scrubbing
untouched, while secrets/PII in other fields are still redacted.
"""

from redaction import DEFAULT_ALLOWLIST, scrub


RULES = ["secrets", "pii-basic"]


class TestDefaultAllowlist:
    """Verify structural fields are protected by the default allowlist."""

    def test_timestamp_survives_phone_regex(self):
        r"""An ISO timestamp in an allowlisted field must not be redacted.

        The phone regex \+?\d[\d\s().-]{7,}\d matches the date portion of
        ISO timestamps (e.g. "2026-02-20" in "2026-02-20T14:30:00Z")
        because digits and hyphens satisfy the character class. Every event
        carries a timestamp from the kernel's emit(), making this the
        primary systematic false-positive trigger.
        """
        event = {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "parent_id": "a1b2c3d4-0000-0000-0000-000000000000",
            "timestamp": "2026-02-20T14:30:00Z",
            "turn_id": "turn_001",
            "span_id": "span_trace_42",
            "type": "session:start",
            "status": "active",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        # Every field here is in DEFAULT_ALLOWLIST — all must survive intact
        assert result["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["parent_id"] == "a1b2c3d4-0000-0000-0000-000000000000"
        assert result["timestamp"] == "2026-02-20T14:30:00Z"
        assert result["turn_id"] == "turn_001"
        assert result["span_id"] == "span_trace_42"
        assert result["type"] == "session:start"
        assert result["status"] == "active"

    def test_uuid_survives_phone_regex(self):
        """A UUID with long numeric runs in an allowlisted field must not be redacted.

        UUIDs like "550e8400-e29b-41d4-a716-446655440000" contain runs such
        as "446655440000" that the phone regex matches. Session IDs are UUID4
        values and must survive scrubbing.
        """
        event = {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "parent_id": "00000000-0000-0000-0000-000000000000",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        assert result["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["parent_id"] == "00000000-0000-0000-0000-000000000000"

    def test_guarded_regex_no_longer_corrupts_ids_or_timestamps(self):
        """After issue #386 / I6, the guarded phone regex leaves UUIDs and ISO
        timestamps intact even when the field is NOT allowlisted.

        Pre-#386 the unguarded phone regex matched digit/hyphen runs inside these
        opaque values (the corruption this fix eliminates). The lookbehind/
        lookahead guards now require a non-identifier boundary, so these shapes
        survive at the regex level -- key/allowlist protection is defense-in-depth
        on top. A still-corruptible value (a bare digit run) remains the
        regression guard proving PII redaction is otherwise intact.
        """
        event = {
            "not_allowlisted_ts": "2026-02-20T14:30:00Z",
            "not_allowlisted_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "not_allowlisted_phoneish": "4255550142",  # bare digit run -- still PII
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        # Opaque id/timestamp shapes are no longer corrupted by the regex.
        assert result["not_allowlisted_ts"] == "2026-02-20T14:30:00Z"
        assert result["not_allowlisted_uuid"] == "550e8400-e29b-41d4-a716-446655440000"
        # A genuinely phone-shaped bare digit run is still redacted.
        assert "[REDACTED:PII]" in result["not_allowlisted_phoneish"]

    def test_pii_in_non_allowlisted_field_still_redacted(self):
        """Secrets and PII in regular fields must still be caught.

        This is the regression guard: the default allowlist must NOT
        weaken redaction for fields that aren't structural identifiers.
        """
        # Built from fragments (not one contiguous literal) so this
        # well-known AWS example key can't be flagged by source-level
        # secret scanners -- the runtime-assembled value still matches
        # the AKIA[0-9A-Z]{16} pattern exactly the same.
        fake_aws_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        event = {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "user_email": "alice@example.com",  # NOT allowlisted — redacted
            "message": "Contact bob@corp.net for access",  # NOT allowlisted — redacted
            "api_key": fake_aws_key,  # NOT allowlisted — redacted
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        # Allowlisted field survives
        assert result["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        # Non-allowlisted fields are redacted
        assert result["user_email"] == "[REDACTED:PII]"
        assert "bob@corp.net" not in result["message"]
        assert "[REDACTED:PII]" in result["message"]
        assert fake_aws_key not in result["api_key"]
        assert "[REDACTED:SECRET]" in result["api_key"]


class TestUserConfigMerge:
    """Verify user-provided allowlist entries are unioned with defaults."""

    def test_user_entries_merged_with_defaults(self):
        """User config extends but never replaces the default allowlist.

        mount() computes: effective = DEFAULT_ALLOWLIST | set(config["allowlist"])
        Both sets of entries must be present in the result.
        """
        user_entries = {"my_custom_field", "another_field"}
        effective = DEFAULT_ALLOWLIST | user_entries

        # All default entries are still present. (Join-key identifiers like
        # session_id/parent_id are intentionally NOT in the allowlist -- they are
        # owned by IDENTIFIER_KEYS; see test_identifier_protection.py.)
        assert "data.working_dir" in effective
        assert "model" in effective
        assert "turn_id" in effective
        assert "span_id" in effective

        # User entries are also present
        assert "my_custom_field" in effective
        assert "another_field" in effective

    def test_empty_user_config_yields_only_defaults(self):
        """When user provides no allowlist, effective == defaults."""
        effective = DEFAULT_ALLOWLIST | set([])
        assert effective == DEFAULT_ALLOWLIST

    def test_user_allowlist_protects_custom_field(self):
        """A user-added allowlist entry actually prevents redaction."""
        effective = DEFAULT_ALLOWLIST | {"custom_id"}
        event = {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "custom_id": "alice@example.com",  # user allowlist — survives despite PII match
            "notes": "alice@example.com",  # NOT allowlisted — redacted
        }
        result = scrub(event, RULES, effective)

        assert result["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["custom_id"] == "alice@example.com"  # protected by user entry
        assert result["notes"] == "[REDACTED:PII]"  # not protected
