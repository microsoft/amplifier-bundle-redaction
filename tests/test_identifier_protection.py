"""Regression tests for issue #386: Context Intelligence graph join-key integrity.

Two distinct, independently-tested guarantees (see redaction/__init__.py):

* **IDENTIFIER_KEYS** -> passed through **intact / byte-identical at any depth**,
  never PII- or secret-masked. These ARE the node_id/lineage join keys; redacting
  one (even a secret-shaped one) recreates the corruption this issue prevents.
  Root and nested behave identically (the inconsistency flagged in re-review).

* **DATETIME_KEYS** -> **shape-gated**: a value passes only when it is actually
  datetime-shaped (epoch or datetime string); anything else (email, secret,
  prose) is redacted. So a datetime field can never become a PII/secret bypass,
  while real timestamps survive.

Membership is grounded in emitters + server readers; join-key identifiers and
datetime keys are the SINGLE owner of their fields (not duplicated in
DEFAULT_ALLOWLIST).
"""

from redaction import DATETIME_KEYS
from redaction import DEFAULT_ALLOWLIST
from redaction import IDENTIFIER_KEYS
from redaction import RedactionConfig
from redaction import Redactor
from redaction import scrub

RULES = ["secrets", "pii-basic"]

# A bare epoch-ms run matches the guarded phone regex, so it is a value that
# WOULD be corrupted without protection -- making the identifier tests load-
# bearing rather than incidentally passing on the regex fix.
EPOCH = "1740060600000"
EMAIL = "id@example.com"
FAKE_SECRET = "sk-ant-" + "A" * 24

# The full protected identifier set (each emitted into event data + read by a
# consumer). tool_use_id is deliberately absent (0 server readers).
IDENTIFIERS = [
    "session_id",
    "parent_id",
    "parent",
    "parent_session_id",
    "sub_session_id",
    "tool_call_id",
    "parallel_group_id",
    "step_id",
]


class TestIdentifiersPassIntact:
    """Identifier join keys survive byte-identical at every depth."""

    def test_corruptible_id_survives_at_root(self):
        for key in IDENTIFIERS:
            result = scrub({key: EPOCH}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == EPOCH, f"{key} must survive at root"

    def test_all_ids_survive_nested(self):
        # Nested under `data` (no exact-path allowlist entry applies) -> the
        # KEY-based identifier protection is what preserves them.
        ids = {key: EPOCH for key in IDENTIFIERS}
        result = scrub({"data": ids}, RULES, DEFAULT_ALLOWLIST)
        for key in IDENTIFIERS:
            assert result["data"][key] == EPOCH, f"{key} must survive nested"

    def test_realistic_id_shapes_survive(self):
        event = {
            "data": {
                "sub_session_id": "0000000000000000-fdc74ec656e5411d_foundation-explorer",
                "tool_call_id": "toolu_01A9fe4b7c2d3e4f5a6b7c8d",
                "parent_session_id": "a90ed519-35a3-4ea4-8f81-5912e2d29634",
            }
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["data"] == event["data"]

    def test_step_id_survives(self):
        # step_id is emitted by the recipes tool (recipe:step); it must survive.
        result = scrub({"data": {"step_id": EPOCH}}, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["step_id"] == EPOCH


class TestIdentifiersAreConsistentRootAndNested:
    """The re-review fix: a join key behaves identically at root and nested,
    including when it (pathologically) holds a secret -- integrity wins, and a
    real id never matches a secret pattern anyway.
    """

    def test_secret_shaped_id_passes_intact_at_root(self):
        result = scrub({"session_id": FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        assert result["session_id"] == FAKE_SECRET

    def test_secret_shaped_id_passes_intact_when_nested(self):
        result = scrub({"data": {"session_id": FAKE_SECRET}}, RULES, DEFAULT_ALLOWLIST)
        assert result["data"]["session_id"] == FAKE_SECRET

    def test_root_and_nested_agree(self):
        root = scrub({"tool_call_id": FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
        nested = scrub({"d": {"tool_call_id": FAKE_SECRET}}, RULES, DEFAULT_ALLOWLIST)
        assert root["tool_call_id"] == nested["d"]["tool_call_id"] == FAKE_SECRET


DATETIME_SHAPED = [
    "2026-02-20T14:30:00Z",
    "2026-08-10T19:59:33.123456+00:00",
    "2026-08-10 19:59:33",  # space-separated -- clipped by phone regex if unprotected
    "2026-08-10",  # date-only
    "1754938773.123",  # epoch float -- clipped by phone regex if unprotected
    EPOCH,  # epoch ms
]


class TestDatetimeShapeGating:
    """Datetime keys pass ONLY datetime-shaped values; everything else redacted."""

    def test_datetime_shaped_values_survive(self):
        for key in ("timestamp", "started_at", "ts"):
            for val in DATETIME_SHAPED:
                result = scrub({key: val}, RULES, DEFAULT_ALLOWLIST)
                assert result[key] == val, f"{key}={val!r} must survive"

    def test_datetime_key_with_email_is_redacted(self):
        # Issue #386 re-review #1: a datetime field must NOT leak an email.
        for key in ("timestamp", "started_at", "ts"):
            result = scrub({key: EMAIL}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:PII]", f"{key} must redact an email"

    def test_datetime_key_with_secret_is_redacted(self):
        for key in ("timestamp", "started_at", "ts"):
            result = scrub({key: FAKE_SECRET}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:SECRET]", f"{key} must redact a secret"

    def test_datetime_shaped_survives_nested(self):
        event = {"env": {"started_at": "2026-08-10 19:59:33", "ts": EPOCH}}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["env"]["started_at"] == "2026-08-10 19:59:33"
        assert result["env"]["ts"] == EPOCH

    def test_dropped_datetime_keys_are_not_protected(self):
        # created_at/completed_at/ended_at had zero consumers -> removed. They
        # are now scrubbed like any other field.
        for key in ("created_at", "completed_at", "ended_at"):
            assert key not in DATETIME_KEYS
            result = scrub({key: EPOCH}, RULES, DEFAULT_ALLOWLIST)
            assert "[REDACTED:PII]" in result[key], f"{key} should be scrubbed now"


class TestSingleOwner:
    """Join keys/datetimes are owned by IDENTIFIER_KEYS/DATETIME_KEYS -- NOT
    duplicated in DEFAULT_ALLOWLIST (that dual ownership was the #2 defect).
    """

    def test_join_keys_not_in_allowlist(self):
        for key in ("session_id", "parent_id", "parent", "timestamp", "ts"):
            assert key not in DEFAULT_ALLOWLIST, f"{key} must not be dual-owned"

    def test_working_dir_is_allowlisted_byte_identical(self):
        # A numeric path segment would be phone-clipped without the allowlist.
        path = "/data/20260811123456/run"
        result = scrub({"working_dir": path}, RULES, DEFAULT_ALLOWLIST)
        assert result["working_dir"] == path


class TestNonJoinIdFieldsAreScrubbed:
    """id-shaped fields that are NOT graph join keys are scrubbed normally --
    there is no `*_id` glob, and tool_use_id (0 readers) was dropped.
    """

    def test_non_join_id_fields_with_pii_are_redacted(self):
        for key in (
            "user_id",
            "request_id",
            "order_id",
            "contact_email_id",
            "root_session_id",
            "process_id",
            "tool_use_id",
        ):
            assert key not in IDENTIFIER_KEYS
            result = scrub({key: EMAIL}, RULES, DEFAULT_ALLOWLIST)
            assert result[key] == "[REDACTED:PII]", f"{key} must be scrubbed"

    def test_node_id_is_not_protected(self):
        # node_id is composed server-side, never in event payloads.
        assert "node_id" not in IDENTIFIER_KEYS
        result = scrub({"node_id": EMAIL}, RULES, DEFAULT_ALLOWLIST)
        assert result["node_id"] == "[REDACTED:PII]"


class TestNoOverProtection:
    """The protection must not stop redacting genuine PII/secrets elsewhere."""

    def test_non_identifier_fields_still_redacted(self):
        event = {
            "phone": "+1 (425) 555-0142",
            "email": "alice@example.com",
            "message": "reach me at bob@example.com",
            "command": f"export KEY={FAKE_SECRET}",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)
        assert result["phone"] == "[REDACTED:PII]"
        assert result["email"] == "[REDACTED:PII]"
        assert "[REDACTED:PII]" in result["message"]
        assert "[REDACTED:SECRET]" in result["command"]

    def test_bare_id_key_is_not_protected(self):
        assert "id" not in IDENTIFIER_KEYS
        result = scrub({"id": "alice@example.com"}, RULES, DEFAULT_ALLOWLIST)
        assert result["id"] == "[REDACTED:PII]"


class TestRedactorExtensions:
    """Redactor config EXTENDS -- never replaces -- the protected sets."""

    def test_extra_identifier_keys_pass_intact(self):
        redactor = Redactor(
            RedactionConfig(extra_identifier_keys=frozenset({"correlation_ref"}))
        )
        result = redactor.scrub({"correlation_ref": FAKE_SECRET})
        assert result["correlation_ref"] == FAKE_SECRET  # intact like a join key

    def test_extra_datetime_keys_are_shape_gated(self):
        redactor = Redactor(
            RedactionConfig(extra_datetime_keys=frozenset({"polled_at"}))
        )
        assert redactor.scrub({"polled_at": EPOCH})["polled_at"] == EPOCH
        assert redactor.scrub({"polled_at": EMAIL})["polled_at"] == "[REDACTED:PII]"

    def test_defaults_still_apply_with_empty_config(self):
        redactor = Redactor(RedactionConfig())
        result = redactor.scrub({"sub_session_id": EPOCH, "message": EMAIL})
        assert result["sub_session_id"] == EPOCH
        assert result["message"] == "[REDACTED:PII]"


def test_constants_are_exported():
    assert IDENTIFIER_KEYS == frozenset(
        {
            "session_id",
            "parent_id",
            "parent",
            "parent_session_id",
            "sub_session_id",
            "tool_call_id",
            "parallel_group_id",
            "step_id",
        }
    )
    assert DATETIME_KEYS == frozenset({"timestamp", "started_at", "ts"})
    # The tightening: id-shaped non-join fields are NOT blanket-protected.
    assert "tool_use_id" not in IDENTIFIER_KEYS
    assert "node_id" not in IDENTIFIER_KEYS
    assert "user_id" not in IDENTIFIER_KEYS
