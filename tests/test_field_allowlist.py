"""Regression tests for issue #247: cost_usd and model false-positive PII redaction.

The phone regex \\+?\\d[\\d\\s().-]{7,}\\d in PII_PATTERNS matches decimal cost
strings like "16.57469425", replacing them with [REDACTED:PII].  The same phone
regex matches model names with date suffixes like "claude-sonnet-4-20250514".

Both fields are structured metadata that must never be redacted.  The fix adds
them to DEFAULT_ALLOWLIST so scrub() returns them untouched.
"""

from redaction import DEFAULT_ALLOWLIST, scrub


RULES = ["secrets", "pii-basic"]


class TestCostUsdAllowlist:
    """Verify usage.cost_usd survives redaction."""

    def test_cost_usd_survives_pii_redaction(self):
        """A cost_usd value at path usage.cost_usd must not be redacted.

        The phone regex matches decimal cost strings like "16.57469425"
        because the digits-and-dots pattern satisfies the character class.
        Every provider emits cost_usd under usage, making this a systematic
        false positive that causes 3.4x to 53x cost underreporting.
        """
        event = {
            "usage": {
                "cost_usd": "16.57469425",
                "input_tokens": 100,
                "output_tokens": 50,
            },
            "status": "ok",
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        assert result["usage"]["cost_usd"] == "16.57469425", (
            f"cost_usd must survive redaction, got: {result['usage']['cost_usd']!r}"
        )

    def test_cost_usd_value_triggers_without_allowlist(self):
        """Confirm the cost value actually triggers the phone regex when not protected.

        This is the regression guard: if someone changes the regex later,
        this test documents that "16.57469425" does match the phone pattern.
        """
        event = {"not_allowlisted": "16.57469425"}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        assert "[REDACTED:PII]" in result["not_allowlisted"], (
            "Cost-like value must trigger phone regex when not allowlisted "
            f"(proves the bug is real), got: {result['not_allowlisted']!r}"
        )


class TestModelAllowlist:
    """Verify model name survives redaction."""

    def test_model_name_survives_pii_redaction(self):
        """A model name at bare path 'model' must not be redacted.

        The phone regex matches model names with date suffixes like
        "claude-sonnet-4-20250514" because the digit-and-dash run
        "4-20250514" satisfies the \\d[\\d\\s().-]{7,}\\d character class.
        Every provider emits model as a top-level key, making this a
        systematic false positive that corrupts model attribution in logs.
        """
        event = {
            "model": "claude-sonnet-4-20250514",
            "status": "ok",
            "usage": {"input_tokens": 100},
        }
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        assert result["model"] == "claude-sonnet-4-20250514", (
            f"model must survive redaction, got: {result['model']!r}"
        )

    def test_model_name_no_longer_false_positives_without_allowlist(self):
        """After issue #386 / I6, the guarded phone regex no longer matches
        model-name-shaped strings like "claude-sonnet-4-20250514".

        Pre-#386 the unguarded phone regex matched the "4-20250514" digit/hyphen
        run (which is why #247 added ``model`` to the allowlist). The
        lookbehind/lookahead guards now require the match to be delimited by a
        non-identifier boundary, so the date suffix embedded in a longer token is
        left intact even when the field is NOT allowlisted. The allowlist entry
        remains as defense-in-depth (see the test above).
        """
        event = {"not_allowlisted": "claude-sonnet-4-20250514"}
        result = scrub(event, RULES, DEFAULT_ALLOWLIST)

        assert result["not_allowlisted"] == "claude-sonnet-4-20250514", (
            "Guarded phone regex must NOT corrupt a model-name-shaped token, "
            f"got: {result['not_allowlisted']!r}"
        )
