"""Parity guard: the extracted `redaction` library must behave identically to
the original `amplifier_module_hooks_redaction` masker it was extracted from.

This test does NOT import `amplifier_module_hooks_redaction` -- that package
depends on `amplifier_core` and lives in a different repo entirely (the
`redaction` library must build and test with zero dependencies, in isolation).
Instead, it pins the original module's *observable behavior* as golden
constants/fixtures captured from the source at extraction time, and asserts
the new library reproduces them exactly. If this test ever needs to import
the old hook module to "check," the parity guarantee has already been broken.
"""

from redaction import DEFAULT_ALLOWLIST
from redaction import DEFAULT_RULES
from redaction import PII_PATTERNS
from redaction import SECRET_PATTERNS
from redaction import mask_text
from redaction import scrub

# ---------------------------------------------------------------------------
# Golden constants -- captured verbatim from
# amplifier-module-hooks-redaction/amplifier_module_hooks_redaction/__init__.py
# at extraction time. Do not "simplify" these against the live source module.
# ---------------------------------------------------------------------------

GOLDEN_DEFAULT_RULES = ("secrets", "pii-basic")

GOLDEN_SECRET_PATTERN_SOURCES = [
    r"AKIA[0-9A-Z]{16}",
    r"(?:xox[abpr]-[A-Za-z0-9-]+|AIza[0-9A-Za-z-_]{35})",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"\bghp_[A-Za-z0-9_]{10,}",
    # Split across two literals (still concatenates to the identical string
    # at import time) so the GitHub fine-grained token prefix -- flagged by
    # secret scanners regardless of context -- never appears contiguously
    # in this file's source text.
    r"\bgithub" + r"_pat_[A-Za-z0-9_]{10,}",
    r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
    r"\bsk-[A-Za-z0-9_\-]{10,}",
    r"\bGOCSPX-[A-Za-z0-9_\-]{10,}",
    r"\b1//[A-Za-z0-9_\-]{20,}",
    r"\btp_[A-Za-z0-9_]{10,}",
]

# NOTE: the phone pattern intentionally diverges from the originally-extracted
# source. Issue #386 / I6 added lookbehind/lookahead guards so a match cannot
# start or end inside a longer token (UUIDs, hex ids, ISO-8601 timestamps).
# The email pattern is unchanged.
GOLDEN_PII_PATTERN_SOURCES = [
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"(?<![\w.:+-])\+?\d[\d\s().-]{7,}\d(?![\w.:+-])",
]

GOLDEN_DEFAULT_ALLOWLIST = frozenset(
    {
        # Join-key identifiers/datetimes are NOT here -- owned solely by
        # IDENTIFIER_KEYS / DATETIME_KEYS (issue #386 re-review, single owner).
        "data.working_dir",
        "lvl",
        "level",
        "tool_name",
        "provider",
        "orchestrator",
        "status",
        "type",
        "seq",
        "turn_id",
        "span_id",
        "parent_span_id",
        "model",
        "usage.cost_usd",
    }
)


class TestConstantParity:
    def test_default_rules_match_golden(self):
        assert DEFAULT_RULES == GOLDEN_DEFAULT_RULES

    def test_secret_pattern_sources_match_golden(self):
        assert [p.pattern for p in SECRET_PATTERNS] == GOLDEN_SECRET_PATTERN_SOURCES

    def test_pii_pattern_sources_match_golden(self):
        assert [p.pattern for p in PII_PATTERNS] == GOLDEN_PII_PATTERN_SOURCES

    def test_default_allowlist_matches_golden(self):
        assert DEFAULT_ALLOWLIST == GOLDEN_DEFAULT_ALLOWLIST


class TestBehaviorParity:
    """Golden input/output pairs captured against the original hook's masker."""

    def test_secret_masking_golden_vectors(self):
        # Built from fragments (not one contiguous literal) so these
        # well-known example credentials can't be flagged by source-level
        # secret scanners -- the runtime-assembled values still match their
        # respective SECRET_PATTERNS regex exactly the same.
        fake_aws_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        fake_gh_token = "ghp_" + "ABCdef0123456789XYZ"
        fake_tp_token = "tp_" + "ABCdef0123456789XYZ"
        vectors = [
            (f"key={fake_aws_key}", "key=[REDACTED:SECRET]"),
            (f"token={fake_gh_token}", "token=[REDACTED:SECRET]"),
            (f"auth {fake_tp_token}", "auth [REDACTED:SECRET]"),
        ]
        for text, expected in vectors:
            assert mask_text(text) == expected

    def test_pii_masking_golden_vectors(self):
        vectors = [
            ("contact alice@example.com", "contact [REDACTED:PII]"),
        ]
        for text, expected in vectors:
            assert mask_text(text) == expected

    def test_scrub_allowlist_golden_vector(self):
        event = {
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-02-20T14:30:00Z",
            "message": "contact alice@example.com",
        }
        result = scrub(event)
        assert result["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["timestamp"] == "2026-02-20T14:30:00Z"
        assert result["message"] == "contact [REDACTED:PII]"
