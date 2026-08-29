"""Tests for SECRET_ASSIGNMENT_PATTERNS: NAME=value credential redaction.

Covers the gap that let a bash command print `NAME=value` API keys straight
to stdout unredacted: SECRET_PATTERNS is prefix-anchored on known vendor
token shapes only, so a non-vendor-prefixed credential (a plain
`ACME_STAGING_API_KEY=...` assignment) passed through untouched even on
events that WERE scrubbed. These patterns close that gap by matching on the
assignment's NAME (segment-anchored, case-insensitive on the word only) and
masking ONLY the value, preserving the name.

All secret-shaped values below are assembled from fragments (never one
contiguous literal in source) so they can't be flagged by source-level
secret scanners / push-protection, while the runtime-assembled value still
matches the pattern exactly the same -- mirrors the existing convention in
tests/test_token_patterns.py.
"""

import re
import time

from redaction import RedactionConfig
from redaction import Redactor
from redaction import mask_text
from redaction import secret_assignment_pattern

FAKE = "Zx9QpL" + "4mNvR2tYw8"  # 16 chars, no vendor prefix
SECRET = "[REDACTED:SECRET]"


class TestMustMatch:
    """MUST MATCH: assert FAKE not in out and SECRET in out."""

    def test_m1_bare_assignment(self):
        out = mask_text(f"ACME_STAGING_API_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m2_export_form(self):
        out = mask_text(f"export ACME_STAGING_API_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m3_double_quoted_value(self):
        out = mask_text(f'ACME_API_KEY="{FAKE}"')
        assert FAKE not in out
        assert SECRET in out
        assert out == f'ACME_API_KEY="{SECRET}"'

    def test_m4_single_quoted_value(self):
        out = mask_text(f"ACME_API_KEY='{FAKE}'")
        assert FAKE not in out
        assert SECRET in out
        assert out == f"ACME_API_KEY='{SECRET}'"

    def test_m5_json_form(self):
        out = mask_text(f'"SOME_API_KEY": "{FAKE}"')
        assert FAKE not in out
        assert SECRET in out
        assert out == f'"SOME_API_KEY": "{SECRET}"'

    def test_m6_yaml_form(self):
        out = mask_text(f"api_key: {FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m7_camel_case_name(self):
        out = mask_text(f"apiKey={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m8_camel_case_second_word(self):
        out = mask_text(f"authToken={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m9_cli_flag_kebab_case(self):
        out = mask_text(f"--api-key={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m10_password(self):
        out = mask_text(f"DB_PASSWORD={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m11_pat_segment(self):
        out = mask_text(f"GITHUB_PAT={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m12_multi_segment_name(self):
        out = mask_text(f"AWS_SECRET_ACCESS_KEY={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m13_http_header_scheme_preserved(self):
        out = mask_text(f"Authorization: Bearer {FAKE}")
        assert FAKE not in out
        assert SECRET in out
        assert out == f"Authorization: Bearer {SECRET}"

    def test_m14_credentials(self):
        out = mask_text(f"MY_SERVICE_CREDENTIALS={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m15_bare_lowercase_name(self):
        out = mask_text(f"passphrase={FAKE}")
        assert FAKE not in out
        assert SECRET in out

    def test_m16_auth_trailing_segment(self):
        out = mask_text(f"CONTEXT_AUTH={FAKE}")
        assert FAKE not in out
        assert SECRET in out


class TestMustNotMatch:
    """MUST NOT MATCH: assert mask_text(x) == x, byte-identical."""

    def test_n1_path_not_pat_segment(self):
        text = "PATH=/usr/local/bin:/usr/bin:/bin"
        assert mask_text(text) == text

    def test_n2_home_no_sensitive_segment(self):
        text = "HOME=/home/someuser"
        assert mask_text(text) == text

    def test_n3_monkey_key_is_substring_not_segment(self):
        text = "MONKEY=abcdefghij"
        assert mask_text(text) == text

    def test_n4_monkey_mixed_case(self):
        text = "Monkey=abcdefghij"
        assert mask_text(text) == text

    def test_n5_keyboard_requires_trailing_delimiter(self):
        text = "KEYBOARD=abcdefghij"
        assert mask_text(text) == text

    def test_n6_author_is_auth_prefix(self):
        text = "AUTHOR=somebodyelse"
        assert mask_text(text) == text

    def test_n7_author_name_full_segment(self):
        text = "AUTHOR_NAME=somebodyelse"
        assert mask_text(text) == text

    def test_n8_max_tokens_plural_absent(self):
        text = "MAX_TOKENS=4096"
        assert mask_text(text) == text

    def test_n9_max_tokens_lowercase_colon(self):
        text = "max_tokens: 128000"
        assert mask_text(text) == text

    def test_n10_prompt_tokens_llm_telemetry(self):
        text = "prompt_tokens: 45231"
        assert mask_text(text) == text

    def test_n11_token_limit_numeric_value_guard(self):
        text = "TOKEN_LIMIT=80000000"
        assert mask_text(text) == text

    def test_n12_dashless_uuid(self):
        text = "id=550e8400e29b41d4a716446655440000"
        assert mask_text(text) == text

    def test_n13_git_sha_under_benign_name(self):
        text = "commit=9f2c1ab4d5e6f7081923a4b5c6d7e8f90a1b2c3d4"
        assert mask_text(text) == text

    def test_n14_credentials_include_under_length_floor(self):
        text = "credentials=include"
        assert mask_text(text) == text

    def test_n15_datetime_shape_guard(self):
        text = "AUTH_EXPIRES_AT=2026-08-19T12:00:00Z"
        assert mask_text(text) == text

    def test_n16_ls_colors_no_sensitive_segment(self):
        text = "LS_COLORS=rs=0:di=01;34:ln=01;36"
        assert mask_text(text) == text

    def test_n17_base64_under_benign_name(self):
        text = "data: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
        assert mask_text(text) == text

    def test_n18_use_auth_short_boolean(self):
        text = "USE_AUTH=true"
        assert mask_text(text) == text

    def test_n19_auth_short_keyword(self):
        text = "AUTH=none"
        assert mask_text(text) == text

    def test_n20_digest_under_benign_name(self):
        text = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert mask_text(text) == text


M_VECTORS = [
    f"ACME_STAGING_API_KEY={FAKE}",
    f"export ACME_STAGING_API_KEY={FAKE}",
    f'ACME_API_KEY="{FAKE}"',
    f"ACME_API_KEY='{FAKE}'",
    f'"SOME_API_KEY": "{FAKE}"',
    f"api_key: {FAKE}",
    f"apiKey={FAKE}",
    f"authToken={FAKE}",
    f"--api-key={FAKE}",
    f"DB_PASSWORD={FAKE}",
    f"GITHUB_PAT={FAKE}",
    f"AWS_SECRET_ACCESS_KEY={FAKE}",
    f"Authorization: Bearer {FAKE}",
    f"MY_SERVICE_CREDENTIALS={FAKE}",
    f"passphrase={FAKE}",
    f"CONTEXT_AUTH={FAKE}",
]


class TestAdditionalRequired:
    def test_t_idem(self):
        """Every M1-M16 must be idempotent."""
        for text in M_VECTORS:
            once = mask_text(text)
            twice = mask_text(once)
            assert twice == once, f"not idempotent: {text!r} -> {once!r} -> {twice!r}"

    def test_t_gate_off(self):
        """New patterns are gated by the `secrets` rule."""
        out = mask_text(f"API_KEY={FAKE}", rules=("pii-basic",))
        assert SECRET not in out

    def test_t_gate_none(self):
        text = f"API_KEY={FAKE}"
        assert mask_text(text, rules=()) == text

    def test_t_ext_closure_path(self):
        """RedactionConfig.extra_secret_assignment_patterns closes the name-gap."""
        redactor = Redactor(
            RedactionConfig(
                extra_secret_assignment_patterns=[
                    secret_assignment_pattern(["personal"]),
                ]
            )
        )
        out = redactor.mask_text("MY_SVC_PERSONAL=" + FAKE)
        assert FAKE not in out
        assert SECRET in out

        # Bare mask_text (no extension) does not mask it -- proves the
        # extension, not some other rule, did the masking above.
        bare = mask_text("MY_SVC_PERSONAL=" + FAKE)
        assert FAKE in bare

    def test_t_name_gap_regression_lock(self):
        """Explicit regression lock on the accepted limitation (\u00a74.4): the
        default vocabulary is name-anchored, so a credential variable whose
        name carries no conventional sensitive word is NOT matched by
        default. If someone later adds an entropy rule, this test fails and
        forces the \u00a73.4 conversation (value-entropy rules are closed off by
        the dashless-UUID / git-SHA tests above)."""
        text = "MY_SERVICE_PERSONAL=" + FAKE
        assert mask_text(text) == text

    def test_t_perf(self):
        """The assignment pattern alone must stay linear -- deliberately using
        `secrets` only, not the default rules, since PII_PATTERNS[0] (the
        email regex) has a pre-existing, out-of-scope quadratic on this exact
        input (see AGENTS.md / design doc \u00a73.5). Testing with default rules
        would make this a test of someone else's bug."""
        text = "AUTHOR_" * 4000 + "X"
        start = time.monotonic()
        mask_text(text, rules=("secrets",))
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, (
            f"assignment pattern took {elapsed * 1000:.1f}ms, expected < 50ms"
        )


class TestAcceptedFalsePositives:
    """\u00a74.4: these ARE masked, deliberately -- a path-shaped-value exclusion
    or a benign-literal denylist was considered and rejected (see design doc).
    Masking-when-in-doubt is the correct direction for a security bundle."""

    def test_ssh_auth_sock(self):
        out = mask_text("SSH_AUTH_SOCK=/tmp/ssh-ABC123/agent.4567")
        assert SECRET in out

    def test_google_application_credentials(self):
        out = mask_text("GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json")
        assert SECRET in out

    def test_auth_mode_disabled(self):
        out = mask_text("AUTH_MODE=disabled")
        assert SECRET in out

    def test_public_key(self):
        out = mask_text("PUBLIC_KEY=ssh-rsa-AAAAB3NzaC1yc2E")
        assert SECRET in out


class TestSecretAssignmentPatternHelper:
    """Direct coverage of the exported `secret_assignment_pattern()` builder."""

    def test_builds_a_compiled_pattern(self):
        pat = secret_assignment_pattern(["widget"])
        assert isinstance(pat, re.Pattern)

    def test_never_applies_global_ignorecase(self):
        """\u00a74.3 rule 2 footgun: case-insensitivity must be scoped to the word
        group only. A global re.IGNORECASE would let `monkey=` start matching
        via the camelCase guard. Guarded by asserting the compiled pattern
        carries no global IGNORECASE flag."""
        pat = secret_assignment_pattern(["widget"])
        assert not (pat.flags & re.IGNORECASE)
