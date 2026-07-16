"""Tests for the provider/app token patterns contributed to SECRET_PATTERNS.

These cover the prefix-anchored secret formats (GitHub PAT, fine-grained PAT,
OpenAI / generic sk-, Anthropic sk-ant-, Google OAuth client secret and refresh
token, Team Pulse token) added so the shared primitive covers tokens that
consumer apps previously vendored. All are part of the ``secrets`` rule.

There are deliberately NO generic high-entropy rules (bare long-hex / base64):
hooks-redaction runs by default on the live event stream, and such catch-alls
would mask ordinary content (git SHAs, sha256/docker digests, dashless UUIDs,
base64 blobs). The regression guard at the bottom locks that in.
"""

from redaction import mask_text

SECRET = "[REDACTED:SECRET]"

# All secret-shaped values below are assembled from fragments (never one
# contiguous literal in source) so they can't be flagged by source-level
# secret scanners / push-protection, while the runtime-assembled value
# still matches the corresponding SECRET_PATTERNS regex exactly the same.
GITHUB_PAT = "ghp_" + "ABCdef0123456789XYZ"
GITHUB_FINE = "github" + "_pat_" + "ABCdef0123456789XYZ"
OPENAI_KEY = "sk-" + "ABCdef0123456789XYZ-_"
ANTHROPIC_KEY = "sk-ant-" + "api03-AbCdEf0123456789_-GhIjKlMnOpQrStUvWxYz0123456789AA"
GEMINI_KEY = "AIza" + "SyAbCdEfGhIjKlMnOpQrStUvWxYz01234_-"  # Google AI Studio / Gemini
GOOGLE_OAUTH_SECRET = "GOCSPX-" + "AbCdEf0123456789_-XyZ"
GOOGLE_REFRESH = "1//" + "0gAbCdEf0123456789_-GhIjKlMnOpQrStUv"
TEAMPULSE = "tp_" + "ABCdef0123456789XYZ"


class TestNewSecretPatterns:
    def test_github_pat(self):
        assert mask_text(f"token={GITHUB_PAT}") == f"token={SECRET}"

    def test_github_fine_grained_pat(self):
        out = mask_text(f"token={GITHUB_FINE}")
        assert GITHUB_FINE not in out
        assert SECRET in out

    def test_openai_key(self):
        out = mask_text(f"key {OPENAI_KEY}")
        assert OPENAI_KEY not in out
        assert SECRET in out

    def test_teampulse_token(self):
        assert mask_text(f"auth {TEAMPULSE}") == f"auth {SECRET}"


class TestProviderApiKeys:
    """LLM-provider API keys: Anthropic, OpenAI, Google (Gemini / AI Studio)."""

    def test_anthropic_key(self):
        out = mask_text(f"ANTHROPIC_API_KEY={ANTHROPIC_KEY}")
        assert ANTHROPIC_KEY not in out
        assert "sk-ant-" not in out
        assert SECRET in out

    def test_openai_key(self):
        assert mask_text(f"key {OPENAI_KEY}") == f"key {SECRET}"

    def test_gemini_ai_studio_key(self):
        out = mask_text(f"GOOGLE_API_KEY={GEMINI_KEY}")
        assert GEMINI_KEY not in out
        assert "AIza" not in out
        assert SECRET in out

    def test_google_oauth_client_secret(self):
        out = mask_text(f"secret {GOOGLE_OAUTH_SECRET}")
        assert GOOGLE_OAUTH_SECRET not in out
        assert "GOCSPX-" not in out
        assert SECRET in out

    def test_google_oauth_refresh_token(self):
        out = mask_text(f"refresh {GOOGLE_REFRESH}")
        assert GOOGLE_REFRESH not in out
        assert SECRET in out

    def test_provider_keys_gated_by_secrets_rule(self):
        text = f"{ANTHROPIC_KEY} {GEMINI_KEY} {GOOGLE_OAUTH_SECRET}"
        assert SECRET not in mask_text(text, rules=("pii-basic",))


class TestNewPatternsGatedBySecretsRule:
    def test_disabled_when_secrets_rule_off(self):
        # With the "secrets" rule off, the new token patterns must not fire.
        # (Some token samples contain long digit runs that the unrelated
        # phone-PII pattern may still touch, so assert on the SECRET marker
        # specifically rather than whole-string equality.)
        text = f"{GITHUB_PAT} {OPENAI_KEY} {TEAMPULSE} {GOOGLE_OAUTH_SECRET}"
        assert SECRET not in mask_text(text, rules=("pii-basic",))

    def test_enabled_when_secrets_rule_on(self):
        text = f"{GITHUB_PAT} {OPENAI_KEY} {TEAMPULSE} {ANTHROPIC_KEY}"
        out = mask_text(text, rules=("secrets",))
        for token in (GITHUB_PAT, OPENAI_KEY, TEAMPULSE, ANTHROPIC_KEY):
            assert token not in out
        assert SECRET in out

    def test_idempotent(self):
        text = f"{GITHUB_PAT} {OPENAI_KEY} {ANTHROPIC_KEY} {GOOGLE_REFRESH}"
        once = mask_text(text)
        assert mask_text(once) == once


class TestDoesNotSecretRedactOrdinaryContent:
    """Regression guard for the dropped high-entropy catch-alls.

    hooks-redaction scrubs the live event stream (terminal, llm:response) by
    default, so the default ``secrets`` rule must NOT mask everyday coding
    output as ``[REDACTED:SECRET]``. We assert specifically on the SECRET
    marker — the pre-existing phone PII pattern (intentionally left untouched)
    may still touch long pure-digit runs, which is out of scope here.
    """

    def test_git_commit_sha_not_secret_redacted(self):
        text = "fix landed in 9f2c1ab4d5e6f7081923a4b5c6d7e8f90a1b2c3d4"
        assert mask_text(text) == text  # fully clean: no SECRET, no PII

    def test_sha256_digest_not_secret_redacted(self):
        text = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert SECRET not in mask_text(text)

    def test_docker_image_digest_not_secret_redacted(self):
        text = "image@sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        assert SECRET not in mask_text(text)

    def test_dashless_uuid_not_secret_redacted(self):
        text = "id=550e8400e29b41d4a716446655440000"
        assert SECRET not in mask_text(text)

    def test_base64_blob_not_secret_redacted(self):
        text = "data: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
        assert SECRET not in mask_text(text)

    def test_plain_words_unchanged(self):
        text = "the quick brown fox jumps over the lazy dog"
        assert mask_text(text) == text
