"""Independent public-synthetic regressions for strict sink copies."""

import hashlib
import json
import logging
import re

import pytest

from redaction import (
    IDENTIFIER_KEYS,
    LogRedactingFormatter,
    RedactionConfig,
    Redactor,
    mask_text,
    scrub,
    scrub_for_log,
    secret_assignment_pattern,
)

SECRET = "[REDACTED:SECRET]"
PII = "[REDACTED:PII]"
FABRICATED = "fabricated_" + "public_profile_fixture"
EMAIL = "profile.fixture@example.invalid"
VENDOR = "ghp_" + "PublicProfileFixtureOnly"
IDENTIFIERS = sorted(IDENTIFIER_KEYS | {"custom_join"})
CONFIG = RedactionConfig(extra_identifier_keys=frozenset({"custom_join"}))


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


@pytest.mark.parametrize("key", IDENTIFIERS)
@pytest.mark.parametrize("kind", ["dict", "list", "tuple", "nested-list"])
@pytest.mark.parametrize("nested", [False, True])
def test_identifier_containers_are_scrubbed_and_aliases_detached(key, kind, nested):
    raw = {"password": FABRICATED, "email": EMAIL, "vendor": VENDOR}
    masked = {"password": SECRET, "email": PII, "vendor": SECRET}
    if kind in ("list", "tuple"):
        raw = [raw] if kind == "list" else (raw,)
        masked = [masked]
    elif kind == "nested-list":
        raw, masked = [[raw]], [[masked]]
    source = {key: raw, "alias": raw}
    expected = {key: masked, "alias": masked}
    if nested:
        source, expected = {"result": source}, {"result": expected}
    before = fingerprint(source)
    result = scrub_for_log(source, config=CONFIG)
    assert fingerprint(result) == fingerprint(expected)
    assert fingerprint(source) == before
    container = result["result"] if nested else result
    assert container[key] is not raw
    assert container[key] is not container["alias"]
    serialized = json.dumps(result)
    assert all(value not in serialized for value in (FABRICATED, EMAIL, VENDOR))


@pytest.mark.parametrize("key", IDENTIFIERS)
@pytest.mark.parametrize(
    "value", [VENDOR, EMAIL, "1740060600000", "2026-10-28", 123, 2.5, None, True]
)
def test_scalar_identifier_integrity_remains_intact(key, value):
    source = {"result": {key: value}}
    assert fingerprint(scrub_for_log(source, config=CONFIG)) == fingerprint(source)


@pytest.mark.parametrize("key", IDENTIFIERS)
@pytest.mark.parametrize("kind", ["list", "tuple"])
def test_identifier_container_elements_do_not_inherit_scalar_exemption(key, kind):
    raw = [VENDOR, EMAIL, [VENDOR, {"password": FABRICATED}]]
    source = {key: raw if kind == "list" else tuple(raw)}
    expected = {key: [SECRET, PII, [SECRET, {"password": SECRET}]]}
    assert fingerprint(scrub_for_log(source, config=CONFIG)) == fingerprint(expected)


@pytest.mark.parametrize("marker", [SECRET, PII])
@pytest.mark.parametrize("quote", ["", "'", '"'])
def test_exact_assignment_markers_survive_strict_callback(marker, quote):
    text = f"TOKEN_LIMIT={quote}{marker}{quote}"
    assert fingerprint(scrub_for_log(text)) == fingerprint(text)
    assert fingerprint(scrub_for_log(scrub_for_log(text))) == fingerprint(text)


@pytest.mark.parametrize("marker", [SECRET, PII])
@pytest.mark.parametrize("key", ["password", "TOKEN_LIMIT", "api_key"])
def test_structured_markers_remain_stable_in_sensitive_containers(marker, key):
    source = {key: [marker, {"nested": marker}]}
    assert fingerprint(scrub_for_log(source)) == fingerprint(source)


@pytest.mark.parametrize("marker", [SECRET, PII])
def test_marker_plus_payload_is_not_an_exemption(marker):
    value = marker + FABRICATED
    assert fingerprint(scrub_for_log({"password": value})) == fingerprint(
        {"password": SECRET}
    )
    assert fingerprint(scrub_for_log(f"password={value}")) == fingerprint(
        "password=" + SECRET
    )


TEXTS = [
    "TOKEN_LIMIT=1234567890",
    'TOKEN_LIMIT="1234567890"',
    "ordinary text with no sensitive data",
    f"contact {EMAIL}; vendor {VENDOR}",
    f"password={FABRICATED} TOKEN_LIMIT=1234567890",
    "AUTH_EXPIRES_AT=2026-10-28 AUTH_RETRY_MS=1234567890",
    "\N{SNOWMAN} \N{GREEK SMALL LETTER LAMDA}\r\n"
    "TOKEN_LIMIT=1234567890\r\n"
    f'password = "{FABRICATED}"\r\n'
    f"# contact {EMAIL}\r\n",
    " ".join(
        [
            "TOKEN_LIMIT=1234567890",
            f"key={SECRET}",
            f"key='{PII}'",
            f"password={FABRICATED}",
        ]
    ),
]


@pytest.mark.parametrize("text", TEXTS, ids=[f"text-{i}" for i in range(len(TEXTS))])
def test_default_text_and_formatter_are_stable_after_one_pass(text):
    once = scrub_for_log(text)
    assert fingerprint(scrub_for_log(once)) == fingerprint(once)
    assert fingerprint(scrub_for_log(scrub_for_log(once))) == fingerprint(once)
    formatter = LogRedactingFormatter(include_traceback=False)
    record = logging.LogRecord("synthetic", 20, "fixture.py", 1, "%s", (text,), None)
    formatted = formatter.format(record)
    assert fingerprint(formatted) == fingerprint(once)
    record.args = (formatted,)
    assert fingerprint(formatter.format(record)) == fingerprint(formatted)


@pytest.mark.parametrize(
    "text", TEXTS, ids=[f"envelope-{i}" for i in range(len(TEXTS))]
)
def test_raw_and_sanitized_envelope_paths_have_same_content_and_key(text):
    raw_data = {
        "session_id": "public-fixture-session",
        "timestamp": "2026-10-28 12:34:56",
        "source": text,
        "TOKEN_LIMIT": "1234567890",
        "count": 1234567890,
        "password": PII,
        "result": {"parent": {"password": FABRICATED, "email": EMAIL}},
    }
    before = fingerprint(raw_data)

    def envelope(data):
        return scrub_for_log(
            {"event": "synthetic:event", "workspace": "public-fixture", "data": data}
        )

    direct = envelope(raw_data)
    staged = envelope(scrub_for_log(raw_data))
    assert fingerprint(direct) == fingerprint(staged)
    assert fingerprint(scrub_for_log(direct)) == fingerprint(direct)
    assert fingerprint(raw_data) == before
    assert direct["data"]["TOKEN_LIMIT"] == PII
    assert direct["data"]["count"] == 1234567890
    assert direct["data"]["timestamp"] == raw_data["timestamp"]
    if "\r\n" in text:
        assert direct["data"]["source"].count("\r\n") == text.count("\r\n")
        assert "\N{SNOWMAN}" in direct["data"]["source"]
        assert "\N{GREEK SMALL LETTER LAMDA}" in direct["data"]["source"]


def test_legacy_apis_keep_existing_identifier_and_assignment_behavior():
    source = {"parent": {"password": FABRICATED, "email": EMAIL}}
    assert scrub(source)["parent"] is source["parent"]
    assert Redactor().scrub(source)["parent"] is source["parent"]


@pytest.mark.parametrize(
    ("encoded", "decoded"),
    [
        (r"\\", "\\"),
        (r"\"", '"'),
        (r"\'", "'"),
        (r"\a\b\f\n\r\t\v", "\a\b\f\n\r\t\v"),
        (r"\x09\u000A\U0000000d", "\t\n\r"),
        (r"\u2603\U0001F642", "\N{SNOWMAN}\N{SLIGHTLY SMILING FACE}"),
        (r"\uD83D\uDE42", "\N{SLIGHTLY SMILING FACE}"),
        (r"\ud83d\ude42", "\N{SLIGHTLY SMILING FACE}"),
        (r"\\t", r"\t"),
        (r"\x5ct", r"\t"),
        (r"\u005ct", r"\t"),
        (r"\U0000005ct", r"\t"),
    ],
)
def test_serialization_normalizer_consumes_original_escapes_once(encoded, decoded):
    from redaction._log import _normalize_log_escapes_once

    assert _normalize_log_escapes_once(encoded) == decoded


@pytest.mark.parametrize(
    "text",
    [
        r"\q\z\N{SNOWMAN}\8",
        r"\x0\xGG\u123\u12Q4\U00110000\UFFFFFFFF",
        r"\uD800\uDC00x\uD800-\uDC00",
        r"\uDE42\uD83D",
        r"\U0000D800",
        "trailing\\",
    ],
)
def test_serialization_unknown_malformed_and_invalid_escapes_are_preserved(text):
    from redaction._log import _normalize_log_escapes_once

    expected = text.replace(r"\uD800\uDC00", "\U00010000")
    assert _normalize_log_escapes_once(text) == expected
    assert scrub_for_log(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "snowman \N{SNOWMAN} \N{GREEK SMALL LETTER LAMDA}\r\nordinary text",
        "     1\tprint('ordinary')\r\n     2\tpass\r\n",
        "it's ordinary 'unmatched",
        'ordinary "unmatched',
        r"C:\Users\Public\new\tools\file.txt",
        r"\q unknown \N{SNOWMAN}",
        r"\uD800 lone \U00110000 \xGG",
        r"safe\\path",
        " " * 1_048_577,
        r"\q" + " " * 1_048_575,
    ],
)
def test_serialization_safe_text_returns_original_never_decoded(text):
    assert fingerprint(scrub_for_log(text)) == fingerprint(text)


@pytest.mark.parametrize("marker", [SECRET, PII])
def test_serialization_preexisting_markers_are_not_alarms(marker):
    text = json.dumps("\tpassword=" + marker)
    assert scrub_for_log(text) == text
    assert scrub_for_log(scrub_for_log(text)) == text
    assert scrub_for_log(marker) == marker


def test_serialization_pii_only_alarm_and_secret_wins_across_views():
    encoded_email = EMAIL.replace("@", r"\u0040")
    assert scrub_for_log(encoded_email) == PII
    # PII is visible at sweep one; the credential name is visible at sweep two.
    text = encoded_email + r" \\tpassword=" + FABRICATED
    assert scrub_for_log(text) == SECRET
    # Start every detection view from raw input, not a partially masked baseline.
    assert scrub_for_log(r"\tpassword=" + EMAIL) == SECRET


def test_serialization_extra_assignment_rules_and_existing_precedence():
    cfg = RedactionConfig(
        rules=(),
        extra_secret_patterns=(re.compile(re.escape(EMAIL)),),
        extra_secret_assignment_patterns=(secret_assignment_pattern(["personal"]),),
        extra_pii_patterns=(re.compile("private-place"),),
    )
    assert scrub_for_log(r"\tMY_PERSONAL=" + FABRICATED, config=cfg) == SECRET
    # Default PII precedes the extra secret pattern, on normalized views too.
    assert scrub_for_log(EMAIL.replace("@", r"\u0040"), config=cfg) == PII
    assert scrub_for_log(r"\tprivate-place", config=cfg) == PII


def test_serialization_chosen_marker_honors_intentional_custom_transform():
    cfg = RedactionConfig(extra_pii_patterns=(re.compile(re.escape(SECRET)),))
    assert scrub_for_log(r"\tpassword=" + FABRICATED, config=cfg) == PII
    cfg = RedactionConfig(extra_secret_patterns=(re.compile(re.escape(PII)),))
    assert scrub_for_log(EMAIL.replace("@", r"\u0040"), config=cfg) == SECRET


def test_serialization_inner_identifier_strings_gain_no_structural_exemption():
    text = json.dumps({"session_id": "\tpassword=" + FABRICATED})
    assert scrub_for_log({"content": text, "session_id": text}) == {
        "content": SECRET,
        "session_id": text,
    }


def test_serialization_legacy_apis_do_not_gain_escape_normalization():
    text = json.dumps("\tpassword=" + FABRICATED)
    assert mask_text(text) == text
    assert scrub({"content": text}) == {"content": text}
    assert Redactor().mask_text(text) == text
    assert Redactor().scrub({"content": text}) == {"content": text}
    assert mask_text("TOKEN_LIMIT=" + PII) == "TOKEN_LIMIT=" + SECRET
