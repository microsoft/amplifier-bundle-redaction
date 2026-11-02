"""Public synthetic tests for additive log-sink protection; no live captures."""

import copy
import datetime
import hashlib
import json
import logging
import pathlib
import re
import sys
from typing import Any, cast

import pytest

import redaction
from redaction import (
    DATETIME_KEYS,
    IDENTIFIER_KEYS,
    LOG_REDACTION_API_VERSION,
    LogRedactingFormatter,
    LogRedactionError,
    RedactionConfig,
    scrub_for_log,
    secret_assignment_pattern,
)

SECRET = "[REDACTED:SECRET]"
PII = "[REDACTED:PII]"
FAILURE = "[REDACTED:LOG_FAILURE]"
FABRICATED = "fabricated_" + "log_test_payload"
VENDOR = "ghp_" + "synthetic_public_fixture"
EMAIL = "synthetic@example.invalid"


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, allow_nan=False).encode()
    ).hexdigest()


def assert_snapshot(actual, expected):
    # Failures expose hashes, not the synthetic payloads.
    assert digest(actual) == digest(expected)


def test_public_api():
    names = {
        "scrub_for_log",
        "LogRedactionError",
        "LogRedactingFormatter",
        "LOG_REDACTION_API_VERSION",
    }
    assert names <= set(redaction.__all__)
    assert LOG_REDACTION_API_VERSION == 1
    assert issubclass(LogRedactionError, ValueError)


@pytest.mark.parametrize("value", [None, True, False, 0, 7, -8, 2.5, "", "ordinary"])
def test_json_scalars_preserve_type(value):
    result = scrub_for_log(value)
    assert type(result) is type(value)
    assert_snapshot(result, value)


def test_detached_snapshot_normalizes_tuples_and_repeated_containers():
    shared = {"items": [EMAIL]}
    original = {"rows": (shared, shared), "scalar": 12}
    before = digest(original)
    result = scrub_for_log(original)
    assert_snapshot(
        result, {"rows": [{"items": [PII]}, {"items": [PII]}], "scalar": 12}
    )
    assert digest(original) == before
    assert result is not original
    assert result["rows"][0] is not shared
    assert result["rows"][0] is not result["rows"][1]
    result["rows"][0]["items"].append("detached")
    assert len(shared["items"]) == 1


@pytest.mark.parametrize("key", ["status", "session_id", "custom"])
def test_exempt_containers_are_detached(key):
    value = {"nested": [VENDOR, (EMAIL,)]}
    original = {key: value}
    cfg = RedactionConfig(allowlist=frozenset({"custom"}))
    result = scrub_for_log(original, config=cfg)
    expected = {"nested": [SECRET, [PII]]}
    assert_snapshot(result, {key: expected})
    assert result[key] is not value
    assert result[key]["nested"] is not value["nested"]


@pytest.mark.parametrize("kind", ["dict", "list", "tuple"])
def test_alias_container_is_not_a_path_allowlist_exemption(kind):
    shared = {"api_key": FABRICATED, "email": EMAIL}
    if kind == "list":
        shared = [shared]
    elif kind == "tuple":
        shared = (shared,)
    original = {"data": {"working_dir": shared, "other": shared}}
    before = digest(original)
    result = scrub_for_log(original)
    masked = {"api_key": SECRET, "email": PII}
    expected = masked if kind == "dict" else [masked]
    assert_snapshot(result, {"data": {"working_dir": expected, "other": expected}})
    assert digest(original) == before
    assert result["data"]["working_dir"] is not result["data"]["other"]
    assert result["data"]["working_dir"] is not shared


@pytest.mark.parametrize(
    "value", [VENDOR, EMAIL, "/data/20260811123456/project", 12, None, True]
)
def test_path_allowlist_preserves_scalar_values(value):
    original = {"data": {"working_dir": value}, "custom": value}
    cfg = RedactionConfig(allowlist=frozenset({"custom"}))
    assert_snapshot(scrub_for_log(original, config=cfg), original)


def test_root_allowlist_does_not_skip_container_contents():
    original = {"api_key": FABRICATED, "email": EMAIL}
    cfg = RedactionConfig(allowlist=frozenset({""}))
    assert_snapshot(
        scrub_for_log(original, config=cfg), {"api_key": SECRET, "email": PII}
    )


class StringSubclass(str):
    pass


class DictSubclass(dict):
    pass


class Explosive:
    def __repr__(self):
        raise AssertionError("repr must not run")

    def __str__(self):
        raise AssertionError("str must not run")


@pytest.mark.parametrize(
    "value",
    [
        object(),
        Explosive(),
        b"bytes",
        bytearray(b"bytes"),
        {"set"},
        frozenset({"set"}),
        complex(1, 2),
        pathlib.Path("synthetic"),
        datetime.datetime(2026, 1, 1),
        {1: "non-string key"},
        StringSubclass("subclass"),
        DictSubclass(),
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
    ids=[f"unsupported-{i}" for i in range(15)],
)
@pytest.mark.parametrize("path", ["ordinary", "status", "session_id"])
def test_invalid_values_fail_closed_even_in_exempt_fields(value, path):
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log({path: value})
    assert str(caught.value) == "Log redaction failed"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("kind", ["list", "dict", "tuple-through-list"])
@pytest.mark.parametrize("key", ["ordinary", "status", "session_id"])
def test_cycles_fail_closed(kind, key):
    value = []
    if kind == "dict":
        value = {}
        value["loop"] = value
    elif kind == "tuple-through-list":
        value.append((value,))
    else:
        value.append(value)
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log({key: value})
    assert caught.value.__context__ is None


def test_depth_failure_has_no_exception_chain():
    value = None
    for _ in range(sys.getrecursionlimit() + 10):
        value = [value]
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log(value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("rules", [(), ("secrets",), ("pii-basic",), ("unknown",)])
def test_default_rules_cannot_be_narrowed(rules):
    cfg = RedactionConfig(rules=rules, allowlist=frozenset())
    assert_snapshot(scrub_for_log([VENDOR, EMAIL], config=cfg), [SECRET, PII])


@pytest.mark.parametrize(
    "key",
    ["password", "api_key", "apiKey", "API-KEY", "authorization", "service.token"],
)
@pytest.mark.parametrize("value", [FABRICATED, "x", "none", "true"])
def test_sensitive_fields_use_existing_name_grammar_without_length_floor(key, value):
    assert_snapshot(scrub_for_log({key: value}), {key: SECRET})


def test_sensitive_containers_inherit_masking_but_preserve_structural_values():
    original = {
        "password": {
            "parts": ["x", FABRICATED, "", 123, None, True, "2026-01-01", "12345678"],
            "session_id": VENDOR,
        },
        "monkey": FABRICATED,
        "KEYBOARD": FABRICATED,
        "MAX_TOKENS": 12345678,
    }
    expected = copy.deepcopy(original)
    expected["password"]["parts"][:2] = [SECRET, SECRET]
    expected["password"]["parts"][2:] = [
        redaction.mask_text(item) if isinstance(item, str) else item
        for item in original["password"]["parts"][2:]
    ]
    assert_snapshot(scrub_for_log(original), expected)


@pytest.mark.parametrize("key", sorted(IDENTIFIER_KEYS))
def test_identifier_exemptions_at_every_depth(key):
    original = {key: VENDOR, "nested": {key: EMAIL}}
    assert_snapshot(scrub_for_log(original), original)


@pytest.mark.parametrize("key", sorted(DATETIME_KEYS))
def test_datetime_shape_gating_and_tuple_normalization(key):
    values = (
        "2026-01-01 12:34:56",
        "1740060600000",
        1740060600000,
        1740060600.25,
        EMAIL,
        VENDOR,
        False,
    )
    assert_snapshot(
        scrub_for_log({key: values}), {key: [*values[:4], PII, SECRET, False]}
    )


def test_extra_structural_keys_and_default_allowlist_union():
    cfg = RedactionConfig(
        allowlist=frozenset({"custom"}),
        extra_identifier_keys=frozenset({"join"}),
        extra_datetime_keys=frozenset({"when"}),
    )
    original = {
        "status": EMAIL,
        "custom": [EMAIL],
        "nested": {"join": VENDOR, "when": ["1740060600000", EMAIL]},
        "data": {"working_dir": EMAIL},
    }
    expected = copy.deepcopy(original)
    expected["custom"] = [PII]
    expected["nested"]["when"][1] = PII
    result = scrub_for_log(original, config=cfg)
    assert_snapshot(result, expected)
    assert result["custom"] is not original["custom"]


def test_schema_keys_are_retained_and_unknown_secrets_are_not_claimed():
    original = {VENDOR: FABRICATED, EMAIL: FABRICATED, "unknown_name": FABRICATED}
    assert_snapshot(scrub_for_log(original), original)


def test_custom_pattern_extensions_and_precedence():
    cfg = RedactionConfig(
        rules=(),
        extra_secret_patterns=(
            re.compile(r"custom-[A-Z]+"),
            re.compile(re.escape(EMAIL)),
        ),
        extra_pii_patterns=(re.compile(r"private-place"),),
        extra_secret_assignment_patterns=(secret_assignment_pattern(["personal"]),),
    )
    original = {
        "text": f"custom-EXAMPLE {EMAIL} private-place MY_PERSONAL={FABRICATED}",
        "personal": "x",
    }
    assert_snapshot(
        scrub_for_log(original, config=cfg),
        {"text": f"{SECRET} {PII} {PII} MY_PERSONAL={SECRET}", "personal": SECRET},
    )


@pytest.mark.parametrize(
    "text",
    [
        "key=namespace.synthetic_reference",
        "password=namespace.synthetic_reference",
        'message: "api_key=fabricated_assignment_value"',
        "# TOKEN=fabricated_assignment_value",
    ],
)
def test_raw_assignment_callback_has_no_source_analysis(monkeypatch, text):
    def forbidden(*args, **kwargs):
        pytest.fail("source analysis must not run for log copies")

    monkeypatch.setattr(redaction, "_python_assignment_plan", forbidden)
    expected = text
    for pattern in redaction.SECRET_ASSIGNMENT_PATTERNS:
        expected = pattern.sub(redaction._mask_assignment, expected)
    assert expected != text
    assert_snapshot(scrub_for_log(text), expected)


def test_raw_numeric_date_and_benign_assignment_contract():
    text = (
        "TOKEN_LIMIT=12345678 AUTH_EXPIRES_AT=2026-01-01 "
        "MONKEY=fabricated_assignment_value id=abcdef0123456789"
    )
    expected = redaction.mask_text(text)
    assert_snapshot(scrub_for_log(text), expected)


class BrokenPattern:
    def sub(self, *args):
        raise RuntimeError(FABRICATED)


def test_masking_failure_is_static_and_not_fail_open():
    cfg = RedactionConfig(
        extra_secret_patterns=(cast(re.Pattern[str], BrokenPattern()),)
    )
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log({"text": FABRICATED}, config=cfg)
    assert str(caught.value) == "Log redaction failed"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def make_record(args=None, exc=False):
    info = None
    if exc:
        try:
            raise RuntimeError(VENDOR)
        except RuntimeError:
            info = sys.exc_info()
    return logging.LogRecord(
        "synthetic",
        logging.WARNING,
        "fixture.py",
        12,
        "%s",
        (EMAIL,) if args is None else args,
        info,
        sinfo="synthetic stack " + VENDOR,
    )


@pytest.mark.parametrize("include_traceback", [True, False])
def test_formatter_copies_record_and_clears_cache_only_on_copy(include_traceback):
    record = make_record(exc=True)
    record.exc_text = "cached " + FABRICATED
    before = record.__dict__.copy()
    inner = logging.Formatter("custom|%(levelname)s|%(message)s")
    result = LogRedactingFormatter(inner, include_traceback=include_traceback).format(
        record
    )
    assert record.__dict__ == before
    assert record.args is before["args"]
    assert record.exc_info is before["exc_info"]
    assert result.startswith("custom|WARNING|" + PII)
    assert FABRICATED not in result
    assert VENDOR not in result
    assert EMAIL not in result
    assert ("RuntimeError" in result) is include_traceback
    assert ("synthetic stack" in result) is include_traceback
    # A later unwrapped formatter still sees the original args/cache/stack.
    assert EMAIL in inner.format(record)
    assert record.exc_text == before["exc_text"]


def test_formatter_raw_text_has_no_json_field_exemptions():
    record = make_record((f"session_id={VENDOR} status={EMAIL}",))
    cfg = RedactionConfig(allowlist=frozenset({""}), rules=())
    result = LogRedactingFormatter(config=cfg, include_traceback=False).format(record)
    assert VENDOR not in result
    assert EMAIL not in result


def test_formatter_mapping_args_and_extra_fields():
    record = make_record(({"value": EMAIL},))
    record.msg = "%(value)s"
    record.synthetic_extra = VENDOR
    before = record.__dict__.copy()
    inner = logging.Formatter("%(synthetic_extra)s|%(message)s", style="%")
    result = LogRedactingFormatter(inner, include_traceback=False).format(record)
    assert_snapshot(result, SECRET + "|" + PII)
    assert record.__dict__ == before


def test_formatter_custom_brace_style_and_custom_format_method():
    class Custom(logging.Formatter):
        def format(self, record):
            return "prefix|" + super().format(record) + "|custom-EXAMPLE"

    cfg = RedactionConfig(extra_secret_patterns=(re.compile("custom-EXAMPLE"),))
    inner = Custom("{levelname}|{message}", style="{")
    result = LogRedactingFormatter(inner, config=cfg, include_traceback=False).format(
        make_record()
    )
    assert_snapshot(result, "prefix|WARNING|" + PII + "|" + SECRET)


def test_formatter_source_looking_message_uses_strict_callback(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("source analysis must not run")

    monkeypatch.setattr(redaction, "_python_assignment_plan", forbidden)
    result = LogRedactingFormatter(include_traceback=False).format(
        make_record(("key=namespace.synthetic_reference",))
    )
    assert_snapshot(result, "key=" + SECRET)


@pytest.mark.parametrize("failure", ["inner", "scrub", "args", "non-string", "copy"])
def test_formatter_returns_only_fixed_marker_on_any_failure(failure):
    class BrokenFormatter(logging.Formatter):
        def format(self, record):
            record.msg = "changed only on copy"
            raise RuntimeError(FABRICATED)

    class NonStringFormatter(logging.Formatter):
        # Deliberately violate the formatter contract to test the runtime guard.
        def format(self, record: logging.LogRecord) -> Any:
            return object()

    class UncopyableRecord(logging.LogRecord):
        def __copy__(self):
            raise RuntimeError(FABRICATED)

    record = make_record()
    cfg = None
    inner = None
    if failure == "inner":
        inner = BrokenFormatter()
    elif failure == "non-string":
        inner = NonStringFormatter()
    elif failure == "scrub":
        cfg = RedactionConfig(
            extra_secret_patterns=(cast(re.Pattern[str], BrokenPattern()),)
        )
    elif failure == "args":
        record.msg = "%d"
    else:
        record.__class__ = UncopyableRecord
    before = record.__dict__.copy()
    assert LogRedactingFormatter(inner, config=cfg).format(record) == FAILURE
    assert record.__dict__ == before


def test_formatter_with_no_exception_does_not_reuse_cached_exception_text():
    record = make_record()
    record.exc_text = VENDOR
    result = LogRedactingFormatter(include_traceback=False).format(record)
    assert_snapshot(result, PII)
    assert_snapshot(record.exc_text, VENDOR)


@pytest.mark.parametrize(
    "value",
    [
        "AKIA" + "A" * 16,
        "xoxb-" + "synthetic-fixture",
        "AIza" + "A" * 35,
        "eyJ" + "A" * 12 + "." + "B" * 12 + "." + "C" * 12,
        "ghp_" + "synthetic_fixture",
        "github" + "_pat_" + "synthetic_fixture",
        "sk-ant-" + "A" * 24,
        "sk-" + "A" * 12,
        "GOCSPX-" + "A" * 12,
        "1//" + "A" * 24,
        "tp_" + "synthetic_fixture",
    ],
    ids=[f"vendor-shape-{i}" for i in range(11)],
)
def test_all_vendor_shapes_mask_in_both_apis(value):
    assert_snapshot(scrub_for_log(value), SECRET)
    result = LogRedactingFormatter(include_traceback=False).format(
        make_record((value,))
    )
    assert_snapshot(result, SECRET)


@pytest.mark.parametrize("name", redaction.SECRET_NAME_WORDS)
def test_structured_sensitive_names_share_factory_vocabulary(name):
    assert_snapshot(scrub_for_log({name: "x"}), {name: SECRET})


def test_failure_paths_never_log(caplog):
    cfg = RedactionConfig(
        extra_secret_patterns=(cast(re.Pattern[str], BrokenPattern()),)
    )
    with pytest.raises(LogRedactionError):
        scrub_for_log(FABRICATED, config=cfg)
    assert LogRedactingFormatter(config=cfg).format(make_record()) == FAILURE
    assert not caplog.records


def test_extra_assignment_callback_failure_has_no_chain():
    cfg = RedactionConfig(extra_secret_assignment_patterns=(re.compile("fixture"),))
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log("fixture", config=cfg)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def serialized_source(kind, source):
    if kind == "repr-str":
        return repr(source)
    if kind == "repr-dict":
        return repr({"content": source})
    if kind == "json-str":
        return json.dumps(source)
    return json.dumps({"content": source})


@pytest.mark.parametrize("numbered", [False, True])
@pytest.mark.parametrize("separator", ["\t", "\n", "\r\n"])
def test_serialization_plain_source_keeps_strict_baseline(numbered, separator):
    prefix = "     1\t" if numbered else ""
    text = prefix + separator + "password=" + FABRICATED
    expected = prefix + separator + "password=" + SECRET
    assert_snapshot(scrub_for_log(text), expected)


@pytest.mark.parametrize("kind", ["repr-str", "repr-dict", "json-str", "json-dict"])
@pytest.mark.parametrize("numbered", [False, True])
def test_serialization_tool_source_masks_whole_telemetry_string(kind, numbered):
    source = "\tpassword=" + FABRICATED + "\n"
    if numbered:
        source = "     1\t" + source
    text = serialized_source(kind, source)
    # Coarse masking deliberately sacrifices inner serialization/source layout.
    assert_snapshot(scrub_for_log(text), SECRET)
    assert_snapshot(
        LogRedactingFormatter(include_traceback=False).format(make_record((text,))),
        SECRET,
    )


@pytest.mark.parametrize("depth", [1, 2, 3, 4])
@pytest.mark.parametrize("first_repr", [False, True])
def test_serialization_alternating_wrappers_within_four_sweeps(depth, first_repr):
    text = "\tpassword=" + FABRICATED
    for level in range(depth):
        text = repr(text) if (level % 2 == 0) == first_repr else json.dumps(text)
    assert_snapshot(scrub_for_log(text), SECRET)


@pytest.mark.parametrize(
    "text",
    [
        r"\tpassword=\"" + FABRICATED + r"\"",
        r"\"password\":\"" + FABRICATED + r"\"",
        r"\'password\':\'" + FABRICATED + r"\'",
        r"\x09password=" + FABRICATED,
        r"\u0009password=" + FABRICATED,
        r"\U00000009password=" + FABRICATED,
        r"\u0070assword=" + FABRICATED,
    ],
)
def test_serialization_escaped_assignment_keys_values_and_numeric_escapes(text):
    assert_snapshot(scrub_for_log(text), SECRET)


def test_serialization_outer_structure_ids_and_aliases_remain_detached():
    text = json.dumps({"content": "\tpassword=" + FABRICATED})
    shared = {"content": text, "session_id": EMAIL}
    original = {
        "session_id": VENDOR,
        "tool_call_id": "public-call",
        "data": [shared, shared],
    }
    before = digest(original)
    result = scrub_for_log(original)
    assert_snapshot(
        result,
        {
            "session_id": VENDOR,
            "tool_call_id": "public-call",
            "data": [
                {"content": SECRET, "session_id": EMAIL},
                {"content": SECRET, "session_id": EMAIL},
            ],
        },
    )
    assert digest(original) == before
    assert result["data"] is not original["data"]
    assert result["data"][0] is not shared
    assert result["data"][0] is not result["data"][1]


@pytest.mark.parametrize("include_traceback", [False, True])
def test_serialization_formatter_leaves_msg_args_exception_and_cache(include_traceback):
    text = json.dumps("\tpassword=" + FABRICATED)
    record = make_record((text,), exc=True)
    record.msg = "serialized=%s"
    record.exc_text = "cached " + FABRICATED
    before = record.__dict__.copy()
    result = LogRedactingFormatter(include_traceback=include_traceback).format(record)
    assert_snapshot(result, SECRET)
    assert record.__dict__ == before
    assert record.args is before["args"]
    assert record.exc_info is before["exc_info"]


@pytest.mark.parametrize("depth", [5, 6])
@pytest.mark.parametrize("wrapper", [repr, json.dumps])
def test_serialization_over_depth_fails_closed_in_both_apis(depth, wrapper, caplog):
    text = "\tpassword=" + FABRICATED
    for _ in range(depth):
        text = wrapper(text)
    with pytest.raises(LogRedactionError) as caught:
        scrub_for_log(text)
    assert str(caught.value) == "Log redaction failed"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    record = make_record((text,))
    before = record.__dict__.copy()
    assert LogRedactingFormatter(include_traceback=False).format(record) == FAILURE
    assert record.__dict__ == before
    assert not caplog.records


@pytest.mark.parametrize("over", [False, True])
def test_serialization_exact_character_budget_and_overflow(over, caplog):
    size = 1_048_576 + int(over)
    text = r"\t" + " " * (size - 2)
    assert len(text) == size
    record = make_record((text,))
    formatter = LogRedactingFormatter(include_traceback=False)
    if over:
        with pytest.raises(LogRedactionError) as caught:
            scrub_for_log(text)
        assert str(caught.value) == "Log redaction failed"
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert formatter.format(record) == FAILURE
    else:
        assert_snapshot(scrub_for_log(text), text)
        assert_snapshot(formatter.format(record), text)
    assert not caplog.records
