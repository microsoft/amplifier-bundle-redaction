"""Strict, detached masking for observability copies, never source delivery."""

from __future__ import annotations

import copy
import logging
import math
import re
from typing import Any

from . import (
    DATETIME_KEYS,
    DEFAULT_ALLOWLIST,
    IDENTIFIER_KEYS,
    PII_PATTERNS,
    SECRET_ASSIGNMENT_PATTERNS,
    SECRET_PATTERNS,
    RedactionConfig,
    _is_credential_shaped,
    _mask_assignment,
    _protect_datetime,
)

LOG_REDACTION_API_VERSION = 1
_SECRET = "[REDACTED:SECRET]"
_PII = "[REDACTED:PII]"
_MARKERS = frozenset({_SECRET, _PII})
_FAILURE = "[REDACTED:LOG_FAILURE]"
_LOG_ESCAPE_LIMIT = 1_048_576
_LOG_ESCAPE_SWEEPS = 4
_LOG_ESCAPES = re.compile(
    r"""\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}"""
    r"""|[\\'"abfnrtv]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"""
)
_LOG_SINGLE_ESCAPES = {
    "\\": "\\",
    '"': '"',
    "'": "'",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
}


class LogRedactionError(ValueError):
    """A log snapshot could not be protected; callers must drop it, not retry raw."""


def _snapshot(obj: Any, active: set[int]) -> Any:
    """Accept only JSON primitives and tuples; validate even exempt subtrees."""
    kind = type(obj)
    if obj is None or kind in (str, bool, int):
        return obj
    if kind is float:
        if not math.isfinite(obj):
            raise ValueError
        return obj
    if kind not in (dict, list, tuple) or id(obj) in active:
        raise ValueError
    active.add(id(obj))
    try:
        if kind is dict:
            out = {}
            for key, value in obj.items():
                if type(key) is not str:
                    raise ValueError
                out[key] = _snapshot(value, active)
            return out
        return [_snapshot(value, active) for value in obj]
    finally:
        active.remove(id(obj))


def _mask_log_assignment(match: re.Match[str]) -> str:
    """Keep completed mask categories stable without exempting adjacent data."""
    if match.group("redact") in _MARKERS:
        return match.group(0)
    return _mask_assignment(match)


def _mask_log_plain(text: str, config: RedactionConfig) -> str:
    """Keep legacy pattern precedence, but never grant Python-syntax relief.

    Default rules always run, even when config.rules narrows them. Additional
    (currently unknown) rule names have no effect, as in the legacy masker.
    """
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(_SECRET, text)
    for pattern in SECRET_ASSIGNMENT_PATTERNS:
        text = pattern.sub(_mask_log_assignment, text)
    for pattern in PII_PATTERNS:
        text = pattern.sub(_PII, text)
    for pattern in config.extra_secret_patterns:
        text = pattern.sub(_SECRET, text)
    for pattern in config.extra_secret_assignment_patterns:
        text = pattern.sub(_mask_log_assignment, text)
    for pattern in config.extra_pii_patterns:
        text = pattern.sub(_PII, text)
    return text


def _decode_log_escape(match: re.Match[str]) -> str:
    token = match.group(0)
    if len(token) == 2:
        return _LOG_SINGLE_ESCAPES[token[1]]
    if len(token) == 12:  # Adjacent UTF-16 high/low surrogate escapes.
        high, low = int(token[2:6], 16), int(token[8:12], 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)
    codepoint = int(token[2:], 16)
    if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
        return token
    return chr(codepoint)


def _normalize_log_escapes_once(text: str) -> str:
    """Detection view only: consume original escapes once, never emitted text.

    Unknown/malformed escapes and invalid Unicode scalars remain unchanged.
    This is deliberately not a Python/JSON parser or general string decoder.
    """
    return _LOG_ESCAPES.sub(_decode_log_escape, text)


def _has_log_escapes(text: str) -> bool:
    # Invalid numeric escapes do not change a view and must not cause refusal.
    return any(
        _decode_log_escape(match) != match.group(0)
        for match in _LOG_ESCAPES.finditer(text)
    )


def _mask_log_text(text: str, config: RedactionConfig) -> str:
    """Mask serialized log text conservatively without returning decoded text.

    A changed detection view alarms on any strict-pattern substitution. Mask
    the whole original string, not reconstructed inner JSON/source spans.
    Limits bound added normalization work, not caller-supplied regex execution.
    """
    if type(text) is not str:
        raise ValueError
    if not _has_log_escapes(text):
        return _mask_log_plain(text, config)
    if len(text) > _LOG_ESCAPE_LIMIT:
        raise ValueError("Log escape normalization limit exceeded")
    baseline = _mask_log_plain(text, config)
    view = text  # Never normalize the baseline: partial masks can hide context.
    marker = None
    for _ in range(_LOG_ESCAPE_SWEEPS):
        normalized = _normalize_log_escapes_once(view)
        if normalized == view:
            break
        view = normalized
        masked = _mask_log_plain(view, config)
        if masked != view:
            if _SECRET in masked:
                marker = _SECRET
            elif marker is None:
                marker = _PII
    if _has_log_escapes(view):
        raise ValueError("Log escape normalization limit exceeded")
    return _mask_log_plain(marker, config) if marker is not None else baseline


def _scrub_snapshot(obj: Any, config: RedactionConfig) -> Any:
    allowlist = DEFAULT_ALLOWLIST | set(config.allowlist)
    identifiers = IDENTIFIER_KEYS | set(config.extra_identifier_keys)
    datetimes = DATETIME_KEYS | set(config.extra_datetime_keys)
    assignments = (
        *SECRET_ASSIGNMENT_PATTERNS,
        *config.extra_secret_assignment_patterns,
    )

    def visit(value: Any, path: str = "", sensitive: bool = False) -> Any:
        if path in allowlist and not isinstance(value, (dict, list)):
            return value  # Path exemptions protect scalars, not arbitrary payloads.
        if isinstance(value, str):
            if value in _MARKERS:
                return _mask_log_text(value, config)
            if sensitive and value and _is_credential_shaped(value):
                return _SECRET
            return _mask_log_text(value, config)
        if isinstance(value, list):
            return [
                visit(item, f"{path}[{i}]", sensitive) for i, item in enumerate(value)
            ]
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                child_path = f"{path}.{key}" if path else key
                if (key in identifiers or child_path in allowlist) and not isinstance(
                    item, (dict, list)
                ):
                    out[key] = item
                    continue
                # Reuse the factory's name grammar, not another vocabulary.
                child_sensitive = sensitive or any(
                    pattern.fullmatch(key + "=xxxxxxxx") for pattern in assignments
                )
                if key in datetimes:
                    out[key] = _protect_datetime(
                        item,
                        child_path,
                        lambda val, p: visit(val, p, child_sensitive),
                    )
                else:
                    out[key] = visit(item, child_path, child_sensitive)
            return out
        return value

    return visit(obj)


def scrub_for_log(obj: Any, *, config: RedactionConfig | None = None) -> Any:
    """Return a detached, masked JSON snapshot (tuples normalize to lists).

    Reject cycles, non-string dictionary keys, non-finite floats, subclasses
    and unsupported objects, including inside structural exemptions. Preserve
    schema keys, scalar-only identifier/path allowlist exemptions and
    shape-gated datetimes. Containers at exempt paths/keys are scrubbed.
    Sensitive-name fields additionally mask nonempty, nonnumeric, nondatetime
    strings regardless of length, including strings nested below those fields.
    No source-aware exception is applied. This does not detect unknown secrets.
    Established SECRET/PII markers retain their categories across repeated
    default masking; custom patterns may intentionally transform markers.
    Recognized string escapes are inspected through at most four detection-only
    normalization sweeps, limited to 1,048,576 characters per eligible string.
    A detection alarm replaces the whole string with a marker; inner serialized
    layout is not preserved. Outer structural exemptions remain unchanged.

    Any validation or masking failure raises a static LogRedactionError without
    an input-bearing exception chain. Never fall back to writing the input.
    """
    try:
        return _scrub_snapshot(
            _snapshot(obj, set()), config if config is not None else RedactionConfig()
        )
    except Exception:
        pass
    # Outside the handler: do not retain even a suppressed exception context.
    raise LogRedactionError("Log redaction failed") from None


class LogRedactingFormatter(logging.Formatter):
    """Wrap an inner formatter, then mask its complete output, failing closed.

    The LogRecord is shallow-copied; normal formatting cannot change the
    original message, args, exception, stack or cached exception text. Custom
    inner formatters must not mutate objects reachable through record fields.
    Raw formatted text has no JSON-field allowlist or identifier exemptions.
    """

    def __init__(
        self,
        inner: logging.Formatter | None = None,
        *,
        include_traceback: bool = True,
        config: RedactionConfig | None = None,
    ) -> None:
        super().__init__()
        self.inner = inner if inner is not None else logging.Formatter()
        self.include_traceback = include_traceback
        self.config = config if config is not None else RedactionConfig()

    def format(self, record: logging.LogRecord) -> str:
        try:
            detached = copy.copy(record)
            detached.exc_text = None
            if not self.include_traceback:
                detached.exc_info = None
                detached.stack_info = None
            return _mask_log_text(self.inner.format(detached), self.config)
        except Exception:
            return _FAILURE
