"""
Redaction library: masks secrets/PII in arbitrary text and JSON-like structures.

This is the zero-dependency, stdlib-only core of the redaction bundle. It has
no knowledge of Amplifier, hooks, or events -- it is a plain Python library
that consumer apps can `import redaction` directly (no `amplifier_core`
required), or that the sibling `hook-redaction` module wraps with `mount()`
for use inside an Amplifier session.

Public API:
    mask_text(text, rules) -> str
        Mask secrets/PII inside a single string using the frozen defaults.
    scrub(obj, rules, allowlist, path) -> Any
        Recursively scrub secrets/PII from a JSON-like structure.
    RedactionConfig
        Frozen-default configuration apps can EXTEND (never replace) with
        additional rules/allowlist entries/patterns.
    Redactor
        A configured masker built from a RedactionConfig. Its mask_text/scrub
        methods behave like the free functions above, but apply the extra
        patterns/allowlist entries on top of the frozen defaults.
"""

from __future__ import annotations

import ast
import io
import re
import time
import tokenize
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from dataclasses import field
from itertools import pairwise
from types import MappingProxyType
from typing import Any

# Public API. The redaction primitives (mask_text, scrub) and the pattern/
# allowlist constants are exported so consumer apps can depend on the vetted
# masker directly instead of vendoring a private copy.
__all__ = [
    "SECRET_PATTERNS",
    "SECRET_ASSIGNMENT_PATTERNS",
    "SECRET_NAME_WORDS",
    "secret_assignment_pattern",
    "PII_PATTERNS",
    "DEFAULT_ALLOWLIST",
    "IDENTIFIER_KEYS",
    "DATETIME_KEYS",
    "DEFAULT_RULES",
    "mask_text",
    "scrub",
    "RedactionConfig",
    "Redactor",
]

# Default rule set applied when a caller does not specify one.
DEFAULT_RULES: tuple[str, ...] = ("secrets", "pii-basic")

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(
        r"(?:xox[abpr]-[A-Za-z0-9-]+|AIza[0-9A-Za-z-_]{35})"
    ),  # Slack/Google keys
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    # Provider/app token formats. These are all PREFIX-ANCHORED and structurally
    # distinctive, so they match real credentials in free-form text without
    # touching ordinary content. (Deliberately NO generic high-entropy rules
    # like bare long-hex or long-base64: hooks-redaction runs by default on the
    # live event stream, and those catch-alls would mask git SHAs, sha256/docker
    # digests, dashless UUIDs, and base64 blobs in normal terminal/LLM output.)
    re.compile(r"\bghp_[A-Za-z0-9_]{10,}"),  # GitHub personal access token
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{10,}"),  # GitHub fine-grained PAT
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),  # Anthropic API key (sk-ant-...)
    re.compile(r"\bsk-[A-Za-z0-9_\-]{10,}"),  # OpenAI / generic "sk-" API key
    re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{10,}"),  # Google OAuth client secret
    re.compile(r"\b1//[A-Za-z0-9_\-]{20,}"),  # Google OAuth refresh token
    re.compile(r"\btp_[A-Za-z0-9_]{10,}"),  # Team Pulse token
]
PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    # Phone numbers. The lookbehind/lookahead guards stop a match from starting
    # or ending INSIDE a longer token (issue #386 / I6): without them the digit/
    # hyphen run eats fragments of UUIDs, hex session handles, git SHAs, and
    # ISO-8601 timestamps (e.g. "2026-08-10T19:59:33" -> "[REDACTED:PII]T19:59:
    # [REDACTED:PII]"). The guards require the match to be bounded by a
    # non-identifier delimiter on both sides, so real phone numbers in prose
    # still redact while opaque identifiers/timestamps are left intact.
    re.compile(r"(?<![\w.:+-])\+?\d[\d\s().-]{7,}\d(?![\w.:+-])"),
]

# ---------------------------------------------------------------------------
# Default allowlist -- structural/config fields returned BYTE-IDENTICAL.
#
# WHAT: Envelope/config fields whose exact value must survive verbatim (routing
#       keys, model/cost/status metadata, streaming envelope). Matched on the
#       field's exact dotted path.
#
# NOTE (issue #386 re-review): graph join-key identifiers (session_id,
#       parent_id, parent, ...) and datetime join keys (timestamp, ts, ...) are
#       DELIBERATELY NOT here -- they are owned solely by IDENTIFIER_KEYS /
#       DATETIME_KEYS below. Each field has a SINGLE owner, so it behaves
#       identically at the envelope root and when nested. Listing a join key here
#       too was the inconsistency flagged in review: a secret-shaped id was
#       returned byte-identical at the root but scrubbed when nested.
#
# WHY byte-identical (no PII/secret masking): these are machine-generated
#       structural values whose exact bytes are load-bearing. `data.working_dir`,
#       for example, is the context-intelligence destination-routing match key
#       and a CI-server query key -- a numeric path segment like
#       /data/20260811123456/run would otherwise be clipped by the phone regex,
#       breaking routing.
#
#       These fields are exempt because their bytes must survive, NOT because
#       they are guaranteed PII-free: a home-directory path such as
#       /home/alice.smith/proj legitimately carries a username. Do not add a
#       field here on the assumption that it is clean -- add it only when
#       byte-identical survival is required by a named consumer.
#
# HOW:  merged (union) with user-provided config["allowlist"] at mount() time.
#       Users extend but never replace the defaults.
# ---------------------------------------------------------------------------
DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Session working directory. NOTE: the allowlist is matched on the
        # EXACT dotted path (see scrub()), and this field rides on
        # data.working_dir -- a bare "working_dir" entry would only ever match
        # the envelope root and leave the real field clipped by the phone regex.
        # Destination-routing match key for the context-intelligence hook and a
        # CI-server query key, so it must stay byte-identical.
        "data.working_dir",
        # Event classification
        "lvl",
        "level",
        # Correlation / config metadata
        "tool_name",
        "provider",
        "orchestrator",
        "status",
        # Streaming envelope
        "type",
        "seq",
        "turn_id",
        "span_id",
        "parent_span_id",
        "model",
        "usage.cost_usd",
    }
)

# ---------------------------------------------------------------------------
# Graph join-key protection -- Context Intelligence graph integrity
# (amplifier-support issue #386). Matched on the field KEY at EVERY nesting
# depth (not the exact dotted path), so a join key is protected whether it sits
# at the envelope root or nested inside a delegation/recipe payload.
#
# Two DISTINCT guarantees, each documented for exactly what it does:
#
#   IDENTIFIER_KEYS -> passed through INTACT (byte-identical). NOT PII- or
#       secret-masked, at any depth. These *are* the node_id / lineage join
#       keys; redacting one -- even a secret-shaped one -- recreates the exact
#       corruption this issue exists to prevent (an orphaned, unjoinable node).
#       They are opaque machine identifiers with no reliable "shape" to validate
#       against, so full pass-through is the only integrity-preserving option. A
#       secret literally placed in an identifier field therefore survives; in
#       practice a real id never matches a secret pattern, and integrity of the
#       join key wins by design.
#
#   DATETIME_KEYS  -> SHAPE-GATED (see _protect_datetime). The value passes
#       through only when it is actually datetime-shaped (an epoch number/string
#       or a datetime string); anything else is redacted normally. A datetime
#       field can therefore never become a PII/secret bypass (an email or secret
#       in `started_at` is redacted), while real timestamps -- including the
#       space-separated and epoch forms the guarded phone regex still clips --
#       survive.
#
# Membership is grounded in the CODE, not a corpus count: every key below is
# EMITTED into event `data` before the redaction hook runs AND read by a
# consumer (emitter/reader cited per key). Server-COMPOSED ids (node_id/edge_id)
# and post-redaction enrichment fields are excluded -- redaction never sees them.
# Consumers EXTEND via RedactionConfig.extra_identifier_keys /
# extra_datetime_keys, never replace.
# ---------------------------------------------------------------------------
IDENTIFIER_KEYS: frozenset[str] = frozenset(
    {
        # kernel envelope -- amplifier-core/python/amplifier_core
        "session_id",  # emit session.py:159; read server utils.py:91 (node_id)
        "parent_id",  # emit session.py:160; read server session.py:55 (_parent_of)
        "parent",  # emit _session_init.py:315 (session:fork); read server session.py:55
        # delegate tool -- amplifier-foundation/modules/tool-delegate
        "parent_session_id",  # emit __init__.py:1034; read server delegation.py:170
        "sub_session_id",  # emit __init__.py:1033; read server delegation.py:177
        "tool_call_id",  # emit __init__.py:1037; read server tool_call.py:48
        "parallel_group_id",  # emit __init__.py:1038; read server tool_call.py:81
        # recipes tool -- amplifier-bundle-recipes/modules/tool-recipes
        "step_id",  # emit executor.py:371 (recipe:step); read server recipe_step.py:219
    }
)

# Server/Neo4j-COMPOSED identifiers -- reference only, NEVER in event payloads,
# so the redaction hook never sees them (the server BUILDS node_id via
# make_node_id() and the edge ids). Listed so a future reader does not add them
# to IDENTIFIER_KEYS by mistake.
_SERVER_COMPOSED_IDENTIFIERS: frozenset[str] = frozenset({"node_id", "edge_id"})

# Datetime join keys -- SHAPE-GATED (see _protect_datetime). Only consumer-backed
# keys are included; a key with no reader does not belong here (issue #386
# re-review). `created_at`/`completed_at`/`ended_at` were dropped -- zero server
# payload reads.
DATETIME_KEYS: frozenset[str] = frozenset(
    {
        "timestamp",  # node_id component; read server utils.make_node_id + ~29 handlers
        "started_at",  # read server services.py:314 (Session.started_at)
        # Legacy streaming timestamp. No server payload read; the consumer is
        # the upload path, which maps it onto `timestamp`:
        #   tool-context-intelligence-upload legacy_transform.py:171
        #       data["timestamp"] = legacy_record.get("ts", "")
        #   context_intelligence/reconstruct/events.py:308
        "ts",
    }
)

# Value shapes that qualify as a datetime for DATETIME_KEYS gating: an epoch
# number (optionally fractional) or a datetime string (ISO-8601 / space-
# separated / date-only, with optional time and timezone). fullmatch is required
# below, so an email, a secret, or prose never qualifies.
_EPOCH_SHAPE = re.compile(r"\d{1,19}(?:\.\d+)?")
_DATETIME_STRING_SHAPE = re.compile(
    r"\d{4}-\d{2}-\d{2}"  # calendar date
    r"(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?"  # optional time
    r"(?:Z|[+-]\d{2}:?\d{2})?)?"  # optional timezone
)

# ---------------------------------------------------------------------------
# NAME=value credential assignments.
#
# WHY a separate list from SECRET_PATTERNS: these patterns must mask ONLY the
# VALUE and preserve the NAME (`API_KEY=[REDACTED:SECRET]`, not
# `[REDACTED:SECRET]`). SECRET_PATTERNS are applied with a fixed replacement
# string (`pat.sub("[REDACTED:SECRET]", out)`), which would destroy the name.
# These are applied with the `_mask_assignment` callable instead, so the match
# keeps everything outside the named `redact` group. Python's `re` has no
# variable-width lookbehind and no `\K`, so "match only the value" cannot be
# expressed as a plain pattern -- the callable is the mechanism.
#
# WHY name-anchored and NOT entropy-anchored: the deliberate exclusion of
# generic high-entropy rules documented on SECRET_PATTERNS above still holds.
# `id=550e8400e29b41d4a716446655440000` and `commit=9f2c1ab...` must stay
# intact (there are shipped tests for both). The signal used here is the NAME,
# not the value's randomness.
#
# Vocabulary is grounded in amplifier_core.utils.truncate.SENSITIVE_KEYS
# (api_key, apikey, api-key, secret, password, token, credential, credentials,
# private_key, privatekey, auth, authorization) reduced to the SEGMENT words
# those decompose into, plus the shell-idiomatic passwd/passphrase/pat.
#
# Plurals `tokens`/`keys` are DELIBERATELY ABSENT: `MAX_TOKENS`,
# `prompt_tokens`, `completion_tokens` are load-bearing numeric telemetry in
# this ecosystem, and a plural credential variable is vanishingly rare.
# ---------------------------------------------------------------------------
SECRET_NAME_WORDS: tuple[str, ...] = (
    "authorization",
    "credentials",
    "credential",
    "passphrase",
    "password",
    "apikey",
    "passwd",
    "secrets",
    "secret",
    "creds",
    "token",
    "cred",
    "auth",
    "key",
    "pat",
)

# Minimum value length before an assignment is treated as a credential.
# Excludes `AUTH=none`, `USE_AUTH=true`, `AUTH_MODE=entra`, `credentials=include`
# and similar config keywords. Real API keys are >= 16 characters; 8 is a
# deliberately conservative floor.
_ASSIGNMENT_MIN_VALUE_LEN = 8


def secret_assignment_pattern(words: Sequence[str]) -> re.Pattern[str]:
    """Build a NAME=value pattern for ``words`` (segment-matched, case-insensitive).

    The returned pattern defines a named group ``redact`` covering exactly the
    VALUE. It is intended for ``SECRET_ASSIGNMENT_PATTERNS`` or for
    ``RedactionConfig.extra_secret_assignment_patterns`` -- both apply it with
    the ``_mask_assignment`` callable, which replaces only that group.

    Use this to cover credential variables whose NAME carries no conventional
    sensitive word (``MY_SERVICE_PERSONAL``, ``ACME_SPARK2``). The default
    vocabulary cannot match those by construction -- nothing in the name says
    "credential".

    Example:
        RedactionConfig(
            extra_secret_assignment_patterns=[
                secret_assignment_pattern(["MY_SERVICE_PERSONAL"]),
            ]
        )
    """
    alt = "|".join(sorted(words, key=len, reverse=True))
    n = _ASSIGNMENT_MIN_VALUE_LEN
    # The opening quote is the only unescaped matching quote in the value.
    # Reject it within the last n characters, preserving the raw length floor
    # even when escape pairs consume two characters in a single regex atom.
    quoted_min = "".join(
        rf"(?<!(?<!\\)(?P=q)[^\r\n]{{{length}}})" for length in range(n)
    )
    return re.compile(
        # Left boundary: the name may not start mid-token, so KEY inside
        # MONKEY / KEYBOARD is unreachable. `-` is deliberately NOT excluded
        # so `--api-key=...` is reachable.
        r"(?<![A-Za-z0-9_.])"
        # Leading name segments: `SOME_API_` (delimiter form) or `api` before a
        # camelCase hump (`apiKey`). Repetitions are bounded so worst-case
        # backtracking stays linear on adversarial input.
        r"(?:[A-Za-z0-9]{1,64}[_.\-]|[a-z0-9]{1,64}(?=[A-Z])){0,12}"
        # The sensitive segment. Case-insensitivity is scoped to THIS group
        # only: a global re.IGNORECASE would make the `(?=[A-Z])` camel guard
        # above match lowercase too, and `monkey=...` would start matching.
        rf"(?:(?i:{alt}))"
        # Trailing name segments. A delimiter is REQUIRED, which is what stops
        # `KEYBOARD=` and `AUTHOR=` from matching on `KEY` / `AUTH`.
        r"(?:[_.\-][A-Za-z0-9]{1,64}){0,12}"
        # Optional closing quote of a quoted key: `"SOME_API_KEY": "..."`.
        r"[\"']?"
        r"[ \t]*[:=][ \t]*"
        # Optional HTTP auth scheme word -- preserved, not masked, so
        # `Authorization: Bearer <token>` keeps the scheme.
        r"(?:(?i:Bearer|Basic|Token)[ \t]+)?"
        r"(?P<q>[\"'])?"
        # Only an actual opening quote selects the quoted branch. Opposite
        # quotes, spaces and separators are value content. Backslash pairs
        # cannot expose an escaped-quote tail.
        # Unquoted values stop at whitespace, commas, semicolons or quotes.
        rf"(?P<redact>(?(q)"
        rf"(?:\\[^\r\n]|(?!(?P=q))[^\\\r\n])*(?:\\(?=[\r\n]|\Z))?{quoted_min}"
        rf"|[^\s,;\"'\r\n]{{{n},}}))"
        # Missing closing quotes conservatively mask through this line only,
        # including a dangling backslash; never fall back to an unquoted match.
        r"(?(q)(?:(?P=q)|(?=[\r\n]|\Z)))"
    )


SECRET_ASSIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    secret_assignment_pattern(SECRET_NAME_WORDS)
]

# Values that are purely numeric/separator characters -- `TOKEN_LIMIT=80000000`,
# `AUTH_RETRY_MS=1_500`. Never a credential; frequently real telemetry.
_NUMERIC_ISH = re.compile(r"[\d.,_+-]+")


def _is_credential_shaped(value: str) -> bool:
    """Reject values structurally incapable of being a credential.

    The length floor is enforced by the regex itself. This adds the two shape
    exclusions a length floor cannot express: pure numbers and datetimes
    (`AUTH_EXPIRES_AT=2026-08-19T12:00:00Z`). Reuses ``_is_datetime_shaped``,
    the same predicate DATETIME_KEYS is gated on.
    """
    if _NUMERIC_ISH.fullmatch(value):
        return False
    return not _is_datetime_shaped(value)


def _mask_assignment(match: re.Match[str]) -> str:
    """Replace only the ``redact`` group; return the match untouched otherwise.

    Idempotent: re-running over `NAME=[REDACTED:SECRET]` re-matches the marker
    as the value and substitutes the identical marker.
    """
    whole = match.group(0)
    value = match.group("redact")
    if value is None or not _is_credential_shaped(value):
        return whole
    base = match.start()
    start, end = match.span("redact")
    return whole[: start - base] + "[REDACTED:SECRET]" + whole[end - base :]


_Span = tuple[int, int]
_SOURCE_MAX_CHARS = 65536
_SOURCE_MAX_LINES = 1024
_SOURCE_MAX_STATEMENT = 8192
_SOURCE_MAX_TOKENS = 8192
_SOURCE_MAX_NODES = 8192
_SOURCE_MAX_DEPTH = 48
_SOURCE_BUDGET_SECONDS = 0.025
_SECRET_MARKER = "[REDACTED:SECRET]"


@dataclass(frozen=True)
class _AssignmentPlan:
    """A complete transaction of original-character edits; never regenerated code."""

    masks: tuple[_Span, ...]


@dataclass(frozen=True)
class _SourceToken:
    kind: int
    text: str
    start: int
    end: int


def _merge_assignment_spans(spans: Sequence[_Span]) -> list[_Span]:
    merged: list[_Span] = []
    for start, end in sorted(spans):
        if start >= end:
            continue
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _subtract_assignment_spans(span: _Span, exclusions: Sequence[_Span]) -> list[_Span]:
    start, end = span
    remaining = []
    for left, right in exclusions:
        if right <= start:
            continue
        if left >= end:
            break
        if left > start:
            remaining.append((start, left))
        start = max(start, right)
    if start < end:
        remaining.append((start, end))
    return remaining


def _python_assignment_plan(
    text: str, patterns: Sequence[re.Pattern[str]]
) -> _AssignmentPlan | None:
    """Bounded syntax evidence, not semantic secret detection.

    Global failures escape to the caller's atomic baseline fallback. SyntaxError
    is local to a complete logical statement; unsupported values get no relief.
    All token payloads are raw slices. In particular, never inspect AST values.
    """
    deadline = time.monotonic() + _SOURCE_BUDGET_SECONDS

    def check() -> None:
        if time.monotonic() > deadline:
            raise ValueError("source analysis budget")

    if len(text) > _SOURCE_MAX_CHARS or len(patterns) != 1:
        return None
    rows = text.splitlines(keepends=True)
    if len(rows) > _SOURCE_MAX_LINES:
        return None
    numbered = [re.match(r" *([0-9]+)\t", row) for row in rows]
    if any(numbered):
        if not all(numbered):
            return None
        numbers = [int(match[1]) for match in numbered if match]
        if any(b != a + 1 for a, b in pairwise(numbers)):
            return None
    # Each source character maps to exactly one original character. Number
    # prefixes are gaps, never part of an edit (including multiline payloads).
    source_parts: list[str] = []
    positions: list[int] = []
    line_starts = [0]
    offset = 0
    for row, prefix in zip(rows, numbered):
        skip = prefix.end() if prefix else 0
        part = row[skip:]
        source_parts.append(part)
        positions.extend(range(offset + skip, offset + len(row)))
        line_starts.append(line_starts[-1] + len(part))
        offset += len(row)
    source = "".join(source_parts)

    def absolute(point: tuple[int, int]) -> int:
        row, column = point
        if row > len(rows):
            if column == 0:
                return len(source)
            raise ValueError("source position")
        # tokenize supplies a virtual NEWLINE column for a final row without
        # a line ending. It has no original character to edit.
        return min(line_starts[row - 1] + column, line_starts[row])

    def mapped(span: _Span) -> list[_Span]:
        start, end = span
        if not 0 <= start <= end <= len(positions):
            raise ValueError("source bounds")
        result: list[_Span] = []
        for index in range(start, end):
            original = positions[index]
            if text[original] != source[index]:
                raise ValueError("source round trip")
            if result and result[-1][1] == original:
                result[-1] = (result[-1][0], original + 1)
            else:
                result.append((original, original + 1))
        return result

    tokens: list[_SourceToken] = []
    count = depth = indent = fdepth = 0
    marker_end = 0
    fstart = 0
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        check()
        start, end = absolute(token.start), absolute(token.end)
        if start < marker_end:
            continue
        count += 1
        if count > _SOURCE_MAX_TOKENS:
            return None
        if (
            not fdepth
            and token.type == tokenize.OP
            and source.startswith(_SECRET_MARKER, start)
        ):
            marker_end = start + len(_SECRET_MARKER)
            tokens.append(
                _SourceToken(tokenize.NAME, _SECRET_MARKER, start, marker_end)
            )
            continue
        kind_name = tokenize.tok_name[token.type]
        # Python 3.12+ exposes f-string internals as tokens. Treat a complete
        # lexical f-string as one conservative literal, also on Python 3.11.
        if kind_name == "FSTRING_START":
            if fdepth == 0:
                fstart = start
            fdepth += 1
        if fdepth:
            if kind_name == "FSTRING_END":
                fdepth -= 1
                if not fdepth:
                    tokens.append(
                        _SourceToken(tokenize.STRING, source[fstart:end], fstart, end)
                    )
            continue
        if token.type == tokenize.INDENT:
            indent += 1
        elif token.type == tokenize.DEDENT:
            indent -= 1
        elif token.type == tokenize.OP:
            if token.string in ("(", "[", "{"):
                depth += 1
            elif token.string in (")", "]", "}"):
                depth -= 1
        if max(depth, indent) > _SOURCE_MAX_DEPTH:
            return None
        tokens.append(_SourceToken(token.type, token.string, start, end))
    if fdepth:
        return None
    regions = [
        (token.start, token.end)
        for token in tokens
        if token.kind in (tokenize.STRING, tokenize.COMMENT)
    ]
    for match in re.finditer(r"(?m)^[ \t]*(?:`{3,}|~{3,})", source):
        if not any(a <= match.start() < b for a, b in regions):
            return None
    if not any(t.text in ("=", ":") and t.kind == tokenize.OP for t in tokens):
        return None

    # Exact public markers are inert only in the parser view, never an
    # exemption or a change to the supplied text. Width/UTF-8 mapping is stable.
    parser_source = source
    for match in reversed(list(re.finditer(re.escape(_SECRET_MARKER), source))):
        if not any(a <= match.start() < b for a, b in regions):
            parser_source = (
                parser_source[: match.start()]
                + "R" * len(_SECRET_MARKER)
                + parser_source[match.end() :]
            )

    pattern = patterns[0]
    # Slots are indexed by the *introducing name*, never by containment. This
    # keeps a consumed outer regex match from hiding a nested sensitive slot.
    slots: dict[int, tuple[_Span, int, tuple[_Span, ...]]] = {}
    mandatory: list[_Span] = []
    node_count = 0
    statement_start = 0
    statement_spans: list[_Span] = []
    ignored = {
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.COMMENT,
        tokenize.ENDMARKER,
        tokenize.ENCODING,
    }
    for boundary in tokens:
        if boundary.kind != tokenize.NEWLINE:
            continue
        check()
        begin, finish = statement_start, boundary.end
        statement_start = finish
        significant = [
            t for t in tokens if begin <= t.start < finish and t.kind not in ignored
        ]
        if not significant:
            continue
        begin = significant[0].start  # remove only known outer indentation
        if finish - begin > _SOURCE_MAX_STATEMENT:
            return None
        statement_spans.append((begin, finish))
        statement = parser_source[begin:finish]
        try:
            tree = ast.parse(statement)
        except SyntaxError:
            continue
        check()
        nodes: list[ast.AST] = []
        pending: list[tuple[ast.AST, int]] = [(tree, 0)]
        while pending:
            check()
            node, level = pending.pop()
            node_count += 1
            if node_count > _SOURCE_MAX_NODES or level > _SOURCE_MAX_DEPTH:
                return None
            nodes.append(node)
            pending.extend((child, level + 1) for child in ast.iter_child_nodes(node))
        # AST columns count UTF-8 bytes, tokenizer columns count characters.
        statement_rows = statement.splitlines(keepends=True)
        byte_maps: list[dict[int, int]] = []
        starts = [begin]
        for row in statement_rows:
            byte_map = {0: 0}
            byte_column = 0
            for column, char in enumerate(row, 1):
                byte_column += len(char.encode("utf-8"))
                byte_map[byte_column] = column
            byte_maps.append(byte_map)
            starts.append(starts[-1] + len(row))

        # Freeze each statement's completed tables before defining its helpers.
        # Later statement iterations must not rebind their coordinate evidence.
        def node_span(
            node: ast.AST,
            starts: tuple[int, ...] = tuple(starts),
            byte_maps: tuple[MappingProxyType[int, int], ...] = tuple(
                MappingProxyType(byte_map) for byte_map in byte_maps
            ),
        ) -> _Span:
            line, col = node.lineno, node.col_offset  # type: ignore[attr-defined]
            end_line, end_col = node.end_lineno, node.end_col_offset  # type: ignore[attr-defined]
            return (
                starts[line - 1] + byte_maps[line - 1][col],
                starts[end_line - 1] + byte_maps[end_line - 1][end_col],
            )

        def reference(node: ast.AST) -> bool:
            while isinstance(node, ast.Attribute):
                node = node.value
            return isinstance(node, ast.Name)

        def callable_key_reference(call: ast.Call, keyword: ast.keyword) -> bool:
            """Recognize one AST-owned static role, not a runtime callable."""
            if (
                not isinstance(call.func, ast.Name)
                or call.func.id not in ("sorted", "min", "max")
                or keyword.arg != "key"
                or not any(owned is keyword for owned in call.keywords)
                or not reference(keyword.value)
                or any(isinstance(arg, ast.Starred) for arg in call.args)
            ):
                return False
            names = [kw.arg for kw in call.keywords]
            if None in names or len(set(names)) != len(names):
                return False
            if call.func.id == "sorted":
                return len(call.args) == 1 and set(names) <= {"key", "reverse"}
            return (
                len(call.args) >= 1
                and set(names) <= {"key", "default"}
                and ("default" not in names or len(call.args) == 1)
            )

        def literal_parts(
            node: ast.AST,
            prefixes: list[_Span],
            significant: tuple[_SourceToken, ...] = tuple(significant),
        ) -> list[_Span] | None:
            """Flatten only lexical string construction; never computed values."""
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = literal_parts(node.left, prefixes)
                right = literal_parts(node.right, prefixes)
                return None if left is None or right is None else left + right
            if not isinstance(node, (ast.Constant, ast.JoinedStr)):
                return None
            start, end = node_span(node)
            strings = [
                t
                for t in significant
                if t.kind == tokenize.STRING and start <= t.start and t.end <= end
            ]
            if not strings:
                return None
            parts = []
            for token in strings:
                opening = re.match(r"(?i:[rubf]*)(\"\"\"|'''|\"|')", token.text)
                if opening is None:
                    raise ValueError("literal boundary")
                quote = opening[1]
                if not token.text.endswith(quote):
                    raise ValueError("literal delimiter")
                prefixes.append((token.start, token.start + opening.start(1)))
                parts.append((token.start + opening.end(), token.end - len(quote)))
            return parts

        def obligations(
            root: ast.AST, *, root_data: bool = True
        ) -> tuple[list[_Span], list[_Span]] | None:
            masks: list[_Span] = []
            prefixes: list[_Span] = []
            work = [(root, root_data)]
            while work:
                check()
                node, data = work.pop()
                if isinstance(node, ast.Name):
                    span = node_span(node)
                    if data and span[1] - span[0] >= _ASSIGNMENT_MIN_VALUE_LEN:
                        masks.append(span)
                elif isinstance(node, ast.Attribute):
                    if not reference(node):
                        return None
                elif isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    parts = literal_parts(node, prefixes)
                    if isinstance(node, (ast.BinOp, ast.JoinedStr)) and parts is None:
                        return None
                    if data and parts:
                        payloads = [source[a:b] for a, b in parts]
                        if sum(map(len, payloads)) >= _ASSIGNMENT_MIN_VALUE_LEN and any(
                            _is_credential_shaped(p) for p in payloads
                        ):
                            masks.extend(parts)
                elif isinstance(node, ast.Call):
                    if not reference(node.func) or any(
                        k.arg is None for k in node.keywords
                    ):
                        return None
                    work.append((node.func, False))
                    work.extend((arg, data) for arg in node.args)
                    work.extend(
                        (kw.value, False if callable_key_reference(node, kw) else data)
                        for kw in node.keywords
                    )
                elif isinstance(node, ast.Subscript):
                    work.extend(((node.value, data), (node.slice, False)))
                elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                    work.extend((element, data) for element in node.elts)
                elif isinstance(node, ast.Dict):
                    if any(key is None for key in node.keys):
                        return None
                    work.extend((key, data) for key in node.keys if key is not None)
                    work.extend((value, data) for value in node.values)
                elif isinstance(node, ast.IfExp):
                    work.extend(
                        ((node.test, False), (node.body, data), (node.orelse, data))
                    )
                elif isinstance(node, ast.DictComp):
                    work.extend(((node.key, data), (node.value, data)))
                    for generator in node.generators:
                        if generator.is_async:
                            return None
                        work.extend(
                            ((generator.target, False), (generator.iter, False))
                        )
                        work.extend((test, False) for test in generator.ifs)
                elif not data and isinstance(
                    node, (ast.Compare, ast.BoolOp, ast.UnaryOp, ast.Slice)
                ):
                    work.extend((child, False) for child in ast.iter_child_nodes(node))
                elif not data and isinstance(
                    node, (ast.cmpop, ast.boolop, ast.unaryop)
                ):
                    pass
                else:
                    return None
            return masks, prefixes

        def eligible(root: ast.AST) -> bool:
            if isinstance(root, ast.Call):
                return isinstance(root.func, ast.Attribute) or any(
                    isinstance(child, ast.Call)
                    for argument in [*root.args, *(k.value for k in root.keywords)]
                    for child in ast.walk(argument)
                )
            if isinstance(root, ast.Tuple):
                return len(root.elts) >= 2 and any(
                    isinstance(child, ast.Subscript)
                    or (isinstance(child, ast.Call) and eligible(child))
                    for element in root.elts
                    for child in ast.walk(element)
                )
            return isinstance(root, (ast.Subscript, ast.IfExp, ast.DictComp))

        def add_slot(
            name_node: ast.AST,
            value: ast.AST,
            separator: str,
            significant: tuple[_SourceToken, ...],
            finish: int,
            *,
            callable_key: bool = False,
        ) -> None:
            name_start, name_end = node_span(name_node)
            name = source[name_start:name_end]
            if isinstance(name_node, ast.Constant):
                if len(name) < 2 or name[0] not in "\"'" or name[-1] != name[0]:
                    return
                name_start += 1
                name = name[1:-1]
                if "\\" in name or not name.isascii():
                    return
            elif not isinstance(name_node, (ast.Name, ast.Attribute, ast.keyword)):
                return
            if not pattern.fullmatch(name + "=xxxxxxxx"):
                return
            value_start, value_end = node_span(value)
            separators = [
                t
                for t in significant
                if (
                    name_end <= t.start < value_start
                    and t.kind == tokenize.OP
                    and t.text == separator
                )
            ]
            if not separators:
                return
            sep = separators[-1]
            callable_key = callable_key and reference(value)
            own_obligations = obligations(value, root_data=not callable_key)
            if own_obligations is None:
                return  # atomic containing-slot baseline, not a safe prefix
            own_masks, literal_prefixes = own_obligations
            for start, end in own_masks:
                # Mandatory data protection does not depend on whether trivia
                # before the value permits structural relief or clipping.
                # Never edit line endings or numbered source prefixes.
                for fragment in re.finditer(r"[^\r\n]+", source[start:end]):
                    mandatory.extend(
                        mapped((start + fragment.start(), start + fragment.end()))
                    )
            prefix = source[sep.end : value_start]
            # Parentheses belonging to this value, not its enclosing Call.
            if prefix.strip(" \t\r\n("):
                return
            extent_start = sep.end
            while extent_start < value_start and source[extent_start].isspace():
                extent_start += 1
            extent_end = value_end
            for _ in range(prefix.count("(")):
                while extent_end < finish and source[extent_end].isspace():
                    extent_end += 1
                if source[extent_end : extent_end + 1] != ")":
                    return
                extent_end += 1
            extent = mapped((extent_start, extent_end))
            if not extent:
                return
            relief: list[_Span] = []
            if callable_key or eligible(value):
                for span in _subtract_assignment_spans(
                    (extent_start, extent_end), regions
                ):
                    relief.extend(mapped(span))
                # Only lexically verified prefix letters are syntax. Quoted
                # content still has ordinary masks and mandatory payload masks.
                for span in literal_prefixes:
                    relief.extend(mapped(span))
                relief = _merge_assignment_spans(relief)
            slots[positions[name_start]] = (
                (extent[0][0], extent[-1][1]),
                positions[sep.start],
                tuple(relief),
            )

        for node in nodes:
            check()
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    add_slot(target, node.value, "=", tuple(significant), finish)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                add_slot(node.target, node.value, "=", tuple(significant), finish)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg is not None:
                        # keyword's AST range includes its value. Use a small
                        # located Name node for its exact lexical introducer.
                        name_node = ast.Name(id=keyword.arg)
                        ast.copy_location(name_node, keyword)
                        name_node.end_lineno = keyword.lineno
                        name_node.end_col_offset = keyword.col_offset + len(
                            keyword.arg.encode("utf-8")
                        )
                        add_slot(
                            name_node,
                            keyword.value,
                            "=",
                            tuple(significant),
                            finish,
                            callable_key=callable_key_reference(node, keyword),
                        )
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if key is not None:
                        add_slot(key, value, ":", tuple(significant), finish)
            elif isinstance(node, ast.DictComp):
                add_slot(node.key, node.value, ":", tuple(significant), finish)

    masks = list(mandatory)
    matches = {m.start(): m for m in pattern.finditer(text)}
    for start in slots:
        match = pattern.match(text, start)
        if match:
            matches[start] = match
    for start, match in matches.items():
        check()
        if not _is_credential_shaped(match.group("redact")):
            continue
        span = match.span("redact")
        slot = slots.get(start)
        if slot is not None:
            (left, right), separator, relief = slot
            introducer = re.search(r"[:=]", text[start : span[0]])
            if introducer is None or start + introducer.start() != separator:
                masks.append(span)
                continue
            # Only proven closing punctuation outside this mapped value may
            # be clipped. Uncertain ownership retains the entire baseline.
            if left <= span[0] < right < span[1] and re.fullmatch(
                r"[\])}]+", text[right : span[1]]
            ):
                span = (span[0], right)
            masks.extend(_subtract_assignment_spans(span, relief))
        else:
            masks.append(span)
    merged = _merge_assignment_spans(masks)
    expansion = sum(len(_SECRET_MARKER) - (b - a) for a, b in merged)
    if len(text) + expansion > _SOURCE_MAX_CHARS:
        return None
    for begin, finish in statement_spans:
        left, right = positions[begin], positions[finish - 1] + 1
        expansion = sum(
            len(_SECRET_MARKER) - (b - a) for a, b in merged if left <= a and b <= right
        )
        if finish - begin + expansion > _SOURCE_MAX_STATEMENT:
            return None
    check()
    return _AssignmentPlan(tuple(merged))


def _mask_default_assignments(text: str, patterns: Sequence[re.Pattern[str]]) -> str:
    # This gate must not depend on regex reaching the RHS: short call prefixes
    # can hide long literal arguments. Names still use the frozen pattern.
    candidate = (
        len(text) <= _SOURCE_MAX_CHARS
        and ("=" in text or ":" in text)
        and any(
            pattern.fullmatch(word + "=xxxxxxxx")
            for word in re.findall(r"[A-Za-z_][A-Za-z0-9_.-]*", text)
            for pattern in patterns
        )
    )
    if candidate:
        try:
            plan = _python_assignment_plan(text, patterns)
            if plan is not None:
                out = text
                for start, end in reversed(plan.masks):
                    out = out[:start] + _SECRET_MARKER + out[end:]
                return out
        except Exception:
            # Never log parser exceptions: they may contain supplied secrets.
            pass
    for pattern in patterns:
        text = pattern.sub(_mask_assignment, text)
    return text


# The PII rule name (see DEFAULT_RULES); referenced by Redactor._mask.
_PII_RULE = "pii-basic"


def _is_datetime_shaped(value: Any) -> bool:
    """Return True if ``value`` is an epoch number or a datetime string.

    Booleans are excluded (``bool`` subclasses ``int``). Strings must FULL-match
    an epoch or datetime shape, so arbitrary content (an email, a secret, prose)
    never qualifies -- that is what stops a datetime key from becoming a
    PII/secret bypass while real timestamps survive.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return bool(
            _EPOCH_SHAPE.fullmatch(value) or _DATETIME_STRING_SHAPE.fullmatch(value)
        )
    return False


def _protect_datetime(value, path, scrub_one):  # type: ignore[no-untyped-def]
    """Datetime-key handling: pass a datetime-shaped value through intact; redact
    anything else normally. Lists are handled element-wise so a list of epochs
    survives while a stray non-datetime element is still scrubbed. ``scrub_one``
    (val, path) fully scrubs a non-datetime value.
    """
    if _is_datetime_shaped(value):
        return value
    if isinstance(value, list):
        return [
            item if _is_datetime_shaped(item) else scrub_one(item, f"{path}[{i}]")
            for i, item in enumerate(value)
        ]
    return scrub_one(value, path)


def mask_text(text: str, rules: Sequence[str] = DEFAULT_RULES) -> str:
    """Mask secrets and PII inside a single string.

    This is the public, pure string masker. It applies SECRET_PATTERNS first
    (replacing matches with ``[REDACTED:SECRET]``) and then PII_PATTERNS
    (replacing matches with ``[REDACTED:PII]``), gated by ``rules``.

    Args:
        text: The string to scrub.
        rules: Which rule categories to apply. ``"secrets"`` enables
            SECRET_PATTERNS **and** SECRET_ASSIGNMENT_PATTERNS (the latter
            masks only the VALUE of a ``NAME=value`` credential assignment,
            preserving the NAME); ``"pii-basic"`` enables PII_PATTERNS.
            Defaults to
            both. Unknown rule names are ignored.

    Returns:
        The masked string. Has no allowlist awareness; callers that need
        structural-field protection should use :func:`scrub`.
    """
    out = text
    if "secrets" in rules:
        for pat in SECRET_PATTERNS:
            out = pat.sub("[REDACTED:SECRET]", out)
        out = _mask_default_assignments(out, SECRET_ASSIGNMENT_PATTERNS)
    if "pii-basic" in rules:
        for pat in PII_PATTERNS:
            out = pat.sub("[REDACTED:PII]", out)
    return out


def scrub(
    obj: Any,
    rules: Sequence[str] = DEFAULT_RULES,
    allowlist: AbstractSet[str] = DEFAULT_ALLOWLIST,
    path: str = "",
) -> Any:
    """Recursively scrub secrets/PII from an arbitrary JSON-like structure.

    Strings are masked via :func:`mask_text`; dicts and lists are traversed,
    building a dotted ``path`` (``a.b`` for nested keys, ``a[0]`` for list
    elements). Any subtree whose ``path`` is in ``allowlist`` is returned
    untouched. Non-container, non-string values are returned as-is.

    Args:
        obj: The value to scrub (str, list, dict, or scalar).
        rules: Rule categories to apply (see :func:`mask_text`).
        allowlist: Dotted paths whose subtrees are exempt from redaction.
            Defaults to DEFAULT_ALLOWLIST.
        path: Internal recursion accumulator; callers normally omit it.

    Returns:
        A redacted copy mirroring the input structure.
    """
    if path in allowlist:
        return obj
    if isinstance(obj, str):
        return mask_text(obj, rules)
    if isinstance(obj, list):
        return [scrub(v, rules, allowlist, f"{path}[{i}]") for i, v in enumerate(obj)]
    if isinstance(obj, dict):

        def _scrub_one(val: Any, p: str) -> Any:
            return scrub(val, rules, allowlist, p)

        out: dict[Any, Any] = {}
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else k
            if child_path in allowlist:
                # Exact-path allowlist: byte-identical (structural/config field).
                out[k] = v
            elif isinstance(k, str) and k in IDENTIFIER_KEYS:
                # Graph join-key identifier (issue #386): byte-identical at any
                # depth, never masked -- redacting it would corrupt the graph.
                out[k] = v
            elif isinstance(k, str) and k in DATETIME_KEYS:
                # Datetime join key (issue #386): pass a datetime-shaped value
                # through; redact anything else (no PII/secret bypass).
                out[k] = _protect_datetime(v, child_path, _scrub_one)
            else:
                out[k] = scrub(v, rules, allowlist, child_path)
        return out
    return obj


@dataclass(frozen=True)
class RedactionConfig:
    """Configuration for a :class:`Redactor`.

    Apps extend the frozen defaults by adding rules, allowlist entries, or
    extra patterns -- they never replace ``SECRET_PATTERNS``/``PII_PATTERNS``/
    ``DEFAULT_ALLOWLIST`` outright. ``extra_secret_patterns`` and
    ``extra_pii_patterns`` are applied ON TOP OF the frozen defaults (defaults
    run first, extras run after).

    Attributes:
        rules: Rule categories to apply. Defaults to ``DEFAULT_RULES``.
        allowlist: Dotted paths exempt from redaction. Defaults to
            ``DEFAULT_ALLOWLIST``.
        extra_secret_patterns: Additional compiled patterns matched under the
            ``"secrets"`` rule, applied after ``SECRET_PATTERNS``.
        extra_pii_patterns: Additional compiled patterns matched under the
            ``"pii-basic"`` rule, applied after ``PII_PATTERNS``.
        extra_secret_assignment_patterns: Additional NAME=value patterns matched
            under the ``"secrets"`` rule, applied after
            ``SECRET_ASSIGNMENT_PATTERNS``. Each MUST define a named group
            ``redact`` covering exactly the value -- build them with
            :func:`secret_assignment_pattern`. Only that group is replaced.
    """

    rules: Sequence[str] = DEFAULT_RULES
    allowlist: AbstractSet[str] = DEFAULT_ALLOWLIST
    extra_secret_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
    extra_pii_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
    extra_secret_assignment_patterns: Sequence[re.Pattern] = field(
        default_factory=tuple
    )
    extra_identifier_keys: AbstractSet[str] = field(default_factory=frozenset)
    extra_datetime_keys: AbstractSet[str] = field(default_factory=frozenset)


class Redactor:
    """A configured masker: ``Redactor(RedactionConfig())`` behaves exactly
    like the free functions :func:`mask_text`/:func:`scrub` with default
    arguments; passing a non-default config extends the frozen defaults with
    app-specific rules/allowlist entries/patterns.
    """

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()

    def _mask(self, text: str, rules: Sequence[str]) -> str:
        """Mask ``text`` under an explicit ``rules`` set (default + extra patterns)."""
        out = mask_text(text, rules)
        if "secrets" in rules:
            for pat in self.config.extra_secret_patterns:
                out = pat.sub("[REDACTED:SECRET]", out)
            for pat in self.config.extra_secret_assignment_patterns:
                out = pat.sub(_mask_assignment, out)
        if _PII_RULE in rules:
            for pat in self.config.extra_pii_patterns:
                out = pat.sub("[REDACTED:PII]", out)
        return out

    def mask_text(self, text: str) -> str:
        """Mask secrets and PII in ``text`` per this Redactor's config."""
        return self._mask(text, self.config.rules)

    def scrub(self, obj: Any, path: str = "") -> Any:
        """Recursively scrub ``obj`` per this Redactor's config."""
        if path in self.config.allowlist:
            return obj
        if isinstance(obj, str):
            return self.mask_text(obj)
        if isinstance(obj, list):
            return [self.scrub(v, f"{path}[{i}]") for i, v in enumerate(obj)]
        if isinstance(obj, dict):
            identifier_keys = IDENTIFIER_KEYS | set(self.config.extra_identifier_keys)
            datetime_keys = DATETIME_KEYS | set(self.config.extra_datetime_keys)

            def _scrub_one(val: Any, p: str) -> Any:
                return self.scrub(val, p)

            out: dict[Any, Any] = {}
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                if child_path in self.config.allowlist:
                    # Exact-path allowlist: byte-identical passthrough.
                    out[k] = v
                elif isinstance(k, str) and k in identifier_keys:
                    # Graph join-key identifier (issue #386): byte-identical at
                    # any depth, never masked.
                    out[k] = v
                elif isinstance(k, str) and k in datetime_keys:
                    # Datetime join key (issue #386): datetime-shaped passes;
                    # anything else is redacted (no PII/secret bypass).
                    out[k] = _protect_datetime(v, child_path, _scrub_one)
                else:
                    out[k] = self.scrub(v, child_path)
            return out
        return obj
