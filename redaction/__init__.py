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

import fnmatch
import re
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from dataclasses import field
from typing import Any

# Public API. The redaction primitives (mask_text, scrub) and the pattern/
# allowlist constants are exported so consumer apps can depend on the vetted
# masker directly instead of vendoring a private copy.
__all__ = [
    "SECRET_PATTERNS",
    "PII_PATTERNS",
    "DEFAULT_ALLOWLIST",
    "IDENTIFIER_KEY_PATTERNS",
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
# Default allowlist -- structural event fields that must never be redacted.
#
# WHAT: These are infrastructure/envelope fields used for session correlation,
#       lineage tracking, event ordering, and trace identification.
#
# WHY:  Two PII regex patterns produce systematic false positives on these
#       structural fields:
#
#       1. Phone regex  \+?\d[\d\s().-]{7,}\d  matches ISO timestamps
#          (e.g. "2026-02-20T14:30:00Z" -> "2026-02-20" triggers the pattern)
#          and numeric runs inside UUIDs (e.g. "446655440000" inside
#          "550e8400-e29b-41d4-a716-446655440000"). Every event carries a
#          timestamp from the kernel's emit(), so without the allowlist every
#          event's timestamp is replaced with [REDACTED:PII].
#
#       2. Email regex  [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
#          can match username fragments when project slugs derived from
#          filesystem paths (e.g. /home/user/my.project) carry dot-separated
#          segments into event fields that happen to resemble local-part@domain.
#
#       Together these cause critical identifiers to display as [REDACTED:PII],
#       breaking event correlation, session lineage trees, and trace
#       verification.
#
# HOW:  These defaults are merged (union) with user-provided
#       config["allowlist"] entries at mount() time. Users extend but never
#       replace the defaults.
# ---------------------------------------------------------------------------
DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Infrastructure envelope -- present on every event via emit().
        # session_id and parent_id are the primary keys for event correlation
        # and session lineage.
        "session_id",
        "parent_id",
        "timestamp",
        # Session lineage -- parent ID in session:fork events
        "parent",
        # Event classification
        "lvl",
        "level",
        # Correlation identifiers -- join related events across the lifecycle
        "tool_name",
        "provider",
        "orchestrator",
        "status",
        # Streaming envelope
        "type",
        "ts",
        "seq",
        "turn_id",
        "span_id",
        "parent_span_id",
        "model",
        "usage.cost_usd",
    }
)

# ---------------------------------------------------------------------------
# Identifier & datetime key protection -- graph join-key integrity
# (amplifier-support issue #386 / engagement item I6).
#
# WHAT: Fields whose KEY marks them as a structural identifier or a datetime
#       join-key component. Unlike DEFAULT_ALLOWLIST (matched on a field's exact
#       dotted path), these are matched on the field KEY at EVERY nesting depth
#       -- so an identifier survives whether it sits at the envelope root or
#       nested inside a delegation/lineage payload. This is the systematic,
#       position-independent counterpart to the exact-path allowlist above.
#
# WHY:  The downstream Context Intelligence graph composes node_ids from these
#       fields (session_id + timestamp + tool_call_id). The PII "phone" regex
#       eats digit/hyphen runs inside hex ids, UUIDs, and ISO timestamps, and
#       scrub() masks any string whose exact path is not allowlisted -- so
#       lineage ids like sub_session_id (never in the flat allowlist) were
#       masked BEFORE node_id composition, permanently corrupting graph join
#       keys (~9.6% of sessions, sometimes colliding two people's work).
#       Protecting the identifier/datetime CLASS by key semantics is the only
#       complete fix; a per-field allowlist patch cannot cover nested or
#       future id fields.
#
# HOW:  IDENTIFIER_KEY_PATTERNS are fnmatch (shell-glob) patterns matched
#       against the field key, minus the _PII_BEARING_ID_KEYS exclusions below.
#       DATETIME_KEYS are matched EXACTLY (no wildcard), so a short token like
#       "ts" cannot accidentally match unrelated keys (e.g. "results") and a
#       broad "*_at" cannot swallow arbitrary fields -- every protected datetime
#       field is enumerated by name. Consumers EXTEND both via RedactionConfig,
#       never replace them.
# ---------------------------------------------------------------------------
IDENTIFIER_KEY_PATTERNS: tuple[str, ...] = (
    "*_id",  # session_id, parent_id, sub_session_id, node_id, run_id,
    # orchestrator_run_id, prompt_id, iteration_id, tool_call_id,
    # span_id, parent_span_id, turn_id, trace_id, tool_use_id, ...
    "*_ids",  # plural id lists (e.g. source_session_ids)
    "parent",  # session:fork lineage pointer (scalar or subtree)
)

# Person-identifying, id-shaped keys that MATCH the *_id glob but are NOT graph
# join keys and can legitimately carry PII (e.g. an email used as a user
# handle). They are EXCLUDED from identifier protection so they remain subject
# to full PII scrubbing -- e.g. {"user_id": "alice@contoso.com"} is still
# redacted. (Zero such instances were found across 8,089 scanned event files,
# so this is belt-and-suspenders that makes the guarantee explicit rather than
# probabilistic.) Note the residual, documented trade-off: an id-shaped field
# NOT on this list that happens to carry PII would be PII-exempt.
_PII_BEARING_ID_KEYS: frozenset[str] = frozenset(
    {
        "user_id",
        "author_id",
        "account_id",
        "owner_id",
        "customer_id",
        "email_id",
    }
)

# Datetime keys are enumerated EXACTLY (no "*_at" glob) so that only real
# datetime join-key fields are exempted and an unrelated "*_at" field is never
# blanket-swallowed. Grounded in the datetime keys that actually appear in
# stored Context Intelligence event payloads (verified against 8,089 event
# files); server-only Neo4j node/edge properties that never reach the redaction
# hook are deliberately excluded. Consumer-specific datetime vocabulary belongs
# in RedactionConfig.extra_datetime_keys, not in these core constants.
DATETIME_KEYS: frozenset[str] = frozenset(
    {
        "timestamp",  # root + data.timestamp -- high volume; node_id component
        "ts",  # streaming envelope -- high volume
        "created_at",  # data.raw.created_at
        "completed_at",  # data.raw.completed_at
        "started_at",  # session/run lifecycle start
        "ended_at",  # session/run lifecycle end
    }
)

# The PII rule name (see DEFAULT_RULES). Protected identifier/datetime fields
# are exempted from THIS rule only -- see _rules_without_pii / scrub().
_PII_RULE = "pii-basic"


def _rules_without_pii(rules: Sequence[str]) -> tuple[str, ...]:
    """Return ``rules`` with the PII rule removed, secret rules preserved.

    Identifier/datetime fields are join keys: the PII patterns (notably the
    "phone" regex) corrupt them, but the prefix-anchored SECRET patterns never
    match an opaque id/timestamp. Dropping only the PII rule fixes the
    corruption while KEEPING secret scrubbing, so a mis-named field (e.g. a
    ``*_id`` that actually carries a credential) can never leak a secret.
    """
    return tuple(r for r in rules if r != _PII_RULE)


def _is_protected_key(
    key: str,
    identifier_patterns: Sequence[str] = IDENTIFIER_KEY_PATTERNS,
    datetime_keys: AbstractSet[str] = DATETIME_KEYS,
    excluded_keys: AbstractSet[str] = _PII_BEARING_ID_KEYS,
) -> bool:
    """Return True if a field KEY marks a structural identifier or datetime.

    Identifier keys are matched as fnmatch shell-globs; datetime keys are
    matched exactly. Matching the key (not the absolute path) makes protection
    depth-independent -- the field is exempt from redaction wherever it appears.

    ``excluded_keys`` are id-shaped keys that are deliberately NOT protected
    (person-identifying fields that can carry PII, e.g. ``user_id``); they stay
    subject to full PII scrubbing.
    """
    if key in excluded_keys:
        return False
    if key in datetime_keys:
        return True
    return any(fnmatch.fnmatchcase(key, pat) for pat in identifier_patterns)


def _protect_join_value(value, path, mask_scalar, scrub_container):  # type: ignore[no-untyped-def]
    """Scrub a value living under a protected identifier/datetime key.

    Shared by the free :func:`scrub` and :meth:`Redactor.scrub` so the
    protected-key handling lives in one place. ``mask_scalar(text)`` masks a
    scalar string with the PII rule removed (opaque ids/timestamps survive while
    secrets are still scrubbed); ``scrub_container(value, path)`` recurses into a
    non-string container with the FULL rule set so ordinary content nested under
    an id-named key is never left un-redacted. Lists are handled element-wise.
    """
    if isinstance(value, str):
        return mask_scalar(value)
    if isinstance(value, list):
        return [
            mask_scalar(item)
            if isinstance(item, str)
            else scrub_container(item, f"{path}[{i}]")
            for i, item in enumerate(value)
        ]
    return scrub_container(value, path)


def mask_text(text: str, rules: Sequence[str] = DEFAULT_RULES) -> str:
    """Mask secrets and PII inside a single string.

    This is the public, pure string masker. It applies SECRET_PATTERNS first
    (replacing matches with ``[REDACTED:SECRET]``) and then PII_PATTERNS
    (replacing matches with ``[REDACTED:PII]``), gated by ``rules``.

    Args:
        text: The string to scrub.
        rules: Which rule categories to apply. ``"secrets"`` enables
            SECRET_PATTERNS; ``"pii-basic"`` enables PII_PATTERNS. Defaults to
            both. Unknown rule names are ignored.

    Returns:
        The masked string. Has no allowlist awareness; callers that need
        structural-field protection should use :func:`scrub`.
    """
    out = text
    if "secrets" in rules:
        for pat in SECRET_PATTERNS:
            out = pat.sub("[REDACTED:SECRET]", out)
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
        pii_off = _rules_without_pii(rules)

        def _mask_scalar(text: str) -> str:
            return mask_text(text, pii_off)

        def _scrub_container(val: Any, p: str) -> Any:
            return scrub(val, rules, allowlist, p)

        out: dict[Any, Any] = {}
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else k
            if child_path in allowlist:
                # Exact-path allowlist wins first: the field is returned
                # byte-identical (its pre-existing "never touched" guarantee).
                out[k] = v
            elif isinstance(k, str) and _is_protected_key(k):
                # Identifier/datetime join key (issue #386 / I6): exempt id/
                # timestamp strings from PII masking (which corrupts them) but
                # KEEP secret masking, at any nesting depth.
                out[k] = _protect_join_value(
                    v, child_path, _mask_scalar, _scrub_container
                )
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
    """

    rules: Sequence[str] = DEFAULT_RULES
    allowlist: AbstractSet[str] = DEFAULT_ALLOWLIST
    extra_secret_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
    extra_pii_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
    extra_identifier_key_patterns: Sequence[str] = field(default_factory=tuple)
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
            identifier_patterns = (
                *IDENTIFIER_KEY_PATTERNS,
                *self.config.extra_identifier_key_patterns,
            )
            datetime_keys = DATETIME_KEYS | set(self.config.extra_datetime_keys)
            pii_off = _rules_without_pii(self.config.rules)

            def _mask_scalar(text: str) -> str:
                return self._mask(text, pii_off)

            def _scrub_container(val: Any, p: str) -> Any:
                return self.scrub(val, p)

            out: dict[Any, Any] = {}
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                if child_path in self.config.allowlist:
                    # Exact-path allowlist wins first (byte-identical passthrough).
                    out[k] = v
                elif isinstance(k, str) and _is_protected_key(
                    k, identifier_patterns, datetime_keys
                ):
                    # Join key (issue #386 / I6): PII-exempt but still
                    # secret-scrubbed, at any nesting depth.
                    out[k] = _protect_join_value(
                        v, child_path, _mask_scalar, _scrub_container
                    )
                else:
                    out[k] = self.scrub(v, child_path)
            return out
        return obj
