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
    re.compile(r"\+?\d[\d\s().-]{7,}\d"),
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
        return {
            k: scrub(v, rules, allowlist, f"{path}.{k}" if path else k)
            for k, v in obj.items()
        }
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


class Redactor:
    """A configured masker: ``Redactor(RedactionConfig())`` behaves exactly
    like the free functions :func:`mask_text`/:func:`scrub` with default
    arguments; passing a non-default config extends the frozen defaults with
    app-specific rules/allowlist entries/patterns.
    """

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()

    def mask_text(self, text: str) -> str:
        """Mask secrets and PII in ``text`` per this Redactor's config."""
        out = mask_text(text, self.config.rules)
        if "secrets" in self.config.rules:
            for pat in self.config.extra_secret_patterns:
                out = pat.sub("[REDACTED:SECRET]", out)
        if "pii-basic" in self.config.rules:
            for pat in self.config.extra_pii_patterns:
                out = pat.sub("[REDACTED:PII]", out)
        return out

    def scrub(self, obj: Any, path: str = "") -> Any:
        """Recursively scrub ``obj`` per this Redactor's config."""
        if path in self.config.allowlist:
            return obj
        if isinstance(obj, str):
            return self.mask_text(obj)
        if isinstance(obj, list):
            return [self.scrub(v, f"{path}[{i}]") for i, v in enumerate(obj)]
        if isinstance(obj, dict):
            return {
                k: self.scrub(v, f"{path}.{k}" if path else k) for k, v in obj.items()
            }
        return obj
