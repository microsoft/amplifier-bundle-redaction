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
    """

    rules: Sequence[str] = DEFAULT_RULES
    allowlist: AbstractSet[str] = DEFAULT_ALLOWLIST
    extra_secret_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
    extra_pii_patterns: Sequence[re.Pattern] = field(default_factory=tuple)
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
