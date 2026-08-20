"""
Redaction hook: masks secrets/PII in event data for logging.

This is a THIN Amplifier adapter over the zero-dependency ``redaction``
library (the sibling ``amplifier-bundle-redaction`` package, consumed here
as a normal dependency). All masking logic -- patterns, allowlist, the
recursive scrubber -- lives in ``redaction``; this module owns only the
Amplifier hook lifecycle: mount()/on_session_ready() event subscription,
and translating library output into a HookResult.

Lifecycle (mirrors hook-context-intelligence's mount()/on_session_ready()
split -- see amplifier-bundle-context-intelligence):

    mount(coordinator, config)
        Setup only: parse config, build the handler closure, stash shared
        state (handler, priority, skip_events, unregister_fns) behind the
        ``redaction._hook_state`` capability, and return an async
        ``cleanup()`` closure. Does NOT subscribe to any events -- at
        mount() time not every module has mounted yet, so the full event
        set (including late module contributions) is not yet knowable.

    on_session_ready(coordinator)
        Called once, after every module has completed mount() (kernel
        Phase 6). Retrieves the shared state, computes the full discovered
        event set (kernel ALL_EVENTS + module contributions + the legacy
        ``observability.events`` capability), subtracts ``skip_events``,
        and registers the handler for every remaining event via
        ``coordinator.hooks.register(...)``. This is what gives redaction
        coverage of the ENTIRE kernel event surface (previously a
        hand-typed 23-event allowlist that silently missed ~19 events,
        including ``execution:start``) without hard-coding event names.

Uses HookResult(action="modify") to return redacted copies rather than
mutating the shared event data dict in-place. Tool events (tool:pre,
tool:post) ARE redacted -- under the ``secrets`` rule only, via
``event_rules`` below. A redacted tool result is what the model reads,
deliberately: a shell-printed secret in tool output must not be carried
forward and re-embedded into every subsequent ``llm:request``. ``pii-basic``
is deliberately NOT enabled for tool events -- the guarded phone-number
pattern eats digit/space runs in ordinary tool stdout (``df`` output, byte
counts, benchmark tables), which would corrupt content the model needs.

Config knobs
------------
rules : list[str], default ["secrets", "pii-basic"]
    Rule categories passed to ``redaction.scrub()``. This is the global
    default, used for any event not overridden by ``event_rules``.
allowlist : list[str], optional
    Additional dotted-path entries unioned with ``redaction.DEFAULT_ALLOWLIST``.
    Users extend but never reduce the defaults.
priority : int, default 10
    Hook registration priority (higher runs first; must run before
    hooks-logging so events.jsonl sees the redacted copy).
skip_events : list[str], default []
    Events excluded from redaction entirely. Empty by default -- see
    ``DEFAULT_SKIP_EVENTS`` for why tool:pre/tool:post no longer live here.
    Setting this explicitly still wins over the default, so a deployment
    that needs the old behavior can restore it with
    ``skip_events: ["tool:pre", "tool:post"]``.
event_rules : dict[str, list[str]], default {"tool:pre": ["secrets"], "tool:post": ["secrets"]}
    Per-event rule override, merged OVER the defaults per key (extend,
    never replace) -- narrowing one event must not silently re-enable
    ``pii-basic`` on tool events. Any event not present here falls back to
    the global ``rules``. The redaction receipt (``data["redaction"]``)
    stamps the RESOLVED per-event rules, not the global set.
"""

from __future__ import annotations

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
from collections.abc import Callable
from collections.abc import Coroutine
from typing import Any

from amplifier_core import HookResult

from redaction import DEFAULT_ALLOWLIST
from redaction import scrub

logger = logging.getLogger(__name__)

__all__ = ["mount", "on_session_ready"]

# Private capability key used to hand shared state from mount() to
# on_session_ready(). Not part of the public contract.
_STATE_CAPABILITY = "redaction._hook_state"

# Events excluded from redaction entirely. EMPTY by default.
#
# tool:pre/tool:post used to live here. They were the gap that let a bash
# command print `NAME=value` API keys straight to disk and to remote telemetry
# -- tool stdout is exactly where shell-printed secrets appear. The original
# rationale (protect session IDs and timestamps the model needs verbatim) is
# now served structurally and better by IDENTIFIER_KEYS / DATETIME_KEYS in the
# `redaction` library (issue #386), which protect those fields on EVERY event
# rather than by disabling redaction on two.
#
# Setting this explicitly still wins over the default, so a deployment that
# needs the old behavior can restore it with skip_events: ["tool:pre", "tool:post"].
DEFAULT_SKIP_EVENTS: frozenset[str] = frozenset()

# Per-event rule override. Tool events run the `secrets` rule ONLY.
#
# MEASURED: the pii-basic phone pattern eats digit/space runs in ordinary tool
# stdout -- `df` output, byte counts, and benchmark tables all become
# [REDACTED:PII]. Tool results are appended to the conversation (see
# amplifier-module-loop-streaming/__init__.py:3757-3770), so that would corrupt
# content the model needs. Scoping tool events to `secrets` keeps the credential
# protection and drops the numeric clipping.
#
# Merged OVER these defaults per key at mount() -- users extend, never replace.
DEFAULT_EVENT_RULES: dict[str, tuple[str, ...]] = {
    "tool:pre": ("secrets",),
    "tool:post": ("secrets",),
}


async def _discover_events(coordinator: Any) -> set[str]:
    """Union of kernel ALL_EVENTS + module contributions + legacy capability.

    Mirrors hook-context-intelligence's ``_discover_events`` exactly so
    redaction coverage tracks the same discovery mechanism other
    observability hooks rely on -- if the kernel adds an event, or a
    module contributes a custom one via ``observability.events``, both
    hooks pick it up the same way.
    """
    from amplifier_core.events import ALL_EVENTS

    discovered: set[str] = set(ALL_EVENTS)

    contributions = await coordinator.collect_contributions("observability.events")
    for event_list in contributions:
        discovered.update(event_list)

    capability = coordinator.get_capability("observability.events")
    if capability is not None:
        raw = capability() if callable(capability) else capability
        if isinstance(raw, (list, set, frozenset, tuple)):
            discovered.update(raw)

    return discovered


def _build_handler(
    rules: list[str],
    allowlist: frozenset[str],
    skip_events: frozenset[str],
    event_rules: dict[str, list[str]],
) -> Callable[[str, dict[str, Any] | None], Coroutine[Any, Any, HookResult]]:
    """Build the redaction handler closure over the resolved config."""

    async def handler(event: str, data: dict[str, Any] | None) -> HookResult:
        if event in skip_events:
            return HookResult(action="continue")
        # Per-event rules if configured, else the global default. The receipt
        # below stamps THESE rules, not the global set -- claiming pii-basic ran
        # on a tool event when it did not is the same class of lie FIX 1 exists
        # to prevent.
        active_rules = event_rules.get(event, rules)
        try:
            redacted = scrub(data, active_rules, allowlist)
        except Exception as e:
            # FIX 2 (fail-closed): a scrub() failure must never let the raw,
            # possibly-secret-bearing payload through. Log loudly (WARNING,
            # not debug -- this must be visible) and replace the event data
            # entirely with a failure marker. No original keys survive.
            logger.warning(
                "hook-redaction: scrub() failed for event %r (%s) -- "
                "failing closed, raw payload suppressed",
                event,
                e,
            )
            return HookResult(
                action="modify",
                data={"redaction": {"applied": False, "error": "scrub_failed"}},
            )

        if isinstance(redacted, dict):
            # FIX 1 (forged receipt): only claim redaction ran when the RESOLVED
            # rules for this event are non-empty. With an empty rule set scrub()
            # is a structural no-op (mask_text() applies no patterns), so
            # stamping applied=True would lie about protection that didn't
            # happen. This now also covers event_rules: {"<event>": []}.
            if active_rules:
                redacted["redaction"] = {
                    "applied": True,
                    "rules": list(active_rules),
                }
            return HookResult(action="modify", data=redacted)

        # Non-dict payloads (None, list, scalar) are not something the
        # kernel's action="modify" contract expects as top-level event
        # data; let the pipeline continue unmodified.
        return HookResult(action="continue")

    return handler


async def mount(
    coordinator: Any, config: dict[str, Any] | None = None
) -> Callable[[], Coroutine[Any, Any, None]]:
    """Mount the redaction hook: parse config, build the handler, stash state.

    Does NOT subscribe to any events -- see module docstring. Event
    registration happens in :func:`on_session_ready`, once the full event
    set is knowable.
    """
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))
    # Effective allowlist = built-in structural fields ∪ user-provided entries.
    # Users extend but never reduce the defaults.
    allowlist = DEFAULT_ALLOWLIST | set(config.get("allowlist", []))
    priority = int(config.get("priority", 10))
    skip_events = frozenset(config.get("skip_events", DEFAULT_SKIP_EVENTS))
    # Merge user overrides OVER the defaults per key (extend, never replace):
    # narrowing one event must not silently re-enable pii-basic on tool events.
    event_rules: dict[str, list[str]] = {
        k: list(v) for k, v in DEFAULT_EVENT_RULES.items()
    }
    for event_name, event_rule_list in (config.get("event_rules") or {}).items():
        event_rules[event_name] = list(event_rule_list)

    handler = _build_handler(rules, allowlist, skip_events, event_rules)

    unregister_fns: list[Callable[[], None]] = []

    # Share mutable state with on_session_ready via a private capability.
    # The cleanup closure closes over unregister_fns by reference -- any
    # entries appended by on_session_ready() will be torn down automatically.
    _hook_state = {
        "handler": handler,
        "priority": priority,
        "skip_events": skip_events,
        "event_rules": event_rules,
        "unregister_fns": unregister_fns,
    }
    coordinator.register_capability(_STATE_CAPABILITY, _hook_state)

    async def cleanup() -> None:
        for unreg in unregister_fns:
            try:
                unreg()
            except Exception:
                pass
        try:
            coordinator.register_capability(_STATE_CAPABILITY, None)
        except Exception:
            pass

    return cleanup


async def on_session_ready(coordinator: Any) -> None:
    """Finalize event subscription once every module has mounted.

    Discovers the full event set (kernel ALL_EVENTS + module contributions
    + legacy ``observability.events`` capability), subtracts
    ``skip_events``, and registers the redaction handler for every
    remaining event.

    Never raises. The kernel catches on_session_ready exceptions (logs a
    warning, emits ``MODULE_ON_SESSION_READY_FAILED``, and continues the
    session) -- so a raise here would silently disable redaction for the
    whole session with no other signal. If the ``mount()`` state capability
    is missing (mount() did not run, or ran against a different
    coordinator), log a warning and return instead of raising.
    """
    state = coordinator.get_capability(_STATE_CAPABILITY)
    if state is None:
        logger.warning(
            "on_session_ready: hook-redaction state not found -- mount() may not have run"
        )
        return

    handler = state["handler"]
    priority = state["priority"]
    skip_events = state["skip_events"]
    unregister_fns = state["unregister_fns"]

    # FIX 3 (completeness): coverage now comes from discovery, not a
    # hand-typed allowlist -- execution:start and the ~18 other previously
    # missing events are automatically covered.
    events = await _discover_events(coordinator)
    active_events = events - skip_events

    for event in sorted(active_events):
        unreg = coordinator.hooks.register(
            event, handler, priority=priority, name="hook-redaction"
        )
        unregister_fns.append(unreg)

    logger.info(
        "hook-redaction: registered %d events (skipped %d)",
        len(active_events),
        len(skip_events),
    )
