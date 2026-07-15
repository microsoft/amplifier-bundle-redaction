"""
Redaction hook: masks secrets/PII in event data for logging.
Register with higher priority than logging.

This is a THIN Amplifier adapter over the zero-dependency ``redaction``
library (the sibling ``amplifier-bundle-redaction`` package, consumed here
as a normal dependency). All masking logic -- patterns, allowlist, the
recursive scrubber -- lives in ``redaction``; this module owns only the
Amplifier hook lifecycle: mount() registration, event subscription, and
translating library output into a HookResult.

Uses HookResult(action="modify") to return redacted copies rather than
mutating the shared event data dict in-place. Events that feed back into
LLM context (tool:pre, tool:post) are skipped to avoid corrupting tool
results the model needs verbatim (e.g. session IDs, timestamps).
"""

from __future__ import annotations

# Amplifier module metadata
__amplifier_module_type__ = "hook"

import logging
from typing import Any

from amplifier_core import HookResult
from amplifier_core import ModuleCoordinator

from redaction import DEFAULT_ALLOWLIST
from redaction import scrub

logger = logging.getLogger(__name__)

__all__ = ["mount"]


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    config = config or {}
    rules = list(config.get("rules", ["secrets", "pii-basic"]))
    # Effective allowlist = built-in structural fields ∪ user-provided entries.
    # Users extend but never reduce the defaults.
    allowlist = DEFAULT_ALLOWLIST | set(config.get("allowlist", []))
    priority = int(config.get("priority", 10))

    # Events whose data feeds back into LLM context. Redacting these
    # corrupts tool results the model needs verbatim (session IDs, etc.).
    context_events = set(
        config.get(
            "skip_events",
            [
                "tool:pre",
                "tool:post",
            ],
        )
    )

    async def handler(event: str, data: dict[str, Any]) -> HookResult:
        if event in context_events:
            return HookResult(action="continue")
        try:
            redacted = scrub(data, rules, allowlist)
            if isinstance(redacted, dict):
                redacted["redaction"] = {"applied": True, "rules": rules}
                return HookResult(action="modify", data=redacted)
        except Exception as e:
            logger.debug(f"Redaction error: {e}")
        return HookResult(action="continue")

    # Subscribe to the canonical event set (verbatim from the source hook's
    # mount(), amplifier-module-hooks-redaction/amplifier_module_hooks_redaction/
    # __init__.py lines 224-268 -- 23 events).
    events = [
        "session:start",
        "session:end",
        "prompt:submit",
        "prompt:complete",
        "plan:start",
        "plan:end",
        "provider:request",
        "provider:response",
        "provider:error",
        # LLM text events -- carry the actual content of LLM turns.
        #
        # These were previously missing from the subscription list, which meant
        # 100% of LLM text events reached events.jsonl without redaction applied:
        #
        #   llm:request      -- full message history in data.raw.messages; each
        #                       message may include prior LLM turns that echoed
        #                       secrets back to the model.
        #   llm:response     -- full API response in data.raw; content blocks in
        #                       data.raw.content[*].text carry the LLM's reply.
        #   content_block:end -- the streamed LLM response text in data.block.text.
        #
        # The kernel's Modify-chain propagates redaction mutations to all
        # subsequent handlers including hooks-logging, so events.jsonl will
        # contain redacted text after this fix. This also affects streaming-ui
        # rendering -- secrets in LLM output will be masked at the terminal,
        # which is the correct default for privacy.
        #
        # scrub() already traverses arbitrary nested dicts/lists, so adding
        # these subscriptions is sufficient -- no structural changes needed.
        "llm:request",
        "llm:response",
        "content_block:end",
        "tool:pre",
        "tool:post",
        "tool:error",
        "context:pre_compact",
        "context:post_compact",
        "artifact:write",
        "artifact:read",
        "policy:violation",
        "approval:required",
        "approval:granted",
        "approval:denied",
    ]
    for ev in events:
        coordinator.hooks.on(ev, handler, name="hook-redaction", priority=priority)

    logger.info("Mounted hook-redaction")
    return
