"""Tests for LLM event redaction subscription coverage.

hooks-redaction must subscribe to llm:request, llm:response, and
content_block:end — the three events that carry actual LLM text content.
Before the fix these events were NOT subscribed, meaning 100% of them
reached events.jsonl with no redaction applied (empirically confirmed:
347/347 content_block:end, 316/316 llm:request, 316/316 llm:response
in a real session with full text unredacted).

The scrub() function already handles nested dicts/lists recursively,
so the fix is purely subscription coverage: add the three events to
the registration list in mount().
"""

import pytest
import pytest_asyncio
from amplifier_core import HookResult

from tests.conftest import mount_and_ready

# AWS Access Key matches the AKIA[0-9A-Z]{16} pattern in SECRET_PATTERNS.
# Built from fragments (not one contiguous literal) so this well-known
# example value can't be flagged by secret scanners on the source itself --
# the runtime-assembled string still matches the pattern exactly the same.
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
REDACTED = "[REDACTED:SECRET]"


@pytest_asyncio.fixture
async def coordinator():
    """Fresh coordinator with hook-redaction mounted AND subscribed.

    hook-redaction no longer subscribes to events at mount() time --
    subscription happens in on_session_ready(), once the full event set is
    discoverable (mount()/on_session_ready() split, mirrors
    hook-context-intelligence). Both phases must run for emit() to reach
    the handler.
    """
    return await mount_and_ready()


@pytest.mark.asyncio
async def test_llm_response_text_redacted(coordinator):
    """llm:response: data.raw.content[0].text containing a secret must be scrubbed.

    Before the fix: hooks-redaction is NOT subscribed to llm:response.
    emit() returns the raw data unmodified — the secret survives intact
    and the redaction marker is absent.

    After the fix: hooks-redaction IS subscribed. scrub() traverses
    raw > content > [0] > text and replaces the secret. The redaction
    marker confirms the handler ran.
    """
    data = {"raw": {"content": [{"text": f"Here is your API key: {AWS_KEY}"}]}}
    result = await coordinator.hooks.emit("llm:response", data)

    assert result is not None
    text = result.data["raw"]["content"][0]["text"]
    assert AWS_KEY not in text, (
        f"Secret must be redacted in llm:response content text, got: {text!r}"
    )
    assert REDACTED in text, f"Redaction marker must appear in text, got: {text!r}"
    assert result.data.get("redaction", {}).get("applied") is True, (
        "redaction.applied must be True — handler must have run on llm:response"
    )


@pytest.mark.asyncio
async def test_content_block_end_text_redacted(coordinator):
    """content_block:end: data.block.text containing a secret must be scrubbed.

    Before the fix: hooks-redaction is NOT subscribed to content_block:end.
    The emitted text (the LLM's actual response) arrives unredacted.

    After the fix: hooks-redaction IS subscribed. scrub() traverses
    block > text and replaces the secret.
    """
    data = {"block": {"text": f"Hello, your token is {AWS_KEY}"}}
    result = await coordinator.hooks.emit("content_block:end", data)

    assert result is not None
    text = result.data["block"]["text"]
    assert AWS_KEY not in text, (
        f"Secret must be redacted in content_block:end block text, got: {text!r}"
    )
    assert REDACTED in text, f"Redaction marker must appear in text, got: {text!r}"
    assert result.data.get("redaction", {}).get("applied") is True, (
        "redaction.applied must be True — handler must have run on content_block:end"
    )


@pytest.mark.asyncio
async def test_llm_request_messages_redacted(coordinator):
    """llm:request: data.raw.messages user content containing a secret must be scrubbed.

    Before the fix: hooks-redaction is NOT subscribed to llm:request.
    The full message history (including prior LLM turns that may contain
    secrets the model echoed) is logged unredacted.

    After the fix: hooks-redaction IS subscribed. scrub() traverses
    raw > messages > [0] > content and replaces the secret.
    """
    data = {"raw": {"messages": [{"role": "user", "content": f"My key is {AWS_KEY}"}]}}
    result = await coordinator.hooks.emit("llm:request", data)

    assert result is not None
    content = result.data["raw"]["messages"][0]["content"]
    assert AWS_KEY not in content, (
        f"Secret must be redacted in llm:request messages content, got: {content!r}"
    )
    assert REDACTED in content, (
        f"Redaction marker must appear in content, got: {content!r}"
    )
    assert result.data.get("redaction", {}).get("applied") is True, (
        "redaction.applied must be True — handler must have run on llm:request"
    )


@pytest.mark.asyncio
async def test_non_secret_text_passthrough(coordinator):
    """content_block:end without secrets must pass through text unchanged.

    Redaction must not munge legitimate non-secret content. This is the
    regression guard: adding these subscriptions must not cause false
    positives on ordinary LLM output.
    """
    clean_text = "Here is a normal response with no secrets."
    data = {"block": {"text": clean_text}}
    result = await coordinator.hooks.emit("content_block:end", data)

    assert result is not None
    assert result.data["block"]["text"] == clean_text, (
        f"Clean text must be unchanged — no false-positive redaction. "
        f"Got: {result.data['block']['text']!r}"
    )


@pytest.mark.asyncio
async def test_redaction_field_marker_set(coordinator):
    """llm:response containing a secret must have the redaction marker set.

    The marker shape must match what existing subscribed events produce:
    redaction = {"applied": True, "rules": [...]} at the top level of data.
    This mirrors the behavior already verified for prompt:submit.
    """
    data = {"raw": {"content": [{"text": f"Key: {AWS_KEY}"}]}}
    result = await coordinator.hooks.emit("llm:response", data)

    assert result is not None
    redaction = result.data.get("redaction")
    assert redaction is not None, (
        "redaction marker must be present after processing llm:response with a secret"
    )
    assert redaction.get("applied") is True, "redaction.applied must be True"
    assert isinstance(redaction.get("rules"), list), "redaction.rules must be a list"
    assert "secrets" in redaction["rules"], "redaction.rules must include 'secrets'"


@pytest.mark.asyncio
async def test_handler_survives_none_data(coordinator):
    """Handler must not crash when emitted with data=None on a subscribed event.

    Native replacement for the crash-safety coverage that used to come from
    amplifier-core's inherited `HookBehaviorTests` (which exercised a generic,
    unsubscribed "test:event" -- never actually invoking this handler). This
    calls the handler for real via a subscribed event ("session:start").

    `scrub(None, ...)` returns None unchanged (not a dict), so the handler's
    `if isinstance(redacted, dict)` branch is skipped and it falls through to
    `HookResult(action="continue")` -- no exception needed, but we assert
    the non-crash behavior explicitly either way.
    """
    result = await coordinator.hooks.emit("session:start", None)

    assert isinstance(result, HookResult), (
        f"Handler must return a HookResult on None data, got: {result!r}"
    )
    assert result.action == "continue", (
        f"Handler must let the pipeline continue on None data, got action: {result.action!r}"
    )


@pytest.mark.asyncio
async def test_handler_survives_empty_data(coordinator):
    """Handler must not crash when emitted with data={} on a subscribed event.

    Native replacement for the crash-safety coverage that used to come from
    amplifier-core's inherited `HookBehaviorTests` (see test above for why
    that coverage was vacuous for this module).

    `scrub({}, ...)` returns `{}` (a dict), so the handler takes the
    redaction-marker branch and returns `HookResult(action="modify", ...)` --
    it does not crash, and the result is a valid HookResult either way.
    """
    result = await coordinator.hooks.emit("session:start", {})

    assert isinstance(result, HookResult), (
        f"Handler must return a HookResult on empty data, got: {result!r}"
    )
    assert result.action in ("continue", "modify"), (
        f"Handler must return a valid, non-crashing action on empty data, got: {result.action!r}"
    )
