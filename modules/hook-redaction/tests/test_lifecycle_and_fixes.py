"""Tests for the mount()/on_session_ready() lifecycle split and the three
ratified fixes applied to the redaction handler.

Coverage (FIX 3): event subscription now comes from discovery
(ALL_EVENTS + module contributions + legacy capability) minus skip_events,
computed in on_session_ready() -- not a hand-typed allowlist. This is what
gives ``execution:start`` and the ~18 other previously-missing events
automatic coverage.

Forged receipt (FIX 1): the handler must not stamp ``redaction.applied =
True`` when ``rules`` is empty -- that would claim protection that did not
run.

Fail-closed (FIX 2): a ``scrub()`` exception must never let the raw payload
through. The handler must log at WARNING and replace the event data with a
failure marker.

All secret-shaped literals below are assembled from fragments at runtime
(never one contiguous literal in source) so they can't be flagged by
source-level secret scanners, while the assembled runtime value still
matches the ``redaction`` library's own SECRET_PATTERNS regex.
"""

from __future__ import annotations

import pytest
from amplifier_core import MockCoordinator
from amplifier_core.events import ALL_EVENTS

import amplifier_module_hook_redaction as mod
from tests.conftest import mount_and_ready

REDACTED_SECRET = "[REDACTED:SECRET]"


def _fake_aws_key() -> str:
    """Matches AKIA[0-9A-Z]{16} -- built from fragments, not one literal."""
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _fake_github_pat() -> str:
    """Matches \\bghp_[A-Za-z0-9_]{10,} -- built from fragments."""
    return "ghp_" + "0" * 36


# ---------------------------------------------------------------------------
# FIX 3 / completeness: event coverage comes from discovery, not an allowlist
# ---------------------------------------------------------------------------


class TestCoverageComplete:
    """on_session_ready() must register every kernel event except skip_events."""

    @pytest.mark.asyncio
    async def test_coverage_complete(self):
        mc = MockCoordinator()
        await mod.mount(mc)
        await mod.on_session_ready(mc)

        registered = set(mc.hooks.list_handlers().keys())

        assert registered == set(ALL_EVENTS) - mod.DEFAULT_SKIP_EVENTS, (
            "hook-redaction must register exactly ALL_EVENTS minus skip_events -- "
            f"missing: {set(ALL_EVENTS) - mod.DEFAULT_SKIP_EVENTS - registered!r}, "
            f"unexpected: {registered - (set(ALL_EVENTS) - mod.DEFAULT_SKIP_EVENTS)!r}"
        )

        # The complementary framing from the task: registered | skip_events
        # must reconstitute the full kernel event set. This is the assertion
        # that fails loudly if the kernel ever adds a new event -- discovery
        # via ALL_EVENTS means it's covered automatically, but this test
        # pins the invariant so a future skip_events change can't silently
        # shrink coverage either.
        assert registered | mod.DEFAULT_SKIP_EVENTS == set(ALL_EVENTS)

    @pytest.mark.asyncio
    async def test_skip_events_not_registered(self):
        mc = MockCoordinator()
        await mod.mount(mc)
        await mod.on_session_ready(mc)

        registered = set(mc.hooks.list_handlers().keys())
        assert "tool:pre" not in registered
        assert "tool:post" not in registered

    @pytest.mark.asyncio
    async def test_execution_start_now_covered(self):
        """execution:start was one of the ~19 events missing from the old
        hand-typed 23-event allowlist. Discovery-based coverage picks it up
        automatically."""
        mc = MockCoordinator()
        await mod.mount(mc)
        await mod.on_session_ready(mc)

        assert "execution:start" in mc.hooks.list_handlers()


# ---------------------------------------------------------------------------
# execution:start redaction + structure preservation
# ---------------------------------------------------------------------------


class TestExecutionStartRedacted:
    @pytest.mark.asyncio
    async def test_execution_start_redacted(self):
        mc = await mount_and_ready()
        secret = _fake_aws_key()
        data = {
            "prompt": f"here is my key: {secret}",
            "turn": 3,
            "nested": {"a": 1, "list": [1, 2, 3]},
        }
        result = await mc.hooks.emit("execution:start", data)

        assert result is not None
        assert secret not in result.data["prompt"], (
            f"secret must be redacted, got: {result.data['prompt']!r}"
        )
        assert REDACTED_SECRET in result.data["prompt"]

        # Behavior preservation: structure and non-secret fields survive intact.
        assert result.data["turn"] == 3
        assert result.data["nested"] == {"a": 1, "list": [1, 2, 3]}

        assert result.data.get("redaction", {}).get("applied") is True


# ---------------------------------------------------------------------------
# False positives: masking is consistent, doesn't corrupt sibling fields
# ---------------------------------------------------------------------------


class TestFalsePositiveNoCorruption:
    @pytest.mark.asyncio
    async def test_false_positive_no_corruption(self):
        """A legitimate identifier that happens to match a secret pattern
        (the generic "sk-" prefix rule has no way to distinguish a real
        OpenAI-style key from any other "sk-"-prefixed identifier) still
        gets masked -- and masking it must not corrupt sibling fields."""
        mc = await mount_and_ready()

        # Legitimate-looking identifier, not a real credential, but matches
        # \bsk-[A-Za-z0-9_\-]{10,} structurally (false positive by design).
        false_positive_id = "sk-" + "session0123456789"
        data = {
            "identifier": false_positive_id,
            "sibling_str": "completely-untouched-value",
            "sibling_int": 5,
            "sibling_list": ["a", "b", "c"],
        }
        result = await mc.hooks.emit("session:start", data)

        assert false_positive_id not in result.data["identifier"]
        assert REDACTED_SECRET in result.data["identifier"]

        # Sibling fields must survive completely untouched -- no corruption
        # bleeding from the masked field into neighbors.
        assert result.data["sibling_str"] == "completely-untouched-value"
        assert result.data["sibling_int"] == 5
        assert result.data["sibling_list"] == ["a", "b", "c"]

    @pytest.mark.asyncio
    async def test_masking_is_deterministic(self):
        """The same false-positive value masked twice produces the same result."""
        mc = await mount_and_ready()
        false_positive_id = "sk-" + "session0123456789"

        result1 = await mc.hooks.emit(
            "session:start", {"identifier": false_positive_id}
        )
        result2 = await mc.hooks.emit(
            "session:start", {"identifier": false_positive_id}
        )

        assert result1.data["identifier"] == result2.data["identifier"]


# ---------------------------------------------------------------------------
# Free-text carrier events: secrets in the LLM's own "thinking"/notification
# text must still be redacted, wherever the text lives in the payload.
# ---------------------------------------------------------------------------


class TestFreeTextCarriers:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "event,field",
        [
            ("thinking:delta", "delta"),
            ("thinking:final", "text"),
            ("user:notification", "message"),
        ],
    )
    async def test_free_text_carrier_redacted(self, event, field):
        assert event in ALL_EVENTS, f"{event!r} must be a real kernel event"
        mc = await mount_and_ready()
        secret = _fake_github_pat()
        data = {field: f"note to self: {secret}"}

        result = await mc.hooks.emit(event, data)

        assert secret not in result.data[field], (
            f"secret must be redacted in {event}/{field}, got: {result.data[field]!r}"
        )
        assert REDACTED_SECRET in result.data[field]


# ---------------------------------------------------------------------------
# FIX 1: forged receipt -- rules=[] must not stamp applied=True
# ---------------------------------------------------------------------------


class TestForgedReceipt:
    @pytest.mark.asyncio
    async def test_forged_receipt_not_stamped(self):
        mc = await mount_and_ready(config={"rules": []})
        secret = _fake_aws_key()

        result = await mc.hooks.emit("session:start", {"value": secret})

        # With rules=[] scrub() is a structural no-op -- nothing was actually
        # redacted, so no "redaction" marker claiming applied=True may exist.
        assert result.data.get("redaction") is None, (
            "rules=[] must not stamp a redaction marker at all -- "
            f"got: {result.data.get('redaction')!r}"
        )
        # And, correspondingly, the value truly was NOT redacted (rules=[]
        # really is a no-op, not silently falling back to defaults).
        assert result.data["value"] == secret

    @pytest.mark.asyncio
    async def test_nonempty_rules_still_stamp_applied_true(self):
        """Regression guard: the fix must not break the normal case."""
        mc = await mount_and_ready()
        secret = _fake_aws_key()

        result = await mc.hooks.emit("session:start", {"value": secret})

        assert result.data.get("redaction", {}).get("applied") is True
        assert secret not in result.data["value"]


# ---------------------------------------------------------------------------
# FIX 2: exception fail-closed -- scrub() failure must never leak raw data
# ---------------------------------------------------------------------------


class TestExceptionFailClosed:
    @pytest.mark.asyncio
    async def test_exception_fail_closed(self, monkeypatch, caplog):
        mc = await mount_and_ready()
        secret = _fake_aws_key()

        def _boom(*args, **kwargs):
            raise RuntimeError("scrub exploded")

        monkeypatch.setattr(mod, "scrub", _boom)

        import logging

        with caplog.at_level(logging.WARNING, logger="amplifier_module_hook_redaction"):
            result = await mc.hooks.emit("session:start", {"secret": secret})

        # No raw payload -- the original "secret" key/value must be gone entirely.
        assert result.data == {"redaction": {"applied": False, "error": "scrub_failed"}}
        assert secret not in str(result.data)

        # The failure must be visible at WARNING, not silently swallowed at debug.
        assert any(record.levelno == logging.WARNING for record in caplog.records)

    @pytest.mark.asyncio
    async def test_exception_does_not_raise(self, monkeypatch):
        """The handler itself must never raise -- it always returns a HookResult."""
        mc = await mount_and_ready()

        def _boom(*args, **kwargs):
            raise ValueError("boom")

        monkeypatch.setattr(mod, "scrub", _boom)

        # Must not raise.
        result = await mc.hooks.emit("session:start", {"anything": "value"})
        assert result is not None
        assert result.data.get("redaction", {}).get("applied") is False
