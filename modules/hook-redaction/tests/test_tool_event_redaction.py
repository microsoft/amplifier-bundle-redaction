"""Tests for tool-event (tool:pre/tool:post) redaction coverage.

Before this fix, `DEFAULT_SKIP_EVENTS` excluded `tool:pre`/`tool:post`
entirely -- the scrubber never ran on them. Tool stdout is exactly where a
shell-printed `NAME=value` credential appears (the incident this PR closes:
a bash command echoed an API key straight to disk and to remote telemetry
via these two unscrubbed events).

Tool events are now registered like any other event, but scoped to the
`secrets` rule ONLY via `event_rules` (`DEFAULT_EVENT_RULES`) -- `pii-basic`
is deliberately excluded because the guarded phone-number pattern eats
digit/space runs in ordinary tool stdout (`df` output, byte counts,
benchmark tables), which would corrupt content the model needs verbatim.

All secret-shaped literals below are assembled from fragments at runtime
(never one contiguous literal in source) so they can't be flagged by
source-level secret scanners, mirroring the existing convention in this
test suite.
"""

from __future__ import annotations

import logging

import pytest
from amplifier_core import MockCoordinator

import amplifier_module_hook_redaction as mod
from tests.conftest import mount_and_ready

REDACTED_SECRET = "[REDACTED:SECRET]"
REDACTED_PII = "[REDACTED:PII]"


def _fake_api_key() -> str:
    """A NAME=value-shaped credential with no vendor prefix -- proves the NEW
    SECRET_ASSIGNMENT_PATTERNS pattern fires, not a pre-existing prefix rule."""
    return "Zx9QpL" + "4mNvR2tYw8"


def _df_shaped_stdout() -> str:
    """Ordinary `df`-shaped tool output. The guarded phone-number PII pattern
    is known to clip runs like this -- it must NOT touch tool events."""
    return (
        "Filesystem 1K-blocks Used Available\n/dev/sda1 984372184 812345678 121026506"
    )


# ---------------------------------------------------------------------------
# H-1: tool events are subscribed
# ---------------------------------------------------------------------------


class TestToolEventsSubscribed:
    @pytest.mark.asyncio
    async def test_tool_events_subscribed(self):
        mc = MockCoordinator()
        await mod.mount(mc)
        await mod.on_session_ready(mc)

        registered = set(mc.hooks.list_handlers().keys())
        assert "tool:post" in registered
        assert "tool:pre" in registered


# ---------------------------------------------------------------------------
# H-2: synthetic tool:post is masked AND receipted
# ---------------------------------------------------------------------------


class TestToolPostMaskedAndReceipted:
    @pytest.mark.asyncio
    async def test_tool_post_masked_and_receipted(self):
        mc = await mount_and_ready()
        fake = _fake_api_key()
        data = {
            "tool_name": "bash",
            "tool_call_id": "tc_1",
            "tool_input": {},
            "result": {
                "success": True,
                "output": {
                    "stdout": f"ACME_STAGING_API_KEY={fake}\n",
                    "returncode": 0,
                },
            },
        }
        result = await mc.hooks.emit("tool:post", data)

        stdout = result.data["result"]["output"]["stdout"]
        assert fake not in stdout, f"secret must be redacted, got: {stdout!r}"
        assert REDACTED_SECRET in stdout
        assert result.data["redaction"] == {"applied": True, "rules": ["secrets"]}


# ---------------------------------------------------------------------------
# H-3: numeric tool output is NOT PII-clipped
# ---------------------------------------------------------------------------


class TestToolOutputNotPiiClipped:
    @pytest.mark.asyncio
    async def test_df_shaped_output_byte_identical(self):
        """Regression guard for \u00a73.1: pii-basic corrupts realistic tool
        output (df, byte counts, benchmark tables). Tool events must be
        scoped to `secrets` only, so this content survives untouched."""
        mc = await mount_and_ready()
        stdout = _df_shaped_stdout()
        data = {"result": {"output": {"stdout": stdout}}}

        result = await mc.hooks.emit("tool:post", data)

        assert result.data["result"]["output"]["stdout"] == stdout, (
            "numeric tool output must survive byte-identical -- "
            f"got: {result.data['result']['output']['stdout']!r}"
        )
        assert REDACTED_PII not in result.data["result"]["output"]["stdout"]


# ---------------------------------------------------------------------------
# H-4: tool:pre command string is masked
# ---------------------------------------------------------------------------


class TestToolPreCommandMasked:
    @pytest.mark.asyncio
    async def test_tool_pre_command_masked(self):
        mc = await mount_and_ready()
        fake = _fake_api_key()
        data = {"tool_input": {"command": f"echo ACME_API_KEY={fake}"}}

        result = await mc.hooks.emit("tool:pre", data)

        command = result.data["tool_input"]["command"]
        assert fake not in command, f"secret must be redacted, got: {command!r}"
        assert REDACTED_SECRET in command


# ---------------------------------------------------------------------------
# H-5: non-tool events keep both rules
# ---------------------------------------------------------------------------


class TestNonToolEventsKeepBothRules:
    @pytest.mark.asyncio
    async def test_session_start_keeps_pii_basic(self):
        mc = await mount_and_ready()
        data = {"message": "contact alice@example.com"}

        result = await mc.hooks.emit("session:start", data)

        assert REDACTED_PII in result.data["message"]
        assert result.data["redaction"]["rules"] == ["secrets", "pii-basic"]


# ---------------------------------------------------------------------------
# H-6: back-compat -- explicit skip_events restores old behavior
# ---------------------------------------------------------------------------


class TestBackCompatExplicitSkipEvents:
    @pytest.mark.asyncio
    async def test_explicit_skip_events_restores_old_behavior(self):
        mc = await mount_and_ready(config={"skip_events": ["tool:pre", "tool:post"]})

        registered = set(mc.hooks.list_handlers().keys())
        assert "tool:post" not in registered
        assert "tool:pre" not in registered


# ---------------------------------------------------------------------------
# H-7: event_rules override works
# ---------------------------------------------------------------------------


class TestEventRulesOverride:
    @pytest.mark.asyncio
    async def test_event_rules_override_enables_pii_basic_on_tool_post(self):
        mc = await mount_and_ready(
            config={"event_rules": {"tool:post": ["secrets", "pii-basic"]}}
        )
        data = {"result": {"output": {"stdout": "contact alice@example.com"}}}

        result = await mc.hooks.emit("tool:post", data)

        assert REDACTED_PII in result.data["result"]["output"]["stdout"]
        assert result.data["redaction"]["rules"] == ["secrets", "pii-basic"]


# ---------------------------------------------------------------------------
# H-8: event_rules merge, not replace
# ---------------------------------------------------------------------------


class TestEventRulesMergeNotReplace:
    @pytest.mark.asyncio
    async def test_narrowing_one_event_does_not_clobber_tool_defaults(self):
        mc = await mount_and_ready(config={"event_rules": {"llm:request": ["secrets"]}})
        fake = _fake_api_key()
        data = {"result": {"output": {"stdout": f"API_KEY={fake}"}}}

        result = await mc.hooks.emit("tool:post", data)

        # tool:post must still resolve to the DEFAULT_EVENT_RULES entry
        # (["secrets"]) -- the user's llm:request override must not silently
        # widen or clobber it.
        assert result.data["redaction"]["rules"] == ["secrets"]
        assert fake not in result.data["result"]["output"]["stdout"]


# ---------------------------------------------------------------------------
# H-9: empty resolved rules => no forged receipt
# ---------------------------------------------------------------------------


class TestEmptyResolvedRulesNoForgedReceipt:
    @pytest.mark.asyncio
    async def test_event_rules_empty_list_is_a_structural_noop(self):
        mc = await mount_and_ready(config={"event_rules": {"tool:post": []}})
        fake = _fake_api_key()
        data = {"result": {"output": {"stdout": f"API_KEY={fake}"}}}

        result = await mc.hooks.emit("tool:post", data)

        assert result.data.get("redaction") is None, (
            "event_rules: {'tool:post': []} must not stamp a redaction "
            f"marker at all -- got: {result.data.get('redaction')!r}"
        )
        # And, correspondingly, the value truly was NOT redacted.
        assert result.data["result"]["output"]["stdout"] == f"API_KEY={fake}"


# ---------------------------------------------------------------------------
# H-10: fail-closed unchanged on a tool event
# ---------------------------------------------------------------------------


class TestFailClosedOnToolEvent:
    @pytest.mark.asyncio
    async def test_scrub_exception_fails_closed_on_tool_post(self, monkeypatch, caplog):
        mc = await mount_and_ready()
        fake = _fake_api_key()

        def _boom(*args, **kwargs):
            raise RuntimeError("scrub exploded")

        monkeypatch.setattr(mod, "scrub", _boom)

        with caplog.at_level(logging.WARNING, logger="amplifier_module_hook_redaction"):
            result = await mc.hooks.emit(
                "tool:post", {"result": {"output": {"stdout": f"API_KEY={fake}"}}}
            )

        assert result.data == {"redaction": {"applied": False, "error": "scrub_failed"}}
        assert fake not in str(result.data)
        assert any(record.levelno == logging.WARNING for record in caplog.records)
