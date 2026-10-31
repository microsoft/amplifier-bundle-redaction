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
import warnings
from copy import deepcopy

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


class TestCallableKeyToolDispatch:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("event", ["tool:pre", "tool:post"])
    async def test_callable_key_result_copy_and_secrets_only_receipt(self, event):
        mc = await mount_and_ready()
        fake = "PublicToolPayload" + "246813579"
        vendor = "ghp_" + "PublicToolVendor246813579"
        source = (
            "ranked = sorted(rows, key=helpers.signature)\n"
            "least = min(rows, key=public_sort_identity, default=0)\n"
            "most = max(rows, key=helpers.order.signature)\n"
            f'token = helpers.wrap(sorted("{fake}", key=public_sort_identity))\n'
            f"API_KEY={fake}\n"
            f'options = dict(key="{fake}")\n'
            f'vendor = "{vendor}"\n'
            "# contact person@example.com; count 12345678; date 2026-10-27\n"
        )
        numbered = "".join(
            f"  {number}\t{row}"
            for number, row in enumerate(source.splitlines(keepends=True), 101)
        )
        data = {
            "tool_name": "read_file",
            "result": {
                "output": {"content": source, "parts": [numbered], "returncode": 0}
            },
        }
        before = deepcopy(data)
        result = await mc.hooks.emit(event, data)
        expected = source.replace(fake, REDACTED_SECRET).replace(
            vendor, REDACTED_SECRET
        )
        expected_numbered = numbered.replace(fake, REDACTED_SECRET).replace(
            vendor, REDACTED_SECRET
        )
        assert isinstance(result.data["timestamp"], str)
        assert result.data == {
            "tool_name": "read_file",
            "timestamp": result.data["timestamp"],
            "result": {
                "output": {
                    "content": expected,
                    "parts": [expected_numbered],
                    "returncode": 0,
                }
            },
            "redaction": {"applied": True, "rules": ["secrets"]},
        }
        assert fake not in str(result.data["redaction"])
        assert vendor not in str(result.data["redaction"])
        assert "person@example.com" in result.data["result"]["output"]["content"]
        assert data == before
        assert result.data is not data
        assert result.data["result"] is not data["result"]
        assert result.data["result"]["output"] is not data["result"]["output"]
        assert (
            result.data["result"]["output"]["parts"]
            is not data["result"]["output"]["parts"]
        )


class TestCodeAwareToolDispatch:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("event", ["tool:pre", "tool:post"])
    @pytest.mark.parametrize("policy", ["always", "error"])
    async def test_invalid_escape_read_file_copy_is_quiet(self, event, policy):
        mc = await mount_and_ready()
        payload = _fake_api_key() + "\\" + "s"
        source = (
            "credentials: include\npattern: '" + "\\" + "s+''public'''\n"
            f'token = ns.wrap(ns.inner("{payload}"))\n'
            "# person@example.com; count 12345678\n"
        )
        numbered = "".join(
            f"  {number}\t{row}"
            for number, row in enumerate(source.splitlines(keepends=True), 71)
        )
        data = {
            "tool_name": "read_file",
            "result": {"output": {"parts": [source, {"content": numbered}]}},
        }
        before = deepcopy(data)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(policy)
            result = await mc.hooks.emit(event, data)
        assert isinstance(result.data["timestamp"], str)
        assert result.data == {
            "tool_name": "read_file",
            "timestamp": result.data["timestamp"],
            "result": {
                "output": {
                    "parts": [
                        source.replace(payload, REDACTED_SECRET),
                        {"content": numbered.replace(payload, REDACTED_SECRET)},
                    ]
                }
            },
            "redaction": {"applied": True, "rules": ["secrets"]},
        }
        assert payload not in str(result.data)
        assert data == before
        assert result.data is not data
        assert result.data["result"]["output"] is not data["result"]["output"]
        assert (
            result.data["result"]["output"]["parts"]
            is not data["result"]["output"]["parts"]
        )
        assert caught == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("event", ["tool:pre", "tool:post", "session:start"])
    async def test_nested_source_credentials_and_exact_receipt(self, event):
        mc = await mount_and_ready()
        source = (
            'key = json.dumps(payload, sort_keys=True, separators=(",", ":"))\n'
            'key = (record["major"], record["minor"])\n'
            "field_key = next(iter(mapping))\n"
            "{key: mapping[key] for key in reversed(mapping)}\n"
            "sorted(rows, key=operator.itemgetter(1))\n"
        )
        secret = "Synthetic" + "OnlyCredential"
        vendor = "ghp_" + "SyntheticVendor123456"
        mixed = (
            source
            + f'api_key = ns.wrap("{secret}")\n'
            + f'password = "{secret}" if flag else "{secret}"\n'
            + f'text = "{vendor}"\n'
            + "# contact person@example.com\n"
        )
        numbered = "".join(
            f"  {number}\t{row}"
            for number, row in enumerate(mixed.splitlines(keepends=True), 71)
        )
        data = {
            "tool_name": "read_file",
            "result": {
                "output": {"parts": [mixed, {"content": numbered}], "returncode": 0}
            },
        }
        before = deepcopy(data)
        result = await mc.hooks.emit(event, data)
        expected_plain = mixed.replace(secret, REDACTED_SECRET).replace(
            vendor, REDACTED_SECRET
        )
        expected_numbered = numbered.replace(secret, REDACTED_SECRET).replace(
            vendor, REDACTED_SECRET
        )
        rules = ["secrets"]
        if event == "session:start":
            rules.append("pii-basic")
            expected_plain = expected_plain.replace("person@example.com", REDACTED_PII)
            expected_numbered = expected_numbered.replace(
                "person@example.com", REDACTED_PII
            )
        assert isinstance(result.data["timestamp"], str)
        assert result.data == {
            "tool_name": "read_file",
            "timestamp": result.data["timestamp"],
            "result": {
                "output": {
                    "parts": [expected_plain, {"content": expected_numbered}],
                    "returncode": 0,
                }
            },
            "redaction": {"applied": True, "rules": rules},
        }
        assert data == before
        assert result.data is not data
        assert result.data["result"]["output"] is not data["result"]["output"]
        assert (
            result.data["result"]["output"]["parts"]
            is not data["result"]["output"]["parts"]
        )


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
    async def test_mixed_source_and_credentials_exact_copy(self):
        mc = await mount_and_ready()
        fake = _fake_api_key()
        vendor = "ghp_" + "SyntheticOnly123456"
        source = "ranked = sorted(rows, key=lambda item: (-item[1], item[0]))\n"
        stdout = (
            source
            + f"AUTH=none; API_KEY={fake} done\n"
            + f"options = dict(key='{fake}')\n"
            + f"example = '{vendor}'\n"
        )
        data = {
            "tool_name": "bash",
            "result": {"output": {"stdout": stdout, "returncode": 0}},
        }
        before = deepcopy(data)

        result = await mc.hooks.emit("tool:post", data)

        expected_stdout = (
            source
            + f"AUTH=none; API_KEY={REDACTED_SECRET} done\n"
            + f"options = dict(key='{REDACTED_SECRET}')\n"
            + f"example = '{REDACTED_SECRET}'\n"
        )
        # The real coordinator adds its own dispatch timestamp.
        assert isinstance(result.data["timestamp"], str)
        assert result.data == {
            "tool_name": "bash",
            "timestamp": result.data["timestamp"],
            "result": {"output": {"stdout": expected_stdout, "returncode": 0}},
            "redaction": {"applied": True, "rules": ["secrets"]},
        }
        assert data == before
        assert result.data is not data
        assert result.data["result"]["output"] is not data["result"]["output"]

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
