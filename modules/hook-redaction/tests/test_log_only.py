"""Qualified-host hook mode, using the real Rust registry and public fixtures."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest
from amplifier_core import HookResult, MockCoordinator, events

import amplifier_module_hook_redaction as mod
from redaction import scrub_for_log

APPROVAL = "redaction.log_only.v1"
ACTIVE = "redaction.log_only.active.v1"
STATE = "redaction._hook_state"
ALL_EVENTS = getattr(events, "ALL_EVENTS")
VENDOR = "ghp_" + "SyntheticPublicFixtureOnly"
FABRICATED = "fabricated_" + "public_fixture_value"
EMAIL = "synthetic@example.invalid"
SOURCE = (
    "# public synthetic source; Unicode: \N{SNOWMAN}\r\n"
    f'password = "{FABRICATED}"\r\n'
    f'vendor = "{VENDOR}"\r\n'
    "ranked = sorted(rows, key=namespace.synthetic_reference)\r\n"
    f"# contact {EMAIL}\r\n"
)
ERROR = (
    "Log-only redaction requires default policy; migrate custom redaction "
    "configuration to log sinks before initialization"
)


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def payload():
    return {
        "session_id": "synthetic-session",
        "timestamp": "2026-10-28T12:34:56Z",
        "result": {"output": {"content": SOURCE, "parts": [SOURCE], "returncode": 0}},
        "context": [{"role": "user", "content": SOURCE}],
        "password": FABRICATED,
        "email": EMAIL,
    }


async def approved(config=None):
    coordinator = MockCoordinator()
    assert type(coordinator.hooks).__name__ == "RustHookRegistry"
    coordinator.register_capability(APPROVAL, 1)
    cleanup = await mod.mount(coordinator, config)
    await mod.on_session_ready(coordinator)
    return coordinator, cleanup


def test_static_literal_compatibility_marker():
    tree = ast.parse(Path(mod.__file__).read_text())
    values = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "__log_redaction_api_version__"
            for target in node.targets
        )
    ]
    assert len(values) == 1
    assert isinstance(values[0], ast.Constant)
    assert type(values[0].value) is int
    assert values[0].value == mod.__log_redaction_api_version__ == 1


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        {"rules": ["secrets", "pii-basic"]},
        {"allowlist": []},
        {"skip_events": []},
        {"priority": 10},
        {"priority": -20},
        {"priority": 900},
        {"event_rules": {}},
        {"event_rules": {"tool:pre": ["secrets"]}},
        {"event_rules": {"tool:post": ["secrets"]}},
        {
            "rules": ["secrets", "pii-basic"],
            "allowlist": [],
            "priority": 10,
            "skip_events": [],
            "event_rules": {"tool:pre": ["secrets"], "tool:post": ["secrets"]},
        },
    ],
    ids=[f"default-{index}" for index in range(12)],
)
@pytest.mark.asyncio
async def test_default_policy_accepted_without_handlers(config):
    before = fingerprint(config)
    assert mod.validate_log_only_config(config) is None
    coordinator, cleanup = await approved(config)
    assert coordinator.get_capability(STATE) == {"mode": "logs-only"}
    active = coordinator.get_capability(ACTIVE)
    assert type(active) is int and active == 1
    assert not coordinator.hooks.list_handlers()
    assert fingerprint(config) == before
    await cleanup()


@pytest.mark.parametrize(
    "config",
    [
        [],
        False,
        {"rules": []},
        {"rules": ["secrets"]},
        {"rules": ["pii-basic", "secrets"]},
        {"rules": ["secrets", "pii-basic", "custom"]},
        {"rules": ("secrets", "pii-basic")},
        {"rules": None},
        {"allowlist": ["custom"]},
        {"allowlist": None},
        {"skip_events": ["tool:post"]},
        {"skip_events": None},
        {"priority": True},
        {"priority": "10"},
        {"event_rules": None},
        {"event_rules": []},
        {"event_rules": {"llm:request": ["secrets", "pii-basic"]}},
        {"event_rules": {"tool:pre": []}},
        {"event_rules": {"tool:pre": ["secrets", "pii-basic"]}},
        {"event_rules": {"tool:post": ("secrets",)}},
        {"unknown": FABRICATED},
    ],
    ids=[f"migration-{index}" for index in range(21)],
)
@pytest.mark.asyncio
async def test_custom_policy_rejected_statically_before_ack(config):
    coordinator = MockCoordinator()
    coordinator.register_capability(APPROVAL, 1)
    with pytest.raises(ValueError) as preflight:
        mod.validate_log_only_config(config)
    with pytest.raises(ValueError) as mounted:
        await mod.mount(coordinator, config)
    assert str(preflight.value) == str(mounted.value) == ERROR
    assert mounted.value.__context__ is None
    assert mounted.value.__cause__ is None
    assert coordinator.get_capability(STATE) is None
    assert coordinator.get_capability(ACTIVE) is None
    assert not coordinator.hooks.list_handlers()


@pytest.mark.asyncio
async def test_approved_path_never_constructs_or_discovers_masking(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("logs-only mode must not construct or run legacy masking")

    monkeypatch.setattr(mod, "_build_handler", forbidden)
    monkeypatch.setattr(mod, "_discover_events", forbidden)
    monkeypatch.setattr(mod, "scrub", forbidden)
    coordinator, cleanup = await approved()
    await mod.on_session_ready(coordinator)
    assert not coordinator.hooks.list_handlers()
    await cleanup()


@pytest.mark.parametrize("event", sorted(ALL_EVENTS))
@pytest.mark.asyncio
async def test_rust_dispatch_preserves_authorized_content_bytes(event):
    coordinator, cleanup = await approved()
    source = payload()
    before = fingerprint(source)
    result = await coordinator.hooks.emit(event, source)
    assert result.action == "continue"
    assert fingerprint(source) == before
    content = result.data["result"]["output"]["content"]
    assert (
        hashlib.sha256(content.encode()).digest()
        == hashlib.sha256(SOURCE.encode()).digest()
    )
    # Core owns timestamps and adds request_id to llm:request. Existing content
    # remains verbatim; no redaction receipt is added.
    assert set(result.data) - set(source) <= {"request_id"}
    assert fingerprint({k: result.data[k] for k in source if k != "timestamp"}) == (
        fingerprint({k: v for k, v in source.items() if k != "timestamp"})
    )
    await cleanup()


@pytest.mark.parametrize("approval", [None, False, True, 0, 2, "1", 1.0])
@pytest.mark.asyncio
async def test_unapproved_legacy_mode_still_masks_and_discovers_events(approval):
    coordinator = MockCoordinator()
    if approval is not None:
        coordinator.register_capability(APPROVAL, approval)
    cleanup = await mod.mount(coordinator)
    await mod.on_session_ready(coordinator)
    assert set(coordinator.hooks.list_handlers()) == set(ALL_EVENTS)
    assert coordinator.get_capability(ACTIVE) is None
    source = payload()
    result = await coordinator.hooks.emit("tool:post", source)
    assert VENDOR not in result.data["result"]["output"]["content"]
    assert "[REDACTED:SECRET]" in result.data["result"]["output"]["content"]
    assert result.data["redaction"] == {"applied": True, "rules": ["secrets"]}
    assert fingerprint(source) == fingerprint(payload())
    await cleanup()


@pytest.mark.asyncio
async def test_legacy_late_contributions_preserve_full_51_event_surface():
    coordinator = MockCoordinator()
    contributions = [f"synthetic:event-{index}" for index in range(8)]
    coordinator.register_capability("observability.events", contributions)
    cleanup = await mod.mount(coordinator)
    await mod.on_session_ready(coordinator)
    assert set(coordinator.hooks.list_handlers()) == set(ALL_EVENTS) | set(
        contributions
    )
    assert len(coordinator.hooks.list_handlers()) == len(ALL_EVENTS) + 8
    await cleanup()


@pytest.mark.asyncio
async def test_logs_only_does_not_disable_unrelated_modify_hook():
    coordinator, cleanup = await approved()

    async def legitimate_modifier(event, data):
        return HookResult(action="modify", data={**data, "unrelated": "modified"})

    unregister = coordinator.hooks.register(
        "tool:post", legitimate_modifier, priority=5, name="synthetic-legitimate-hook"
    )
    result = await coordinator.hooks.emit("tool:post", payload())
    assert result.data["unrelated"] == "modified"
    assert fingerprint(result.data["context"]) == fingerprint(payload()["context"])
    await cleanup()
    assert "tool:post" in coordinator.hooks.list_handlers()
    unregister()


@pytest.mark.asyncio
async def test_approval_is_per_coordinator_and_cleanup_clears_only_owned_state():
    parent, cleanup_parent = await approved()
    child = MockCoordinator()
    cleanup_child = await mod.mount(child)
    await mod.on_session_ready(child)
    assert child.get_capability(APPROVAL) is None
    assert child.get_capability(ACTIVE) is None
    assert "tool:post" in child.hooks.list_handlers()
    assert parent.get_capability(ACTIVE) == 1
    await cleanup_child()
    assert child.get_capability(STATE) is None
    await cleanup_parent()
    await cleanup_parent()  # Idempotent.
    assert parent.get_capability(STATE) is None
    assert parent.get_capability(ACTIVE) is None
    assert parent.get_capability(APPROVAL) == 1  # Approval remains host-owned.
    parent.register_capability(APPROVAL, None)
    cleanup_legacy = await mod.mount(parent)
    await mod.on_session_ready(parent)
    assert "tool:post" in parent.hooks.list_handlers()
    assert parent.get_capability(ACTIVE) is None
    await cleanup_legacy()


@pytest.mark.asyncio
async def test_late_approval_does_not_retroactively_skip_legacy_handlers():
    coordinator = MockCoordinator()
    cleanup = await mod.mount(coordinator)
    coordinator.register_capability(APPROVAL, 1)
    await mod.on_session_ready(coordinator)
    assert "tool:post" in coordinator.hooks.list_handlers()
    assert coordinator.get_capability(ACTIVE) is None
    await cleanup()


@pytest.mark.asyncio
async def test_failed_remount_cannot_leave_stale_active_acknowledgement():
    coordinator, cleanup = await approved()
    with pytest.raises(ValueError):
        await mod.mount(coordinator, {"allowlist": ["unsupported-custom-policy"]})
    assert coordinator.get_capability(ACTIVE) is None
    await cleanup()


@pytest.mark.asyncio
async def test_rust_dispatch_keeps_source_raw_while_real_jsonl_sink_masks(tmp_path):
    # Standalone hook CI has no sibling sink dependency. The cross-repo source
    # run must provide the candidate logger on sys.path and execute, not skip.
    sink = pytest.importorskip(
        "amplifier_module_hooks_logging",
        reason="real sink seam requires the separate hooks-logging source package",
    )
    assert sink.scrub_for_log is scrub_for_log
    coordinator, cleanup = await approved()
    log_path = tmp_path / "synthetic-events.jsonl"
    await sink.mount(coordinator, {"session_log_template": str(log_path)})
    await sink.on_session_ready(coordinator)
    source = payload()
    before = fingerprint(source)
    result = await coordinator.hooks.emit("tool:post", source)
    assert fingerprint(result.data["context"]) == fingerprint(source["context"])
    assert (
        hashlib.sha256(result.data["result"]["output"]["content"].encode()).digest()
        == hashlib.sha256(SOURCE.encode()).digest()
    )
    assert fingerprint(source) == before
    records = log_path.read_text().splitlines()
    assert len(records) == 1
    persisted = json.loads(records[0])
    for value in (FABRICATED, VENDOR, EMAIL):
        assert value not in records[0]
    assert persisted["data"]["password"] == "[REDACTED:SECRET]"
    assert persisted["data"]["email"] == "[REDACTED:PII]"
    assert "[REDACTED:SECRET]" in persisted["data"]["result"]["output"]["content"]
    assert coordinator.get_capability(ACTIVE) == 1
    await cleanup()
