"""
Pytest configuration for module tests.

Provides the shared two-phase lifecycle helper (mount() + on_session_ready())
that every test needs, since hook-redaction no longer subscribes to any
events at mount() time -- subscription happens in on_session_ready(), once
the full kernel event set is discoverable (mirrors hook-context-intelligence's
mount()/on_session_ready() split).

Note on MockCoordinator: ``amplifier_core.MockCoordinator`` (the real
Rust-backed test coordinator) already provides working, non-mocked
implementations of ``register_capability``, ``get_capability``,
``collect_contributions`` (returns ``[]`` when no contributors are
registered), and ``hooks.register`` (returns a real unregister callable,
dispatch via ``hooks.emit`` works end-to-end). This was verified directly
against the installed amplifier-core before writing these tests. No custom
mock subclass is needed to get that behavior -- we use the real
MockCoordinator throughout, which gives these tests real dispatch-pipeline
coverage rather than call-recording coverage.

The amplifier-core pytest plugin provides fixtures automatically:
- module_path: Detected path to this module
- module_type: Detected type (provider, tool, hook, etc.)
- provider_module, tool_module, etc.: Mounted module instances
"""

from __future__ import annotations

from typing import Any

import pytest_asyncio
from amplifier_core import MockCoordinator

import amplifier_module_hook_redaction as mod


async def mount_and_ready(config: dict[str, Any] | None = None) -> MockCoordinator:
    """Run the full two-phase lifecycle: mount() then on_session_ready().

    Returns a fresh MockCoordinator with hook-redaction fully mounted and
    subscribed to its discovered event set (kernel ALL_EVENTS minus
    skip_events, by default).
    """
    mc = MockCoordinator()
    await mod.mount(mc, config)
    await mod.on_session_ready(mc)
    return mc


@pytest_asyncio.fixture
async def coordinator() -> MockCoordinator:
    """Fresh coordinator with hook-redaction mounted + subscribed (default config)."""
    return await mount_and_ready()
