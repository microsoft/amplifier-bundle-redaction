#!/usr/bin/env python3
"""Zero-dependency contract check for the `redaction` library.

Run this AFTER installing the built wheel with `pip install --no-deps` into a
clean virtualenv (no other Amplifier packages present). It:

1. Imports `redaction` and exercises `mask_text`/`scrub` to prove the library
   works standalone.
2. Asserts `amplifier_core` (and any other `amplifier_*` package) is NOT
   importable / NOT present in `sys.modules` after that -- i.e. the library
   truly has zero runtime dependencies on the Amplifier ecosystem.
3. Asserts the INSTALLED distribution's own metadata declares zero runtime
   dependencies (`Requires-Dist`) -- this catches the case where a dependency
   was added to `pyproject.toml` but happens not to be imported at runtime
   (e.g. behind an `if TYPE_CHECKING` or an unused import), which (1) and (2)
   alone would miss.

Fails loud (non-zero exit, explicit message) on any violation. This is the
negative-dependency test referenced by the bundle's CI `zero-deps-contract`
job -- it must keep passing on every push/PR so the zero-deps contract can
never silently regress.
"""

from __future__ import annotations

import sys
from importlib.metadata import requires


def fail(message: str) -> None:
    print(f"ZERO-DEPS CHECK FAILED: {message}")
    sys.exit(1)


def main() -> None:
    try:
        import redaction
    except ImportError as e:
        fail(f"could not import redaction: {e}")
        return

    # Exercise the public API to prove it actually works standalone.
    masked = redaction.mask_text("key=AKIAIOSFODNN7EXAMPLE")
    if "[REDACTED:SECRET]" not in masked:
        fail(f"mask_text did not redact secret, got: {masked!r}")

    scrubbed = redaction.scrub({"email": "alice@example.com"})
    if scrubbed["email"] != "[REDACTED:PII]":
        fail(f"scrub did not redact PII, got: {scrubbed!r}")

    redactor = redaction.Redactor(redaction.RedactionConfig())
    if redactor.mask_text("alice@example.com") != "[REDACTED:PII]":
        fail("Redactor.mask_text did not redact PII")

    # Negative check: amplifier_core (or any amplifier_* package) must not be
    # importable as a side effect of importing/using redaction, and must not
    # have been dragged into sys.modules.
    poisoned = [
        name for name in sys.modules if name.split(".")[0].startswith("amplifier")
    ]
    if poisoned:
        fail(f"amplifier_* modules leaked into sys.modules: {poisoned}")

    try:
        import amplifier_core  # type: ignore[import-not-found]  # noqa: F401

        fail("amplifier_core is importable -- redaction is not dependency-free")
    except ImportError:
        pass  # expected: amplifier_core must NOT be installed/importable

    # Metadata check: the INSTALLED distribution's own Requires-Dist must be
    # empty. This catches a dependency added to pyproject.toml that isn't
    # actually imported at runtime (so checks 1/2 above wouldn't see it) --
    # e.g. added behind `if TYPE_CHECKING` or simply unused.
    declared = requires("amplifier-bundle-redaction")
    if declared:
        fail(f"distribution declares runtime dependencies (Requires-Dist): {declared}")

    print("ZERO-DEPS OK")
    sys.exit(0)


if __name__ == "__main__":
    main()
