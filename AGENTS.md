# amplifier-bundle-redaction — Repo Conventions

This repo is a bundle with **three layers**: a zero-dependency library at the
root, a thin hook adapter under `modules/`, and the behavior that wires them
together. Keep these layers separate — that separation is the entire point of
this repo's shape.

## Layout invariant

```
redaction/                  # LIBRARY — root wheel, import name `redaction`, dependencies = []
modules/hook-redaction/     # HOOK — thin Amplifier adapter, depends on the root wheel
behaviors/redaction.yaml    # BEHAVIOR — mounts the hook with sane defaults
bundle.md                   # BUNDLE MANIFEST — includes foundation + this bundle's behavior
```

Do not collapse these back into a nested `modules/redaction/` layout. The
library moved to the repo root deliberately (see `amplifier-module-hooks-redaction`
for the "before" shape this replaced) so that a consumer can `import redaction`
out-of-process without going through Amplifier at all.

## The zero-dependency invariant (non-negotiable)

`redaction/` must never gain a runtime dependency — not on `amplifier_core`,
not on any other `amplifier_*` package, not on any third-party library.
`dependencies = []` in the root `pyproject.toml` is a contract, not a default.

Before adding any import to `redaction/__init__.py`, ask: does this belong in
the hook (`modules/hook-redaction/`) instead? Amplifier-specific concerns
(events, `HookResult`, `ModuleCoordinator`) belong in the hook. Pure masking
logic (patterns, `mask_text`, `scrub`) belongs in the library.

Verify with `scripts/zero_deps_check.py` after any change to `redaction/`:

```bash
uv build
uv venv .check-venv
uv pip install --python .check-venv/bin/python --no-deps dist/*.whl
.check-venv/bin/python scripts/zero_deps_check.py
```

This same check runs as the `zero-deps-contract` CI job on every push/PR —
it must stay green.

## Extend, never replace

`RedactionConfig`'s `extra_secret_patterns` / `extra_pii_patterns` /
`allowlist` exist so consumer apps can **add** rules beside the frozen
defaults (`SECRET_PATTERNS`, `PII_PATTERNS`, `DEFAULT_ALLOWLIST`). Do not add
an API surface that lets a caller **replace** the defaults outright — that
would let one misconfigured app silently disable protection that every other
consumer relies on.

## Testing

Two independent test suites — they exercise different dependency shapes and
must be run separately:

```bash
# Library tests (root) — must pass with dependencies = []
uv sync
uv run pytest tests/ -q

# Hook tests — the hook does NOT declare amplifier_core as a dependency
# (host-provided at runtime), so tests supply it ad-hoc via `uv run --with`
cd modules/hook-redaction
uv run --with "git+https://github.com/microsoft/amplifier-core@main" pytest tests/ -q
```

Both suites, plus the build and zero-deps-contract checks, run in
`.github/workflows/ci.yml` on every push/PR to `main`.

## Relationship to the old module repo

`amplifier-module-hooks-redaction` is the predecessor of this bundle. Its code
is untouched and archived as-is — this repo is not a fork or a shim over it.
Do not add compatibility imports or re-export shims pointing back at the old
module; consumers migrate by changing their dependency to this repo.

## Source of truth for behavior fidelity

If you're modifying the hook's event subscription list or default config,
treat the *current* `modules/hook-redaction/amplifier_module_hook_redaction/__init__.py`
as ground truth — not any design doc, PR description, or prior commit
message. Those can drift; the code is what actually runs.
