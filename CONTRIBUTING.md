# Contributing

Thanks for contributing to **amplifier-bundle-redaction**. This repo has a few
specific conventions — read them before you change the furniture.

**Read [`AGENTS.md`](AGENTS.md) first.** It is the authoritative, always-loaded
guidance: the repo layout, the **zero-dependency contract** for `redaction/`, the
**frozen public surface** external consumers depend on, and the host-injected
`amplifier_core` boundary for the hook. Everything below is the short version.

## Layout

- `redaction/` — the zero-dependency masking **library** (the repo-root wheel;
  `import redaction`). stdlib-only, `dependencies = []`.
- `modules/hook-redaction/` — the thin Amplifier **hook** that mounts the library
  on the event stream. Depends on the root library `@git+…@main` (no `#subdirectory`).
- `behaviors/redaction.yaml` — the bundle's **behavior**; wires the hook.
- `bundle.md` — thin root manifest. `scripts/` — tooling. `tests/` — library suite;
  `modules/hook-redaction/tests/` — hook suite.

## Branches & commits

- Branch names: `feat/…`, `fix/…`, `docs/…`, `chore/…`.
- Conventional-commit subjects (`feat(hook): …`, `fix(library): …`, `docs(readme): …`).
- Keep unrelated changes in separate commits (code / docs / deps).

## Dev setup

Uses [`uv`](https://docs.astral.sh/uv/). From the repo root or a module dir:

```bash
uv sync
```

## Testing — the gates

Two buckets, not five: **CI** (below) runs on every push in GitHub Actions —
fast and deterministic. **DTU** (further down) is something you run locally
when you touch the hook or behavior; it is never run in GitHub Actions
(too heavy for CI).

Unit tests are the floor, not the ceiling. Run and paste evidence for:

```bash
# Library suite (zero-dependency core)
uv run pytest tests/
uv run ruff check . && uv run ruff format --check .
uv run pyright

# Hook suite — needs amplifier_core (host-injected; not a declared dependency)
cd modules/hook-redaction
uv run --with "git+https://github.com/microsoft/amplifier-core@main" pytest tests/
```

### The zero-dependency contract (this repo's signature rule)

The whole point of the library-at-root split is that `import redaction` resolves
with **no Amplifier runtime present** — the team-pulse daemon depends on it. Any
change touching `redaction/` must prove the library stays clean:

```bash
uv build --wheel
uv venv /tmp/clean
uv pip install --python /tmp/clean/bin/python --no-deps dist/*.whl
/tmp/clean/bin/python scripts/zero_deps_check.py    # must print ZERO-DEPS OK, exit 0
```

`scripts/zero_deps_check.py` imports and *calls* `mask_text`/`scrub` and asserts
`amplifier_core` never enters `sys.modules`. Never add a non-stdlib import to
`redaction/` — CI's `zero-deps-contract` job enforces this on every push.

## Full bundle validation

Before opening a PR that touches bundle structure, run the repo's **full**
validation (not the bare recipe, which self-downgrades to `structural_only`):

```bash
scripts/validate-full.sh
```

It builds a throwaway `uv` venv with `hatchling` + `amplifier-foundation` +
`amplifier-core` so the validator runs at `validation_mode: full` — which enables
the two checks that matter most for this repo: BundleRegistry resolution of the
behavior include, and the library-wheel build check. Expect `PASS`, 0 errors.

If your change altered bundle structure, the validator regenerates `bundle.dot` /
`bundle.png`; commit them (it flags `BUNDLE_DOT_STALE` otherwise).

## End-to-end (DTU) testing — run locally, not in CI

If you changed the **hook** (`modules/hook-redaction/`) or the **behavior**
(`behaviors/redaction.yaml`) — the event-stream wiring, the behavior include,
the foundation switch-over, or the `git+…@main` dependency resolution — prove
it with a **real Digital Twin Universe (DTU) run**, not just a passing unit
test. Run this **locally**; it does not run in GitHub Actions (too heavy for
CI). The DTU serves your local branch(es) through **Gitea** (so the bundle
install resolves to *your* code) and drives a real Amplifier CLI session
composing foundation — confirming the hook mounts, redaction actually scrubs
the event stream, and (for the switch-over) the deprecation notice fires.
Live testing here has caught things green unit tests did not.

## Pull requests

Open PRs against `main` and **populate every item in the PR template** from real
evidence — paste it, or mark `N/A — <reason>`. Never pre-check a box you cannot
back. State what you deliberately did **not** touch (e.g. the `redaction/` library
for a hook-only change; the old `amplifier-module-hooks-redaction` repo, which is
deprecated, not edited).

## Capturing lessons

If your work surfaces a lasting lesson — a footgun, an invariant, a new gate —
write it back into the file that owns it (`AGENTS.md` for pitfalls/commands, the PR
template for a new gate) as it lands. Offer the entry and get agreement; keep
what's worth keeping.
