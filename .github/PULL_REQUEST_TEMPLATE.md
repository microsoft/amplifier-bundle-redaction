<!--
Populate every item from REAL evidence. For each: paste the evidence, or mark
`N/A — <reason>`. Never pre-check a box you can't back — an unchecked box reads
as "I forgot"; a checked box you can't back reads as "passed" when it didn't.
Read AGENTS.md before you start — it carries this repo's load-bearing rules
(the zero-dependency contract, the frozen public surface, the host-injected
amplifier_core boundary).
-->

## Summary

<!-- What changed and WHY. One paragraph. Link the issue/PR this builds on, if any. -->

## Scope / guardrails

<!-- What you deliberately did NOT touch, and why. State it explicitly:
- Did you keep the `redaction/` library zero-dependency (no amplifier_core / no
  non-stdlib imports)? If your change is hook- or bundle-only, say the library is
  untouched.
- Did you preserve the frozen public surface (`mask_text(text, rules)` / `scrub`)
  the team-pulse daemon (C2) depends on? Additive-only changes to RedactionConfig/
  Redactor are fine; signature breaks are not.
- The old `amplifier-module-hooks-redaction` repo is deprecated, not edited —
  confirm you did not touch it. -->

## What Changed

- [ ] Library (`redaction/`)
- [ ] Hook (`modules/hook-redaction/`)
- [ ] Behavior (`behaviors/redaction.yaml`) / `bundle.md`
- [ ] CI / packaging / scripts

## Zero-deps contract (load-bearing)

<!-- The whole point of the library-at-root split. If you touched `redaction/`,
paste the negative-dependency proof; if you didn't, mark N/A. -->

- [ ] Built wheel installs `--no-deps` into a clean venv
- [ ] `import redaction` and call `mask_text`/`scrub` works standalone
- [ ] `amplifier_core` does NOT enter `sys.modules` — `scripts/zero_deps_check.py` exits 0
      <paste the `ZERO-DEPS OK` line / negative-dependency test output>

## Verification

- [ ] **Library tests** pass — `uv run pytest tests/` (paste count)
- [ ] **Hook tests** pass — from `modules/hook-redaction/`, `uv run --with "git+https://github.com/microsoft/amplifier-core@main" pytest tests/` (paste count)
- [ ] **`ruff check` + `ruff format --check`** clean
- [ ] **`pyright`** clean (0 errors)
- [ ] **Full bundle validation** PASS — `scripts/validate-full.sh` → `validation_mode: full`
      (paste verdict + error/warning count; the bare recipe self-downgrades to `structural_only`)

## DTU end-to-end (if you changed the hook/behavior)

<!-- CI (above) runs on every push in GitHub Actions. The DTU does not -- it's
too heavy for CI, so it's a local-only check. If you changed the hook
(modules/hook-redaction/) or the behavior (behaviors/redaction.yaml) -- the
event-stream wiring, the behavior include, the foundation switch-over, or the
`git+…@main` dependency resolution -- run the DTU locally and paste the real
result, not just a passing unit test. -->

- [ ] If you changed the hook/behavior, ran the DTU locally and pasted the result
      (instance id + which checks passed), or `N/A — hook/behavior not touched`

## Docs & diagrams

- [ ] `bundle.dot` / `bundle.png` regenerated if bundle structure changed
      (the validator flags `BUNDLE_DOT_STALE`; `source_hash` must match)
- [ ] `README.md` / `AGENTS.md` updated if a contract or layout changed
- [ ] Convention files updated if this surfaced a lasting lesson (`AGENTS.md`, this template)

## Rollback

<!-- How to revert if this regresses. For the foundation switch-over: single-YAML
revert. For most changes here: trivially revertable via git. -->

## Notes / follow-ups

<!-- Non-blocking follow-ups, deferred items, coordination needed
(e.g. the daemon C2 repoint is a separate follow-on). -->
