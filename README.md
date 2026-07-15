# amplifier-bundle-redaction

Secrets and PII redaction for Amplifier -- and for anything else that just wants
to `import redaction`.

This repository is an Amplifier **bundle**: a zero-dependency masking library at
its root, a thin hook module that wires that library into the Amplifier event
lifecycle, and the behavior that mounts the hook with sane defaults.

```
amplifier-bundle-redaction/
├── redaction/                        # the library (import name: redaction)
├── modules/hook-redaction/            # the Amplifier hook (thin adapter)
├── behaviors/redaction.yaml           # the behavior that mounts the hook
├── bundle.md                          # bundle manifest (includes the behavior)
└── scripts/zero_deps_check.py         # the negative-dependency contract check
```

## Three ways to consume this repo

### 1. As a library (no Amplifier required)

`redaction` is a plain, stdlib-only Python package. It has no runtime
dependency on `amplifier_core` or anything else in the Amplifier ecosystem --
you can depend on it directly:

```toml
dependencies = [
    "amplifier-bundle-redaction @ git+https://github.com/microsoft/amplifier-bundle-redaction@main",
]
```

```python
from redaction import mask_text, scrub, RedactionConfig, Redactor

mask_text("key=AKIAIOSFODNN7EXAMPLE")
# -> "key=[REDACTED:SECRET]"

scrub({"email": "alice@example.com", "session_id": "abc-123"})
# -> {"email": "[REDACTED:PII]", "session_id": "abc-123"}   (session_id is allowlisted)
```

### 2. As an Amplifier bundle

Include this bundle in your `bundle.md` to get redaction mounted automatically:

```yaml
includes:
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main
```

Or include just the behavior (skip the foundation include):

```yaml
includes:
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main#subdirectory=behaviors/redaction.yaml
```

### 3. By mounting the hook directly

A core app can mount the hook module without going through the bundle
loader at all:

```python
from amplifier_module_hook_redaction import mount

await mount(coordinator, config={"rules": ["secrets", "pii-basic"]})
```

## Library API

| Symbol | Purpose |
|---|---|
| `mask_text(text, rules=DEFAULT_RULES) -> str` | Mask secrets/PII inside a single string. |
| `scrub(obj, rules=DEFAULT_RULES, allowlist=DEFAULT_ALLOWLIST, path="") -> Any` | Recursively scrub a JSON-like structure (dict/list/str), skipping allowlisted dotted paths. |
| `SECRET_PATTERNS` / `PII_PATTERNS` | The compiled regex patterns applied by `mask_text`. |
| `DEFAULT_RULES` | `("secrets", "pii-basic")` -- the default rule categories. |
| `DEFAULT_ALLOWLIST` | Frozen set of dotted structural field paths (e.g. `session_id`, `timestamp`) that are never redacted. |
| `RedactionConfig` | Frozen dataclass apps use to **extend** (never replace) the defaults with extra rules, allowlist entries, or patterns. |
| `Redactor` | A configured masker built from a `RedactionConfig`. `Redactor(RedactionConfig())` behaves identically to the free functions above with default arguments. |

**Extend, never replace.** `RedactionConfig.extra_secret_patterns` and
`extra_pii_patterns` are applied *on top of* the frozen defaults -- apps add to
the vetted pattern set, they don't get to turn it off:

```python
import re
from redaction import RedactionConfig, Redactor

config = RedactionConfig(
    extra_secret_patterns=[re.compile(r"\bacme-[A-Za-z0-9]{20,}")],
)
redactor = Redactor(config)
redactor.mask_text("token=acme-abcdefghijklmnopqrst")
# -> "token=[REDACTED:SECRET]"
```

## Hook configuration

The `hook-redaction` module (mounted by `behaviors/redaction.yaml`) accepts:

```yaml
hooks:
  - module: hook-redaction
    source: git+https://github.com/microsoft/amplifier-bundle-redaction@main#subdirectory=modules/hook-redaction
    config:
      rules: ["secrets", "pii-basic"]     # default
      allowlist: []                        # extra dotted paths, merged with DEFAULT_ALLOWLIST
      priority: 10                         # hook registration priority
      skip_events: ["tool:pre", "tool:post"]  # events whose data feeds back into LLM context
```

All fields are optional -- the frozen defaults (including the structural
`DEFAULT_ALLOWLIST`) are sufficient for typical use, which is why
`behaviors/redaction.yaml` ships with no `config:` block at all.

The hook subscribes to the canonical Amplifier event set (session, prompt,
plan, provider, LLM, tool, context, artifact, policy, and approval events) and
returns a `HookResult(action="modify")` with a redacted copy of the event data
-- it never mutates the original event in place.

## The zero-dependency contract

`redaction/` (the repo root package) has `dependencies = []` and imports
nothing from the Amplifier ecosystem. This is a load-bearing guarantee, not
an implementation accident -- consumers (like a standalone daemon) depend on
being able to `import redaction` without pulling in `amplifier_core`.

`scripts/zero_deps_check.py` proves this on every push/PR: it installs the
built wheel `--no-deps` into an isolated virtualenv, imports `redaction`,
exercises `mask_text`/`scrub`, and fails loudly if `amplifier_core` (or any
`amplifier_*` package) ever appears in `sys.modules`.

## Testing

Library tests (root):

```bash
uv sync
uv run pytest tests/ -q
```

Hook tests (the hook does not declare `amplifier_core` as a dependency --
it's host-provided at runtime, so tests supply it ad-hoc):

```bash
cd modules/hook-redaction
uv run --with "git+https://github.com/microsoft/amplifier-core@main" pytest tests/ -q
```

Zero-dependency contract, after building the wheel:

```bash
uv build
uv venv .check-venv
uv pip install --python .check-venv/bin/python --no-deps dist/*.whl
.check-venv/bin/python scripts/zero_deps_check.py
```

## Relationship to `amplifier-module-hooks-redaction`

This bundle replaces `amplifier-module-hooks-redaction` (the original module
repo, where the library lived nested under `modules/redaction/`). The old
repo's code is untouched and archived as-is; consumers are pointed here via a
deprecation notice fired by `amplifier-foundation`.
