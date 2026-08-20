# amplifier-bundle-redaction

An [Amplifier](https://github.com/microsoft/amplifier) bundle that masks secrets
(API keys, tokens, JWTs) and basic PII (emails, phone numbers) in logs and the
live session event stream — **and** a standalone, zero-dependency `redaction`
library you can `import` from any Python program, with no Amplifier runtime
present.

The scrubbing logic lives in one place (the `redaction` library at the repo
root) and is consumed three ways: as a plain library, as an auto-mounted
Amplifier behavior, or as a directly-mounted hook.

---

## What's in the box

| Component | Path | What it is |
|-----------|------|------------|
| **`redaction` library** | `redaction/` (repo-root wheel) | Zero-dependency, stdlib-only masking core. `import redaction` needs **no** Amplifier runtime. |
| **`hook-redaction` module** | `modules/hook-redaction/` | A thin Amplifier hook that mounts the library against the event stream. |
| **redaction behavior** | `behaviors/redaction.yaml` | Wires the hook into any bundle or app that composes it. |
| **bundle manifest** | `bundle.md` | Thin root bundle: includes foundation + this bundle's own behavior. |

The distribution name is `amplifier-bundle-redaction`; the import name is
`redaction` (dist ≠ import, on purpose).

---

## Quick Start — install into an app

### Add as a layered behavior (recommended)

Layer the redaction behavior on top of your **active** app bundle with the
Amplifier [app-cli](https://github.com/microsoft/amplifier-app-cli). `--app`
composes it onto your current app **without** pulling foundation in as a
dependency — exactly the same pattern as the context-intelligence bundle:

```bash
amplifier bundle add \
  "git+https://github.com/microsoft/amplifier-bundle-redaction@main#subdirectory=behaviors/redaction.yaml" \
  --app
```

Every session under that app now scrubs secrets/PII from its event stream
automatically — no configuration required (the frozen defaults are enough).

### Or install standalone (full root bundle, includes foundation)

```bash
amplifier bundle add "git+https://github.com/microsoft/amplifier-bundle-redaction@main"
amplifier bundle use redaction
```

### Or compose it from another bundle's `bundle.md`

```yaml
includes:
  # the whole bundle (pulls foundation too):
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main
  # …or just the behavior (no foundation):
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main#subdirectory=behaviors/redaction.yaml
```

Redaction is on-by-default for everything composing `amplifier-foundation`, so
in most Amplifier setups you already have it and don't need to add anything.

---

## Use as a library — programmatic redaction (no Amplifier required)

`redaction` is a plain, stdlib-only Python package. Depend on it directly from
any tool, service, or daemon — it will `import` cleanly in an environment with
**no** `amplifier_core` (or anything else Amplifier) installed:

```toml
# pyproject.toml
dependencies = [
    "amplifier-bundle-redaction @ git+https://github.com/microsoft/amplifier-bundle-redaction@main",
]
```

### Mask a string

```python
from redaction import mask_text

mask_text("key=AKIAIOSFODNN7EXAMPLE contact alice@example.com")
# -> "key=[REDACTED:SECRET] contact [REDACTED:PII]"
```

### Scrub a whole JSON-like structure

`scrub()` walks dicts/lists/strings recursively and leaves allowlisted
structural fields (like `session_id`, `timestamp`) untouched:

```python
from redaction import scrub

scrub({"email": "alice@example.com", "session_id": "abc-123"})
# -> {"email": "[REDACTED:PII]", "session_id": "abc-123"}
```

### Extend the defaults (never replace them)

Apps add their own patterns/allowlist entries **on top of** the vetted frozen
defaults via `RedactionConfig` — you extend the built-in `SECRET_PATTERNS` /
`PII_PATTERNS` / `DEFAULT_ALLOWLIST`, you don't get to turn them off:

```python
import re
from redaction import Redactor, RedactionConfig

redactor = Redactor(RedactionConfig(
    extra_secret_patterns=(re.compile(r"\bacme-[A-Za-z0-9]{20,}"),),
    extra_allowlist=frozenset({"correlation_id"}),
))
redactor.mask_text("token=acme-abcdefghijklmnopqrst")  # -> "token=[REDACTED:SECRET]"
```

`Redactor(RedactionConfig())` is behaviorally identical to the free functions
`mask_text` / `scrub` with default arguments.

### `NAME=value` credential assignments

`SECRET_ASSIGNMENT_PATTERNS` masks the **value** of a `NAME=value` assignment
while preserving the **name** — `API_KEY=[REDACTED:SECRET]`, not
`[REDACTED:SECRET]`. It's anchored on the name's shape (a conventional
credential word like `key`, `token`, `secret`, `auth`, `password`, … as a
whole segment, never a substring — `PATH`/`MONKEY`/`KEYBOARD` don't match),
never on the value's entropy, so dashless UUIDs, git SHAs, and base64 blobs
under a benign name stay intact:

```python
from redaction import mask_text

mask_text("ACME_STAGING_API_KEY=abcd1234efgh5678")
# -> "ACME_STAGING_API_KEY=[REDACTED:SECRET]"
```

**The default vocabulary is name-anchored, so a credential variable whose
name carries no conventional sensitive word is NOT matched** —
`mask_text("MY_SERVICE_PERSONAL=abcd1234efgh5678")` is unchanged, because
nothing in the name says "credential" and a value-anchored (entropy) rule
would break dashless-UUID/git-SHA values that must survive. Close this gap
per-deployment with `secret_assignment_pattern()` — build a pattern for your
own vocabulary and add it via `RedactionConfig.extra_secret_assignment_patterns`
(never by replacing the defaults):

```python
from redaction import Redactor, RedactionConfig, secret_assignment_pattern

redactor = Redactor(RedactionConfig(
    extra_secret_assignment_patterns=[
        secret_assignment_pattern(["personal", "spark2"]),
    ]
))
redactor.mask_text("CONTEXT_INTELLIGENCE_PERSONAL=abcd1234efgh5678")
# -> "CONTEXT_INTELLIGENCE_PERSONAL=[REDACTED:SECRET]"
```

### Library API

| Symbol | Purpose |
|---|---|
| `mask_text(text, rules=DEFAULT_RULES) -> str` | Mask secrets/PII inside a single string. |
| `scrub(obj, rules=DEFAULT_RULES, allowlist=DEFAULT_ALLOWLIST, path="") -> Any` | Recursively scrub a JSON-like structure, skipping allowlisted dotted paths. |
| `RedactionConfig` | Frozen dataclass to **extend** the defaults (extra rules / allowlist / patterns). |
| `Redactor` | A configured masker built from a `RedactionConfig`. |
| `SECRET_PATTERNS` / `PII_PATTERNS` | The compiled regex patterns applied by `mask_text`. |
| `SECRET_ASSIGNMENT_PATTERNS` | `NAME=value` patterns that mask only the value, preserving the name. |
| `SECRET_NAME_WORDS` | The default name-vocabulary (`key`, `token`, `secret`, `auth`, …) `SECRET_ASSIGNMENT_PATTERNS` is built from. |
| `secret_assignment_pattern(words)` | Build a `NAME=value` pattern for a custom vocabulary — the sanctioned way to close the name-gap above. |
| `DEFAULT_RULES` | `("secrets", "pii-basic")` — the default rule categories. |
| `DEFAULT_ALLOWLIST` | Frozen set of structural field paths never redacted (`session_id`, `timestamp`, …). |

---

## Use by mounting the hook directly

A core app can mount the hook module without the bundle loader at all:

```python
from amplifier_module_hook_redaction import mount

await mount(coordinator, config={"rules": ["secrets", "pii-basic"]})
```

### Hook configuration

The `hook-redaction` module (mounted by `behaviors/redaction.yaml`) accepts —
all fields optional, defaults are sufficient, which is why the behavior ships
with no `config:` block:

```yaml
config:
  rules: ["secrets", "pii-basic"]          # default rule categories
  allowlist: []                            # extra dotted paths, merged with DEFAULT_ALLOWLIST
  priority: 10                             # hook registration priority
  skip_events: []                          # events excluded from redaction entirely (empty by default)
  event_rules:                             # per-event rule override, merged OVER these defaults
    tool:pre: ["secrets"]
    tool:post: ["secrets"]
```

The hook subscribes to the canonical Amplifier event set (session, prompt, plan,
provider, LLM, tool, context, artifact, policy, approval) and returns a
`HookResult(action="modify")` with a redacted **copy** — it never mutates the
original event in place.

`skip_events` defaults to `[]` — every event, including `tool:pre`/`tool:post`,
is redacted by default. Tool events run under `event_rules`' `["secrets"]`
scope only (not `pii-basic`): the guarded phone-number pattern eats digit/space
runs in ordinary tool stdout (`df` output, byte counts, benchmark tables),
which would corrupt content the model needs verbatim. A shell-printed secret
in tool output IS masked, deliberately — a redacted tool result is what the
model reads, so a credential printed by `echo NAME=value` is not carried
forward and re-embedded into every subsequent LLM request. Setting
`skip_events` explicitly still wins over the default, so a deployment that
needs the old behavior can restore it with
`skip_events: ["tool:pre", "tool:post"]`. `event_rules` entries are merged
**over** the defaults per event key (extend, never replace) — narrowing one
event (e.g. `event_rules: {"llm:request": ["secrets"]}`) does not silently
widen or clobber the `tool:pre`/`tool:post` defaults. The redaction receipt
(`data["redaction"]`) stamps the RESOLVED per-event rules, not the global
`rules` list — a `tool:post` receipt reads
`{"applied": true, "rules": ["secrets"]}`.

---

## The zero-dependency contract

`redaction/` has `dependencies = []` and imports nothing from the Amplifier
ecosystem. This is a load-bearing guarantee, not an accident: standalone
consumers (e.g. a daemon) rely on `import redaction` working without
`amplifier_core` present. CI enforces that `redaction/` stays stdlib-only on
every push.

---

## Development

```bash
# Library tests (zero-dependency core)
uv sync && uv run pytest tests/

# Hook tests — amplifier_core is host-provided at runtime, supplied ad-hoc here
cd modules/hook-redaction
uv run --with "git+https://github.com/microsoft/amplifier-core@main" pytest tests/

# Full bundle validation (structural + BundleRegistry load + build)
scripts/validate-full.sh
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md) for the
repo's conventions, gates, and the DTU end-to-end testing workflow.

---

## Relationship to `amplifier-module-hooks-redaction`

This bundle replaces `amplifier-module-hooks-redaction` (the original module
repo, where the library was nested under `modules/redaction/`). The old repo's
code is untouched and archived as-is; consumers are pointed here via a
deprecation notice fired by `amplifier-foundation`.

## Contributing

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.