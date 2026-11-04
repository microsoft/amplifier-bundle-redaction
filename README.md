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

Older/unqualified hosts scrub secrets/PII from the shared event stream
automatically. A qualified host uses the log-only lifecycle below instead;
this candidate source change is not a live installation.

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

config = RedactionConfig(
    extra_secret_patterns=(re.compile(r"\bacme-[A-Za-z0-9]{20,}"),),
    extra_allowlist=frozenset({"correlation_id"}),
)
redactor = Redactor(config)
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

config = RedactionConfig(
    extra_secret_assignment_patterns=[
        secret_assignment_pattern(["personal", "spark2"]),
    ],
)
redactor = Redactor(config)
redactor.mask_text("CONTEXT_INTELLIGENCE_PERSONAL=abcd1234efgh5678")
# -> "CONTEXT_INTELLIGENCE_PERSONAL=[REDACTED:SECRET]"
```

Default assignment masking recognizes a bounded set of Python computations
(qualified/nested calls, lookups, result tuples, conditionals and dictionary
comprehensions) in complete logical statements, including consistently numbered
source views. This is syntax-based relief, **not a Python-source exemption**.
Vendor matches and ordinary assignments inside strings/comments still mask.
Sensitive result literals and long bare data names remain maskable, including
both conditional branches and raw string-construction fragments. Simple
unqualified calls remain conservative as containing values. One narrow exception
preserves a static reference in the exact `key=` role of bare `sorted`, `min`
and `max` calls: a name or a name-rooted attribute chain, such as
`sorted(rows, key=helpers.signature)`. `sorted` requires exactly one positional
argument and only `key`/`reverse` keywords. `min`/`max` require at least one
positional argument and only `key`/`default` keywords; `default` requires exactly
one positional argument. Starred arguments, keyword unpacking and duplicate
keywords do not qualify. This adds no exemption for literals, calls or lambdas
as key values; their existing policy is unchanged. Other data arguments,
`reverse`, `default` and nested sensitive fields still inherit sensitivity from
a containing sensitive value. Overlapping masks win over reference relief.
Neither `.sort` nor qualified calls such as `builtins.sorted` gain this new
role; global bare `key=`, `API_KEY=` and `dict(key=...)` remain unchanged.
Explicit extra patterns remain stricter.

This heuristic is not secret recognition: call-function/attribute references,
lookup selectors and control expressions do not inherit an outer sensitive
name. Callee names and attribute chains are static syntax, not runtime proof:
shadowed built-ins can qualify, while differently named aliases do not gain the
new role. A non-vendor identifier can survive in that role even if it holds a
secret. Non-vendor plaintext with computation-like syntax can therefore survive.
Some legitimate variables and long literal field labels still mask. Malformed,
unsupported or over-limit input uses existing regex masking and inherits its
gaps, including some constructed literals and secrets split across events.
Analysis is limited to 65,536 characters, 1024 lines, 8192 tokens/nodes and statement
characters, depth 48, with cooperative 25 ms checks, not a hard CPU deadline.

### Log-copy protection (Phase A, standalone API v1)

Version 0.2.0 adds `scrub_for_log` and `LogRedactingFormatter` for independent
observability copies. The behavior, `mask_text`, `scrub` and `Redactor` are
unchanged. The hook now also supports the qualified-host lifecycle below;
unapproved hosts retain legacy masking. These candidate source changes are
not a live cutover or end-to-end qualification of verbatim
source/tool/model/native-resume content with masked logging copies.

```python
import logging
from redaction import LogRedactingFormatter, LogRedactionError, scrub_for_log

try:
    log_copy = scrub_for_log({"password": "fabricated_example"})
except LogRedactionError:
    pass  # Drop the affected log record. Never write the original as fallback.

handler = logging.StreamHandler()
handler.setFormatter(LogRedactingFormatter(logging.Formatter("%(message)s")))
```

`scrub_for_log(obj, *, config=None)` accepts only built-in JSON scalar, list
and string-keyed dict types, plus tuples normalized to lists. It returns a
detached snapshot, including exempt containers. Cycles, unsupported types
(including subclasses), non-string keys and non-finite floats raise a static
`LogRedactionError(ValueError)` without the input or an exception chain.
Normalize application objects before calling; never stringify unknown objects
as a recovery path.

Default secret, assignment and PII rules always run, even if `config.rules`
narrows them. Extensions retain legacy precedence: default vendor patterns,
default assignment callbacks, default PII, extra secret patterns, extra
assignment callbacks, extra PII. Assignment callbacks use ordinary regex
masking, **not** AST analysis or source-looking exemptions. Sensitive dict
names use the existing assignment-pattern grammar; nonempty string values
mask regardless of length, including strings nested below sensitive fields.
Assignment numeric/date shape checks and scalar types retain prior behavior;
PII rules still apply to strings outside shape-protected datetime fields.
Established `[REDACTED:SECRET]` and `[REDACTED:PII]` markers retain their
categories in strict assignment and sensitive-field processing, so default
masking does not recategorize them on later passes. Extra custom patterns can
intentionally change markers and are not covered by that stability guarantee.

The log-copy profile also inspects detection-only views of escaped strings.
This covers conventional repr/JSON backslash and quote escaping, control escapes,
and valid hexadecimal/Unicode escapes without evaluating or parsing objects.
If any view triggers strict masking, the **entire original string** becomes a
redaction marker. This deliberately sacrifices inner serialized text and layout;
the surrounding structured event and its exempt scalar join IDs remain intact.
Decoded text is never returned. Plain strings without recognized escapes retain
their previous strict masking behavior; the legacy library APIs are unchanged.

Inspection is bounded to four normalization sweeps and 1,048,576 Python
characters per eligible string. Underlying escapes also consume sweeps, so this
is not an unconditional four-wrapper guarantee. Over-budget inputs fail closed:
`scrub_for_log` raises its static error and the formatter returns its failure
marker. Unknown/malformed escapes are not decoded. These bounds limit the added
normalization work, not arbitrary custom-regex execution time. Arbitrary
encodings, unknown secrets and cross-event fragments remain outside this scope.

Default allowlist paths are unioned with `config.allowlist` and exempt only
scalar values. Dicts, lists and normalized tuples at those paths are traversed
and scrubbed, not treated as exempt subtrees. For example, a dict incorrectly
placed in `data.working_dir` cannot hide nested credentials or PII. Repeated
containers are copied independently; an alias never transfers an exemption.
Identifier keys (including extra identifier keys) exempt only scalar values
at every depth, never whole dict/list/tuple payloads. Containers under those
keys are copied and scrubbed, including repeated aliases. Datetime keys
(including extras) remain shape-gated. These exemptions preserve structural
integrity, **not** secrecy: a secret in an exempt scalar survives. Dictionary
schema keys themselves are retained. Unknown/unconventionally named secrets
and values split across separate calls are not universally detected.

`LogRedactingFormatter(inner=None, *, include_traceback=True, config=None)`
shallow-copies the record, clears cached exception text only on the copy,
uses the inner formatter, then masks its complete output, including formatted
args, exceptions, stack text and custom fields. Raw formatted text has **no**
JSON allowlist/identifier exemption. With `include_traceback=False`, exception
info, cached exception text and stack info are cleared on the copy. The
original record's fields remain intact; custom inner formatters must not
mutate objects reachable through those fields. Any format or masking failure
returns only `[REDACTED:LOG_FAILURE]`, without internal logging or raw fallback.

`LOG_REDACTION_API_VERSION = 1` identifies this additive sink API.

### Library API reference

| Symbol | Purpose |
|---|---|
| `mask_text(text, rules=DEFAULT_RULES) -> str` | Mask secrets/PII inside a single string. |
| `scrub(obj, rules=DEFAULT_RULES, allowlist=DEFAULT_ALLOWLIST, path="") -> Any` | Recursively scrub a JSON-like structure, skipping allowlisted dotted paths. |
| `RedactionConfig` | Frozen dataclass to **extend** the defaults (extra rules / allowlist / patterns). |
| `Redactor` | A configured masker built from a `RedactionConfig`. |
| `scrub_for_log(obj, *, config=None) -> Any` | Strict detached log snapshot; default protection cannot be narrowed. |
| `LogRedactionError` | Static `ValueError` on log-snapshot failure; drop the affected log record. |
| `LogRedactingFormatter` | Inner formatter wrapper; masks complete output without changing the original record. |
| `LOG_REDACTION_API_VERSION` | Sink API contract version (`1`). |
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

### Qualified-host log-only lifecycle (hook API v1)

The hook package exports the static literal `__log_redaction_api_version__ = 1`.
A new host must validate all known selected log sinks for API v1 **before
session initialization**, validate redaction configuration, then register the
session-local integer capability `redaction.log_only.v1 = 1`. This approval is
host-owned: it is not a config flag, is not persisted, and is not automatically
inherited. A child host must qualify its own coordinator.

When approved, `mount()` constructs no masking handler, stores private state
with `mode="logs-only"`, and acknowledges with integer
`redaction.log_only.active.v1 = 1`. `on_session_ready()` registers no redaction
event handlers. Cleanup clears the acknowledgement and private state, not the
host-owned approval. Authorized tool/context/model data pass unchanged by
this hook; tool permissions and unrelated modifying hooks still apply.
Independent log sinks must mask their own copies with mandatory secrets and
PII defaults. There is no syntax exception or global hook skip.

The host must refuse model/tool execution if the static marker or active
acknowledgement is missing. A host requesting log-only mode must never fall
back to legacy masking. This is a compatibility handshake, not malicious
module authentication. Real CLI/server, save/resume and child-session
qualification remain required before declaring the full boundary delivered.

`validate_log_only_config(config) -> None` is a pure exported validator; it
raises a static `ValueError` requiring sink-side migration on unsupported
configuration. `mount()` runs the same validator before acknowledging approval.
The first cutover accepts only:

- `None` or a plain dict containing only `rules`, `allowlist`, `priority`,
  `skip_events`, `event_rules`.
- Omitted `rules` or exactly `["secrets", "pii-basic"]`, in that order.
- Omitted `allowlist`/`skip_events` or empty lists.
- Omitted `event_rules`, `{}`, or any subset of `tool:pre`/`tool:post` mapped
  to exactly `["secrets"]`. These are the legacy effective defaults, **not**
  instructions to narrow sink protection.
- Omitted `priority` or any integer (not bool). Priority is ignored in this
  mode because there is no event handler.

Non-default rules, allowlists, event skips/overrides, unknown keys, or invalid
types fail rather than being silently ignored. Custom policies have no route
to sink policy in this increment and require migration before initialization.
Users are not asked to change settings or disable the hook.

### Legacy hook configuration (unapproved hosts)

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

Without host approval, the hook subscribes to the canonical Amplifier event set (session, prompt, plan,
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