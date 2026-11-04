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

Run `ruff check .` against the explicit `E4`, `E7`, `E9`, `F` selection in the
root `pyproject.toml`. This preserves the project's previously used 59-rule
policy across Ruff default changes; adopting a broader rule set is a separate
maintenance change. This is not a Ruff version pin or a claim that all newer
default rules pass. Keep `ruff format --check .` as a separate gate, including
Markdown code blocks when the installed formatter supports them.

## Relationship to the old module repo

`amplifier-module-hooks-redaction` is the predecessor of this bundle. Its code
is untouched and archived as-is — this repo is not a fork or a shim over it.
Do not add compatibility imports or re-export shims pointing back at the old
module; consumers migrate by changing their dependency to this repo.

## Known limitations

Secrets/PII **split across multiple streaming events** are NOT redacted. Each
event (e.g. a `content_block:end` delta) is scrubbed independently -- there is
no cross-event buffer -- and a regex only matches a complete token within a
single payload. If a secret happens to straddle two streamed chunks, neither
chunk contains the whole token and `scrub()` finds nothing to mask in either.

This is a known, accepted limitation, not a bug to fix reactively. Cross-event
buffering (accumulate text across chunks, scan the buffer, re-emit) is a
deliberate future change if/when it's wanted -- it is not implemented, and
there is no test asserting this case is handled (there is nothing correct to
assert against yet).

`SECRET_ASSIGNMENT_PATTERNS` (the `NAME=value` credential masker) is
**name-anchored, not entropy-anchored** -- it fires on a conventional
credential word (`key`, `token`, `secret`, `auth`, `password`, ...) present as
a whole segment of the assignment's NAME. A credential variable whose name
carries no such word (e.g. `MY_SERVICE_PERSONAL`, `ACME_SPARK2`) is **not**
matched by default -- nothing in the name says "credential", and a
value-anchored (entropy) rule is deliberately closed off: it would break the
shipped guarantee that dashless UUIDs, git SHAs, sha256 digests, and base64
blobs under a benign name survive untouched (`tests/test_token_patterns.py`,
`tests/test_assignment_patterns.py::TestAdditionalRequired::test_t_name_gap_regression_lock`).
The sanctioned closure for a deployment with unconventionally-named
credential variables is `secret_assignment_pattern(words)` passed via
`RedactionConfig.extra_secret_assignment_patterns` -- never a value-entropy
rule, and never edit the frozen `SECRET_NAME_WORDS` default in place (that
would change behavior for every consumer, not just the one deployment that
needs it).

**Footgun:** never apply a global `re.IGNORECASE` to an assignment pattern
built by `secret_assignment_pattern()`. Case-insensitivity must stay scoped to
the sensitive-word group only (`(?i:...)`) -- a global flag makes the
camelCase-hump guard (`(?=[A-Z])`) match lowercase too, and a benign
`monkey=...` assignment would start matching.

**Quote footgun:** `(?P<q>["']?)` participates even without a quote, so a
conditional `(?(q)...)` always takes its quoted branch. Make the group itself
optional and condition the closing backreference too. Fix value boundaries,
not with a broad source-code exemption: credential literals in source still
need masking, and bare `key=pick_rank` remains ambiguous and maskable.

## Source of truth for behavior fidelity

Phase A adds a separate, stdlib-only log-copy API in `redaction/_log.py`
(`LOG_REDACTION_API_VERSION = 1`). The hook now supports qualified-host log-only
mode below. These are candidate sources, not a live cutover; do not claim
verbatim source/tool/model/native-resume delivery from library/hook tests alone.
Keep all prior library behavior and the unapproved legacy hook path.

`scrub_for_log` validates and detaches JSON primitives/containers (tuples become
lists), even beneath structural exemptions. Never return raw input on failure:
raise a static `LogRedactionError` without exception context/chain. Always apply
default secret/PII rules and ordinary assignment callbacks, with no AST/source
relief. Extend allowlist paths by union, but exempt only scalars: containers
at allowlisted paths must be traversed and scrubbed, including aliased values.
Identifier exemptions (including extra keys) are also scalar-only: traverse and
scrub dict/list/tuple values under identifier keys, including repeated aliases.
Preserve scalar join IDs and shape-gated datetimes. Sensitive-name
dict fields use the existing pattern grammar, not a new credential vocabulary;
mask nonempty nonnumeric/nondatetime strings even below the old length floor.
Schema keys and structurally exempt secrets survive; this is not universal
unknown-secret detection.
Keep exact SECRET/PII markers stable in strict assignment callbacks and
sensitive-field masking; do not recategorize PII as SECRET on later default
passes. Custom patterns may intentionally change markers. Do not change the
legacy callback/APIs to implement strict-profile behavior. Run independent
`tests/test_log_profile_regressions.py` as well as the full suites.

Serialized string protection is log-profile-only. Inspect detection views of
recognized quote, backslash, control and numeric escapes from the ORIGINAL
string, not a partially masked baseline. Apply the same ordered strict pipeline
to every changed view. An alarm replaces the whole opaque string with a marker;
never return decoded text or reconstruct inner JSON. SECRET wins across views;
explicit extensions can still transform the chosen marker. Plain text retains
the previous strict behavior. Keep legacy `mask_text`/`scrub` untouched.
Allow at most four normalization sweeps and 1,048,576 Python characters for
eligible strings; exhaustion fails closed through the existing public errors.
This is not an unconditional four-wrapper guarantee: underlying escapes also
consume sweeps. Unknown/malformed escapes are preserved in detection views.
Whole-string masking can remove diagnostic detail and inner serialized IDs;
only actual outer structural fields retain their existing scalar exemptions.

`LogRedactingFormatter` shallow-copies the record, clears exception cache only
on the copy, formats through the inner formatter, then masks the entire output
without JSON field exemptions. `include_traceback=False` clears exception info,
cached exception text and stack info on the copy. Do not log inside failures;
return only `[REDACTED:LOG_FAILURE]`. Custom formatters must not mutate nested
record objects.

For a restricted no-install run, reuse an existing interpreter:
`./.venv/bin/python -B -m pytest -q -p no:cacheprovider`.
This runs the library suite, including `tests/test_log_redaction.py`; it does
not replace the clean-wheel zero-dependency gate above. If new environments
or installs are prohibited, report that gate NOT RUN rather than waiving it.

The default assignment phase uses bounded `tokenize`/`ast` span analysis;
never evaluate input or regenerate source. Preserve the frozen pattern factory
and the ordinary callback as the atomic whole-input fallback. Unsupported
subtrees grant no partial containing-slot relief. Fallback retains baseline
gaps; it is not a stronger literal-protection guarantee.
Collect complete data obligations before source-trivia guards for relief.
Verified string-prefix letters are syntax, not payload; preserve them while
masking raw payloads, including on a second pass.

Source-analysis footguns: a simple unqualified call is not enough evidence;
long bare data names stay maskable at every result nesting level. Collect
nested sensitive slots independently of outer regex matches. Group implicit
and explicit string concatenation by raw payload length and mask every
contributing part. Preserve original UTF-8 character mapping, line endings and
number prefixes. Function/attribute references, lookup selectors and control
roles are intentionally outside inherited sensitivity, not proved secret-free.

Callable-key footgun: only an AST-owned `key` reference in a validated bare
`sorted`/`min`/`max` call gains the new role. Use the same predicate for the
keyword slot and enclosing data obligations; never exempt the whole call or
delete masks afterward. Collect nested slots before relief guards; masks win
over overlaps. This static rule does not prove a built-in is unshadowed or a
reference secret-free. Public synthetic tests are not private-source review
or evidence that masked private expressions now survive.

Syntax-role footgun: a dictionary-comprehension key gains relief only as a
direct Name bound in its own synchronous generator's binding positions
(Name, Tuple/List elements, Starred value), never nested target expressions.
This never disables result-data obligations. Initialized reference-only
annotations relieve only whole regex candidates covered by mapped annotation
syntax; partial overlaps keep the full baseline mask. Quoted payloads, comments
and annotation-only data gain no relief. Never subtract from mandatory masks,
elide annotations and rematch `=`, or relax simple calls globally.

If you're modifying the hook's event subscription list or default config,
treat the *current* `modules/hook-redaction/amplifier_module_hook_redaction/__init__.py`
as ground truth — not any design doc, PR description, or prior commit
message. Those can drift; the code is what actually runs.

## Qualified-host hook mode

Hook metadata `__log_redaction_api_version__ = 1` must remain a static literal
assignment for host AST preflight. Only integer `redaction.log_only.v1 = 1`
approval on this coordinator enables log-only mount; bool is not API v1.
The host validates all known selected sinks and config before initialization.
The hook does not create, persist or propagate approval. Children qualify
independently; this is compatibility checking, not module authentication.

Approved mount validates config, constructs no handler, stores private state
`mode="logs-only"` and registers integer `redaction.log_only.active.v1 = 1`.
Ready registers no redaction events. Cleanup clears ack/state, not host approval.
The requesting host must refuse execution when marker/ack is missing, never
fall back to legacy. Do not disable unrelated hooks or tool permissions.

`validate_log_only_config` accepts None/plain dict, only the five legacy keys:
exact default rules list; empty allowlist/skip lists; empty event_rules or any
subset of tool:pre/tool:post with ["secrets"]; any integer priority (ignored).
Omitted values use defaults. Reject all other keys, values or types with a
static migration error, never raw config values. No custom sink-policy route
exists yet. Unapproved hosts keep their existing custom-config behavior.

`modules/hook-redaction/tests/test_log_only.py` uses real RustHookRegistry.
Its JSONL seam test needs the separate candidate hooks-logging source on
process sys.path; standalone CI without that package explicitly skips it.
For qualified local verification it must execute and pass, not skip. Reuse
existing interpreters/Core and inject source paths only within the test process;
do not install, change live settings, or claim full CLI/server/resume E2E.
