---
bundle:
  name: redaction
  version: 1.0.0
  description: Secrets/PII redaction library, hook, and behavior for Amplifier

includes:
  - bundle: git+https://github.com/microsoft/amplifier-foundation@main
  - bundle: redaction:behaviors/redaction
---

# Redaction Bundle

Masks secrets and PII in Amplifier event data before it reaches logs, the
terminal, or persisted session artifacts.

## What's Here

- **`redaction/`** -- the zero-dependency, stdlib-only masking library
  (`mask_text`, `scrub`, `RedactionConfig`, `Redactor`). Importable standalone
  with no `amplifier_core` dependency -- consumer apps can `import redaction`
  directly without going through Amplifier at all.
- **`modules/hook-redaction/`** -- a thin Amplifier hook adapter that wraps the
  library and wires it into the event lifecycle. It reimplements no masking
  logic of its own; all scrubbing comes `from redaction`.
- **`behaviors/redaction.yaml`** -- the behavior that mounts the hook with
  sane defaults. Included automatically above.

## Usage

Include this bundle to get redaction on by default:

```yaml
includes:
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main
```

Or include just the behavior, without the foundation include:

```yaml
includes:
  - bundle: git+https://github.com/microsoft/amplifier-bundle-redaction@main#subdirectory=behaviors/redaction.yaml
```

Or depend on the library directly (no Amplifier involved at all):

```toml
dependencies = [
    "amplifier-bundle-redaction @ git+https://github.com/microsoft/amplifier-bundle-redaction@main",
]
```

```python
from redaction import mask_text, scrub, RedactionConfig, Redactor
```

See [README.md](README.md) for the full library API, hook configuration
options, and the zero-dependency contract this bundle guarantees.
