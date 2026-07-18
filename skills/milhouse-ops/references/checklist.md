# Milhouse Ops Checklist

Before changing internals:

- Identify the affected component.
- Confirm the config shape.
- Confirm expected event model.
- Add fake fixtures.
- Keep spool-before-export behavior.
- Redact secrets, prompts, tokens, URLs with credentials, and user content.
- Update docs and examples.

Before reporting complete:

- `make test`
- `make docs-check`
- `make skill-check`
- list any unverified live behavior
