# Bot-only beta.1 R3 — Telegram gateway/plugin wiring

R3 completes the main Hermes Telegram gateway wiring needed before the
separate Approval Bot transport is implemented.

Changes:

- passes `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ALLOWED_USERS` to upstream Hermes;
- `./hermesctl bot telegram` stores the Telegram token through hidden input;
- mutation allowlisted users are automatically included in the Telegram gateway allowlist;
- `./hermesctl up` enables `control-plane-chatops` before gateway startup;
- `./hermesctl bot check` diagnoses plugin discovery without printing secrets;
- restores CI validation on `dev/**` pushes;
- keeps Kubernetes/Helm execution disabled by default.

The separate Approval Bot Telegram callback transport is still the next beta.1 batch.
