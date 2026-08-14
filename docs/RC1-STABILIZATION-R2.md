# RC.1 stabilization R2 — 9router combo bootstrap shell fix

This update supersedes RC.1 stabilization R1 on `dev/0.5.10-rc.1`. Do not tag `v0.5.10-rc.1` yet.

## Runtime failure found while validating R1

R1 correctly reached the 9router bootstrap phase and reused the existing managed API key, but `./hermesctl up` then returned to the shell before creating any routing combos. The 9router dashboard still showed **No combos yet**, and the strengthened router probe correctly failed a real completion with HTTP 404.

Observed sequence:

```text
==> starting 9router bootstrap phase
[ok] managed 9router API key is already valid
# command exited here
```

The R1 combo reconciliation plan was generated, but each action file was written without a trailing newline. The loop parsed those files with Bash `read` while `hermesctl` runs under `set -e`. Bash populates the variables but returns status 1 when EOF is reached before a newline, so the first `read` terminated the whole command before the `case` statement could create `ai`, `combo-fast`, `combo-standard`, or `combo-strong`.

## R2 fix

R2 makes the combo action parser safe under `set -e`:

- action/count plan files are newline-terminated;
- the `read` operation explicitly tolerates EOF and the following `case` still validates the parsed action;
- malformed/empty actions still fail closed via the existing invalid-action branch;
- no credential, bot-only authorization, ChangeSet, approval, or execution boundary is weakened.

R2 also removes trailing whitespace from the handover so `git diff --check` is clean.

## R1 fixes retained

R2 retains all intended R1 behavior:

- Hermes config uses `api_key: ${OPENAI_API_KEY}` and never writes the actual Smart Router client secret to `config.yaml`;
- `bot check` validates the environment-key reference plus an authenticated Hermes-container request to Smart Router;
- 9router bootstrap fetches the current OpenCode catalog and builds the free `oc/*-free` / `oc/big-pickle` pool;
- `ai` is refreshed by Hermes Control Plane when the catalog is available;
- `combo-fast`, `combo-standard`, and `combo-strong` are seeded only when absent and preserved afterward for operator customization;
- OmniRoute remains on native `auto/best-*` routing and gets no synthetic 9router combos;
- `router probe` performs a real streaming chat completion;
- duplicate-key cleanup preserves the original ambiguity exit status;
- `router cleanup-keys` is documented in CLI help.

## Required live validation

Keep execution disabled.

```bash
./hermesctl execution status
./hermesctl up
./hermesctl router probe
./hermesctl bot check
```

On the first successful R2 startup with an empty 9router combo database, expected lines include:

```text
[ok] created 9router combo ai
[ok] created 9router combo combo-fast
[ok] created 9router combo combo-standard
[ok] created 9router combo combo-strong
[ok] 9router Hermes routing combos ready (... current OpenCode free model(s))
```

The 9router dashboard should then show all four combos. `./hermesctl router probe` should end with a real completion success through Smart Router and 9router.

Run `./hermesctl up` a second time. Expected behavior is to refresh `ai` and preserve the three existing tier combos rather than replacing operator configuration.

After routing passes, send the Telegram read-only request:

```text
Show me the Kubernetes targets managed by Hermes Control Plane.
```

Only after routing and Telegram pass should this checkpoint be committed on `dev/0.5.10-rc.1`.
