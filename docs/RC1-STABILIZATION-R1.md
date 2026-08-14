# RC.1 stabilization R1 — Hermes auth + 9router routing bootstrap

This update is for `dev/0.5.10-rc.1`. `v0.5.10-beta.1` is already published and must not be moved or rewritten.

## Problems proven in beta acceptance testing

1. Hermes could reach Smart Router, but `./hermesctl bot model-sync` cleared the model-level API-key reference from `/opt/data/config.yaml`. Telegram requests therefore reached Smart Router without authentication and failed with HTTP 401.
2. Router Gateway expects the 9router models `ai`, `combo-fast`, `combo-standard`, and `combo-strong`, but Hermes Control Plane did not provision those routing objects.
3. `./hermesctl router probe` only checked `/v1/models`, so it could report an end-to-end success while a real chat completion failed.
4. R8 duplicate-key cleanup safely failed closed, but shell negation hid the helper's original ambiguity exit code and prevented the dedicated error message.
5. `router cleanup-keys` existed but was missing from CLI help.

## Runtime evidence before this patch

- Hermes container `OPENAI_API_KEY` -> Smart Router `/v1/models`: HTTP 200.
- With `api_key: ${OPENAI_API_KEY}` restored manually, the previous Smart Router 401 disappeared.
- 9router OpenCode Free model `oc/deepseek-v4-flash-free` produced HTTP 200 through the managed 9router API key.
- 9router dashboard had no configured combos, confirming the missing bootstrap step.
- `opencode-go/*` models were not usable without a credential and are not used as the default free bootstrap pool.

## R1 behavior

### Hermes authentication

`ensure_hermes_router_model` now writes only this reference to Hermes config:

```yaml
api_key: ${OPENAI_API_KEY}
```

The actual Smart Router client secret remains in the Hermes process environment. It is not copied into `config.yaml`.

`./hermesctl bot check` now verifies:

- the ChatOps plugin is mounted/discovered;
- Hermes model configuration contains the environment-variable reference;
- `OPENAI_API_KEY` exists inside the Hermes container;
- an authenticated Hermes-container request to Smart Router `/v1/models` returns HTTP 200.

### 9router routing reconciliation

When 9router is selected, `hermesctl` now uses 9router's authenticated management API to reconcile the routing objects Router Gateway already expects:

- `ai`
- `combo-fast`
- `combo-standard`
- `combo-strong`

It fetches `https://opencode.ai/zen/v1/models`, selects model IDs ending in `-free` plus `big-pickle`, prefixes them with `oc/`, and uses that current free pool as the bootstrap list.

Ownership rules:

- `ai` is Hermes-managed and refreshed when the live catalog is available.
- tier combos are seeded only when missing;
- after creation, tier combo model lists are operator-owned and are preserved on later starts;
- user-created unrelated combos are never modified;
- if the OpenCode catalog is temporarily unreachable and all required combos already exist, startup preserves and verifies the existing combos instead of failing solely because of the external catalog outage;
- if required combos are missing and the catalog cannot be obtained, reconciliation fails rather than starting with known-broken routing.

Configuration:

```dotenv
NINEROUTER_AUTO_PROVISION_COMBOS=true
NINEROUTER_OPENCODE_CATALOG_URL=https://opencode.ai/zen/v1/models
```

OmniRoute is unchanged and continues using native `auto/best-*` routing aliases. No 9router-style combos are provisioned for OmniRoute.

### Stronger diagnostics

`./hermesctl router probe` now performs a real streaming chat completion through:

```text
client -> Smart Router -> Router Gateway -> selected router -> provider/model
```

A successful model-list request alone is no longer labeled an end-to-end model-route success.

### Duplicate-key cleanup

The R8 safety behavior remains intact. The shell now captures the original `managed_key_stale_ids` exit status without `!`, so the explicit ambiguous-current-key path reports the intended fail-closed message.

CLI help now documents:

```text
router cleanup-keys [scope]
```

## Required local test sequence

Keep execution disabled while validating routing:

```bash
./hermesctl version set 0.5.10-rc.1
./hermesctl execution disable
./scripts/verify.sh
./hermesctl up
./hermesctl router probe
./hermesctl bot check
./hermesctl execution status
```

Expected 9router bootstrap on first run includes creation of missing `ai` and tier combos. A second `./hermesctl up` should refresh `ai` but report existing tier combos as preserved.

Then verify in the 9router dashboard that the four required combos exist, and send the Telegram read-only request:

```text
Show me the Kubernetes targets managed by Hermes Control Plane.
```

The request must not return Smart Router 401 and must not fail because `ai` is absent.

After that, run:

```bash
./hermesctl router cleanup-keys all
./hermesctl router cleanup-keys all
```

The second run should be idempotent and normally report zero stale duplicates.

Do not enable Kubernetes execution until routing, Telegram read-only behavior, and bot authorization checks are clean.
