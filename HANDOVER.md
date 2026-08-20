# Hermes Control Plane — 0.5.11 development handover

**Stable base:** `v0.5.10` — frozen / do not recreate
**Active development branch:** `dev/0.5.11`
**Frozen dev.1 boundary:** `1764cad667717ec78156af8f9f3fcc30eb84c1f5`
**Frozen dev.2 boundary:** `a71b03a54ed2f619d3605c0c08d46de35ad5911c`, tag `v0.5.11-dev.2`
**Frozen dev.3 boundary:** `8547c44de4f6e8116d70f2690b50a50c895eba34`, tag `v0.5.11-dev.3`
**Frozen dev.4 boundary:** `d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`, tag `v0.5.11-dev.4`
**Current development package:** `0.5.11-dev.5`
**Draft PR:** `#2` — keep Draft
**Status:** dev.5 scope closure is in progress as forward-only commits on top of frozen dev.4. Ten slices are committed/pushed with exact-SHA `validate` success through the CRITICAL Velero Restore runtime at `4b9d52ff8cff3412518c1e5c000ff4a7826bc323` (validate run `32407041035`). This slice adds bounded Velero Schedule create/update execution with exact live-state binding, restricted no-more-frequent-than-hourly cron, fixed Backup template fields and active validation/spec verification. Direct etcd snapshot/restore, full-cluster/provider DR and provider-backed lifecycle remain open. Do not amend, move, or recreate dev.4. Dev.5 must still close provider/Cluster Factory runtime gaps, remaining air-gap protocols, provider-coupled verification extensions, and the final audit before `v0.5.11-dev.5` is created. Production image publication remains GitHub Actions -> Docker Hub.

Dev.4 adds the shared Web/Telegram/AI typed intent backend, fleet exact-target snapshots, advanced day-2 plans, VMware/OpenStack/AWS/Azure/GCP foundations, Redfish/IPMI/PXE and typed switch/network contracts, digest-pinned air-gap artifact mirroring, constrained generic operation jobs with signed exact-plan execution tickets and unified verification. It does **not** claim live provider/cloud/bare-metal/switch execution without separate disposable-target evidence.

See `RELEASE-STATUS-0.5.11-dev.5.md`, `docs/DEV5-SCOPE-CLOSURE.md`, and the frozen dev.4 evidence. The historical handover below is retained only as release history.

---

# Hermes Control Plane — Development Handover

**Repository:** `Afsharidevops/hermes-control-plane`
**Published prerelease:** `v0.5.10-beta.1`
**Active development branch:** `dev/0.5.10-rc.1`
**Current development package:** `0.5.10-rc.1`
**Latest local update:** RC.1 stabilization R2
**Status:** beta tag is already published; RC is not ready to tag yet. R1 exposed a shell EOF bug before combo creation; R2 fixes it and still requires live validation.

## Continuation rule

Continue only on `dev/0.5.10-rc.1`. Do not move or recreate `v0.5.10-beta.1`. Do not merge/tag `v0.5.10-rc.1` until the RC acceptance tests below pass.

Keep both mutation execution gates disabled during routing/Telegram debugging:

```text
HERMES_EXECUTION_ENABLED=false
HERMES_KUBERNETES_EXECUTION_ENABLED=false
```

## Product/security architecture that must not regress

Hermes Control Plane is a self-hosted AI-assisted DevOps management plane for Docker/VM and Kubernetes installations.

Core rule: **AI plans; constrained brokers/agents execute.**

- UI/admin: configuration, observability, discovery, audit and plan inspection only.
- Hermes Bot: bot-only infrastructure mutation planning/preview/request/execute flow.
- Approval Bot: separate service identity/token; only it may approve/reject protected infrastructure ChangeSets.
- Kubernetes Broker: isolated kubectl/Helm and credential/execution boundary; no Docker socket and no router authority.
- Smart Router/Router Gateway: model routing only; no raw infrastructure credentials.
- Raw kubeconfig/provider infrastructure credentials must not reach Hermes/LLM/Smart Router.
- approvals bind to the exact immutable ChangeSet hash.
- target/credential drift invalidates execution.
- execution is disabled by default and broker execution requires a short-lived exact-plan ticket.

The UI must not regain Kubernetes/Helm mutation editors, approval buttons, or execute buttons. Backend admin-token mutation must remain blocked.

## Release history/current branch state

The beta development branch was merged into `main` and the tag `v0.5.10-beta.1` was pushed. After that, `dev/0.5.10-rc.1` was created from `main` and pushed.

Do not rewrite that history. Stabilization work belongs on `dev/0.5.10-rc.1`.

## Beta functionality retained

The repository already contains:

- Environment / Integration / Target registries
- metadata-only credential references
- ChangeSet canonical JSON/SHA-256 hashing
- risk classification and exact-hash approval binding
- audit trail
- isolated Kubernetes Broker with kubectl/Helm
- kubeconfig file-reference/fingerprint boundary on Docker/VM
- Kubernetes discovery
- server-side manifest dry-run/diff and guarded apply
- Helm server dry-run, install/upgrade verification, and rollback
- target snapshot/credential-fingerprint drift invalidation
- short-lived HMAC-signed exact-plan broker tickets
- Operations Center configuration/discovery views
- Hermes ChatOps plugin and separate Approval Bot service identity

## Router key lifecycle state

R8 fixed duplicate managed API-key creation during provider restart/switching.

Validated in the real development environment:

- repeated `down -> up` reused the existing valid 9router managed key;
- no new key was created on normal restart;
- `./hermesctl router cleanup-keys` removed 1 stale 9router duplicate and 2 stale OmniRoute duplicates.

RC stabilization R1 also fixes the small R8 error-reporting issue by preserving the real `managed_key_stale_ids` helper status without shell negation, and adds `router cleanup-keys` to CLI help.

Duplicate cleanup must continue to fail closed when the active key cannot be identified unambiguously.

## Hermes -> Smart Router authentication bug — diagnosed

Telegram read-only requests initially failed with:

```text
HTTP 401 authentication required
```

Diagnostics proved:

```text
OPENAI_API_KEY exists inside Hermes                     OK
Hermes container -> Smart Router /v1/models HTTP 200   OK
Router Gateway management API                          OK
9router managed API key                                OK
```

The bug was `./hermesctl bot model-sync`: `ensure_hermes_router_model()` cleared `model.api_key` in `/opt/data/config.yaml`.

Manual validation proved the fix by setting:

```yaml
model:
  provider: custom
  default: auto
  base_url: http://smart-router:8080/v1
  api_mode: chat_completions
  api_key: ${OPENAI_API_KEY}
```

After recreating Hermes, the Smart Router 401 disappeared.

RC stabilization R1 makes this permanent. Only the `${OPENAI_API_KEY}` reference is stored in YAML; the raw Smart Router client key remains in the process environment.

`./hermesctl bot check` now validates the environment reference and performs an authenticated Hermes-container -> Smart Router `/v1/models` request.

## Missing 9router combo bootstrap — diagnosed

Router Gateway already maps neutral Hermes tiers to these 9router model names:

```text
hermes/observe   -> ai
hermes/fast      -> combo-fast
hermes/standard  -> combo-standard
hermes/strong    -> combo-strong
hermes/coding    -> combo-strong
hermes/vision    -> combo-strong
```

But beta.1 did not provision those combos. The live 9router dashboard showed **no combos**, and `/v1/models` contained no `ai`/tier combo entries.

The implementation pattern was compared with `Afsharidevops/hermes-linux-stack` main. That project already seeds an OpenCode free pool and creates `ai`, `combo-fast`, `combo-standard`, and `combo-strong`, preserving customized tier combos on rerun.

For Hermes Control Plane, R1 ports only the routing-combo concept. It does **not** port the old direct-DB API-key insertion because the newer Control Plane managed-key lifecycle is safer and must remain authoritative.

R1 uses the current authenticated 9router `/api/combos` management API rather than directly editing the router database.

## OpenCode provider evidence

The 9router dashboard showed **OpenCode Free: Ready**.

`opencode-go/*` model IDs were visible in `/v1/models`, but all real completions failed with:

```text
No active credentials for provider: opencode-go
```

Those are credential-backed `opencode-go` routes and must not be used as the default no-auth bootstrap pool.

The live OpenCode Zen catalog at `https://opencode.ai/zen/v1/models` returned current model IDs. A real 9router completion using:

```text
oc/deepseek-v4-flash-free
```

returned HTTP 200 with the existing managed 9router API key.

This proves the `oc/*-free` route is a valid bootstrap source.

## RC stabilization R1 — implementation

R1 adds `ensure_nine_router_routing_combos()` to `hermesctl`.

When 9router is selected:

1. start/wait for 9router;
2. reuse/provision the managed Router Gateway API key;
3. authenticate to 9router management API;
4. list existing combos;
5. fetch the current OpenCode Zen catalog;
6. select IDs ending in `-free` plus `big-pickle`, prefix with `oc/`;
7. create/update required routing objects;
8. verify all four required combo names appear through authenticated `/v1/models`.

Ownership behavior:

- `ai`: Hermes-managed and refreshed from the live free pool when the catalog is available;
- `combo-fast`: created only if absent, then operator-owned/preserved;
- `combo-standard`: created only if absent, then operator-owned/preserved;
- `combo-strong`: created only if absent, then operator-owned/preserved;
- unrelated/user combos are untouched.

If the catalog is temporarily unavailable **and all required combos already exist**, startup preserves/verifies them instead of failing solely because of the external catalog outage. If required combos are missing and the catalog cannot be fetched, reconciliation fails rather than knowingly starting with broken routing.

Config controls:

```text
NINEROUTER_AUTO_PROVISION_COMBOS=true
NINEROUTER_OPENCODE_CATALOG_URL=https://opencode.ai/zen/v1/models
```

## OmniRoute behavior

Do not apply 9router combo provisioning to OmniRoute.

OmniRoute remains on its native zero-config routing path through Router Gateway:

```text
hermes/observe   -> auto/best-chat
hermes/fast      -> auto/best-fast
hermes/standard  -> auto/best-chat
hermes/strong    -> auto/best-reasoning
hermes/coding    -> auto/best-coding
hermes/vision    -> auto/best-vision
```

## Stronger probe behavior

The beta `router probe` incorrectly labeled a successful `/v1/models` request as an end-to-end route test.

R1 changes `./hermesctl router probe` to POST a small real streaming chat completion with `model=auto` through Smart Router. This is expected to traverse Smart Router -> Router Gateway -> selected router -> real model/provider.

## First test sequence for R1

Apply the R1 package to `dev/0.5.10-rc.1`, keep the existing local `.env`, then set the branch package version:

```bash
./hermesctl version set 0.5.10-rc.1
./hermesctl execution disable
./scripts/verify.sh
./hermesctl up
```

On the first 9router run, expected output includes creation of any missing required combos. Then:

```bash
./hermesctl router probe
./hermesctl bot check
./hermesctl execution status
```

Expected:

```text
real chat completion through Smart Router -> nine-router   OK
Hermes -> Smart Router authenticated runtime request       OK
HERMES_EXECUTION_ENABLED=false
HERMES_KUBERNETES_EXECUTION_ENABLED=false
```

Open the 9router dashboard -> Combo & Vision Adapter and verify:

- `ai`
- `combo-fast`
- `combo-standard`
- `combo-strong`

exist.

Run `./hermesctl up` again. Expected: `ai` may be refreshed from the current free catalog; existing tier combos must be reported as preserved rather than overwritten.

Then send the Telegram read-only request:

```text
Show me the Kubernetes targets managed by Hermes Control Plane.
```

It must no longer return `authentication required`, and it must not fail because `ai` is absent.

## Router cleanup follow-up tests

After R1 routing tests:

```bash
./hermesctl router cleanup-keys all
./hermesctl router cleanup-keys all
```

The second run should normally remove zero stale duplicates.

Still desirable before RC tag:

- controlled invalid/revoked managed-key rotation test: explicit 401/403 -> exactly one replacement -> next restart reuses replacement;
- controlled ambiguous-current-key cleanup test: deletes nothing and emits the dedicated ambiguity error.

## Kubernetes/Telegram RC acceptance still pending

Do not tag RC merely because model routing works.

With execution disabled first, validate on a disposable Kubernetes cluster:

1. kubeconfig import;
2. environment/target creation;
3. discovery;
4. bot-originated manifest ChangeSet;
5. live server-side manifest dry-run/diff;
6. bot-originated Helm ChangeSet;
7. live Helm server dry-run;
8. UI remains inspection/configuration-only;
9. admin-token mutation is rejected;
10. execution is blocked while gates are false.

Then, only on the disposable cluster, enable execution and validate:

1. Hermes Bot creates exact plan;
2. separate Approval Bot approves exact current hash;
3. execute through Kubernetes Broker;
4. verify result and audit trail;
5. target/credential drift blocks stale execution;
6. wrong/expired approval blocks execution;
7. replayed broker ticket is rejected;
8. rollback where supported.

After execution testing, disable execution again unless explicitly needed.

## RC release rule

Do not create `v0.5.10-rc.1` until routing/authentication, bot-only authorization, Kubernetes preview/execution, upgrade/install, 9router/OmniRoute, and security regression checks pass.

When RC acceptance is complete, merge `dev/0.5.10-rc.1` to `main`, re-run validation on the merged commit, and only then tag `v0.5.10-rc.1`.

After RC.1, allow only release-blocking fixes before `v0.5.10` stable.

## Recommended continuation prompt

Upload the latest source ZIP and this `HANDOVER.md`, then say:

> Continue Hermes Control Plane from HANDOVER.md. Inspect the source ZIP first. We are on `dev/0.5.10-rc.1`; `v0.5.10-beta.1` is already published and must not be changed. RC stabilization R1 permanently fixes Hermes Smart Router auth reference handling, provisions/repairs the missing 9router `ai`/tier combos from the current `oc/*-free` pool while preserving operator-customized tier combos, upgrades router probe to a real completion, and includes the R8 cleanup error/help fixes. Keep execution disabled until routing and Telegram read-only tests pass, then continue the RC acceptance plan without weakening bot-only mutation, credential isolation, exact-hash approval, or broker execution boundaries.

## RC.1 stabilization R2 — current checkpoint

R1 was overlaid on the real `dev/0.5.10-rc.1` checkout and validated far enough to expose one additional shell bug. `./hermesctl up` printed the 9router bootstrap phase and valid managed-key message, then exited before combo creation. The dashboard still showed no combos and the strengthened real-completion probe returned HTTP 404.

Root cause: R1 wrote tiny combo action files without a trailing newline, then parsed them with Bash `read` under global `set -e`. `read` populated the fields but returned status 1 at EOF, aborting the command before the create/update/preserve `case` ran.

R2 fixes this by newline-terminating plan files and making the action-file `read` explicitly EOF-tolerant while preserving fail-closed validation for invalid actions. It also removes handover trailing whitespace so `git diff --check` passes.

R2 must now be overlaid on the same branch and tested with execution disabled. Expected first-run behavior is creation of `ai`, `combo-fast`, `combo-standard`, and `combo-strong`; a second startup must refresh `ai` but preserve existing tier combos. Then `router probe`, `bot check`, and the Telegram read-only target query must pass.

- Dev.5 Hubble runtime slice: trusted Kubernetes Broker collector, pinned Hubble CLI, namespace authorization, typed redaction/aggregation, bounded history, SSE, and Hermes-native Network Live batch UI.

- Dev.5 trusted Kubernetes day-2 runtime slice: exact live-preview-bound node cordon/uncordon/drain, workload restart/scale and pinned Helm-backed add-on/apply execution through Kubernetes Broker with drift rejection and persisted active verification.


## 0.5.11-dev.5 GitOps/Cilium runtime slice
Exact-commit Argo CD Application sync and pinned Cilium Helm upgrade are executable through the trusted Kubernetes Broker with exact preview binding, drift rejection and active verification. Remaining worker/Kubernetes-upgrade/etcd/restore/provider lifecycle is still release-blocking.


## 0.5.11-dev.5 Velero backup runtime slice
One-shot `velero.io/v1` Backup creation is executable through the trusted Kubernetes Broker using exact preview-state binding, namespace-scope enforcement, fixed manifests and active terminal-phase verification. Restore is now separately executable through the CRITICAL bounded path; direct etcd snapshot/restore remains release-blocking.


## 0.5.11-dev.5 Velero restore runtime slice

`cluster.restore` now has a bounded trusted Kubernetes Broker executor for explicit-namespace Velero recovery. Planning requires an exact completed source Backup, rejects wildcard namespace restore, exact-binds both source Backup state and any existing Restore state, and server-side dry-runs only Hermes' fixed `velero.io/v1` Restore CR. The ChangeSet is CRITICAL, so two distinct valid approvals are required. Execution uses `existingResourcePolicy=none`, disables NodePort preservation, forbids hooks/resource modifiers/namespace remapping, waits for `Completed`, and verifies zero errors/validation failures/plugin-operation failures. PV restore is disabled by default and requires target `allow_cluster_scoped` permission when explicitly enabled. Direct etcd snapshot/restore and full provider DR remain open.


## 0.5.11-dev.5 Velero schedule runtime slice

`cluster.backup.schedule` adds trusted `velero.io/v1` Schedule create/update execution through the Kubernetes Broker. Planning restricts schedules to a fixed 5-field numeric cron grammar with a fixed minute (no more frequent than hourly), exact-binds any existing Schedule state, server-side dry-runs only Hermes' bounded Schedule CR/merge patch, and enforces the same namespace authorization as one-shot backups. Existing schedules with fields outside the bounded Hermes contract (for example hooks, storage locations, resource policies or selectors) are rejected rather than silently preserved. Execution creates, idempotently reuses, or updates only the approved cron + namespace scope + snapshot flag + TTL, then actively verifies exact live spec and absence of Velero validation failures. Arbitrary YAML, Velero CLI, shell, schedule deletion and backup-storage credentials are not accepted.
