# Hermes Control Plane — 0.5.11 development handover

**Stable base:** `v0.5.10` — frozen / do not recreate
**Active development branch:** `dev/0.5.11`
**Frozen dev.1 boundary:** `1764cad667717ec78156af8f9f3fcc30eb84c1f5`
**Frozen dev.2 boundary:** `a71b03a54ed2f619d3605c0c08d46de35ad5911c`, tag `v0.5.11-dev.2`
**Frozen dev.3 boundary:** `8547c44de4f6e8116d70f2690b50a50c895eba34`, tag `v0.5.11-dev.3`
**Frozen dev.4 boundary:** `d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`, tag `v0.5.11-dev.4`
**Current development package:** `0.5.11-dev.5`
**Draft PR:** `#2` — keep Draft
**Status:** dev.5 scope closure is in progress as forward-only work on top of frozen dev.4. Sixteen slices are committed/pushed with exact-SHA `validate` success through the bounded exact-tag Git release archive mirror at `395059d63d86316d3056cd28790941726c7e42dd` (validate run `32477791912`). The current continuation work adds typed digest-pinned Ansible Galaxy collection archive mirroring and must still be committed/pushed/validated at its own exact SHA before it can become the next completed slice. Direct etcd snapshot/restore, full-cluster/provider DR and provider-backed lifecycle remain open. Do not amend, move, or recreate dev.4. Dev.5 must still close provider/Cluster Factory runtime gaps, apt/yum/dnf/Python repository protocols, broader Ansible Galaxy catalog/role handling, provider-worker offline-reference consumption/rewrite, broader Git/submodule/signature policy, provider-coupled verification extensions, and the final audit before `v0.5.11-dev.5` is created. Production image publication remains GitHub Actions -> Docker Hub.

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


### Dev.5 OCI image mirror runtime

OCI image mirroring now also has a bounded registry-to-registry runtime. `oci://registry/repository` endpoints must be explicitly allowlisted, the source is addressed by the exact approved SHA-256 digest, the destination tag is the approved artifact version, and Skopeo runs through a fixed argument vector with `--all` and `--preserve-digests`. Source and destination raw manifests are hashed independently; an already-correct destination tag is idempotent, while an existing mismatched tag fails unless the exact approved plan allows replacement. Optional registry authfiles are environment-mounted trusted files under a controlled root and never enter the typed plan or runtime evidence. Helm OCI is now implemented in a subsequent bounded typed slice; package/repository metadata mirroring remains open.

### Dev.5 Helm OCI artifact mirror runtime

`helm-chart` artifact items using `oci://registry/repository` endpoints now enter the trusted mirror worker only as a separate typed OCI path. The source is still addressed by the exact approved SHA-256 manifest digest and registries remain explicitly allowlisted. Before copy, Hermes requires a SemVer-compatible immutable chart tag and validates the source raw manifest as a Helm chart: OCI image-manifest media type, Helm config media type, exactly one Helm chart-content layer, and at most one Helm provenance layer with no unrelated layer media types. The fixed Skopeo copy path remains shell-free and preserves the approved digest; both destination tag and digest references are read back, hashed, and revalidated as Helm manifests. An already-correct chart is idempotent, and a mismatched tag remains fail-closed unless replacement was present in the exact approved plan. This does not close apt/yum/dnf, Python, Ansible, Git-release, generalized repository credentials, broader signature policy, dependency graph ordering, or offline reference rewriting.


### Dev.5 ClusterBlueprint artifact dependency resolver

ClusterBlueprints can now bind exact artifact mirror item IDs and resolve them into a deterministic offline artifact manifest. Each bound artifact must identify its blueprint component/name and dependency key in non-secret labels, match the blueprint's exact provider/Kubernetes/add-on version pin, and have successful `PASS` / `MIRRORED` verification before the manifest can become `READY`. The resolver exposes only the verified destination reference, digest, version and verification metadata; source URLs and arbitrary labels are not copied into the manifest. Optional `depends_on` artifact IDs form an explicitly validated DAG with deterministic topological ordering, duplicate/self/unbound-edge/cycle rejection, and a first blocked artifact resume pointer for partial-sync recovery. This closes deterministic blueprint-to-mirror selection/ordering, but does not yet rewrite Kubespray/K3s/RKE2 provider inputs to consume those offline references. apt/yum/dnf/Python repository metadata synchronization and generalized repository credential delivery also remain open.

### Dev.5 offline provisioning-plan artifact binding

When a ClusterBlueprint declares artifact dependencies, provisioning planning now resolves that manifest in the same database transaction and refuses to create a ProvisioningRun unless the manifest is `READY` and its exact hash verifies. The typed `ClusterProvisioningPlan` receives a bounded `artifact_supply` containing only artifact IDs, component/name/dependency keys, exact versions/digests, dependency edges and verified credential-free offline destination references; source URLs, arbitrary labels, auth material and repository credentials are not copied into the plan. The same exact manifest hash and bounded offline artifact list are placed into each node provider-job request and therefore into the ChangeSet-governed plan hash.

Provider-job authorization re-resolves the current blueprint artifact manifest and rejects execution authorization if it is no longer `READY` or its manifest hash changed after planning/approval. This closes deterministic resolver-to-provisioning-plan consumption and drift binding. It deliberately leaves `provisioner_rewrite_applied=false`: Kubespray/K3s/RKE2 provider workers still need trusted runtime adapters that consume these references and perform class-specific offline rewriting. apt/yum/dnf/Python repository metadata synchronization and generalized repository credential delivery remain open.


## Dev.5 completed bounded exact-tag Git release archive synchronization

The committed dev.5 slice makes `git-release` artifacts runtime-capable when the source is an allowlisted public `https://` Git repository and the destination is a controlled `file://` mirror path. The artifact plan binds only `git_ref` and `git_commit` from labels; arbitrary labels are not copied into the execution plan. `git_ref` must be an immutable `refs/tags/...` reference, `git_commit` must be an exact 40- or 64-hex object ID, and the artifact version must match the tag.

The trusted mirror runtime disables Git credential helpers/prompts and non-HTTPS protocols, rejects redirects, resolves the exact remote tag before fetching, fetches with a fixed depth-one refspec, rejects `.gitmodules`, renders a canonical `git archive --format=tar`, verifies its pinned SHA-256 digest, atomically publishes it into the controlled mirror root and reads the destination back for independent verification. Existing exact destinations are idempotent and network operations use a fixed two-attempt bound. Raw stderr/credentials and caller-controlled Git flags are not returned or accepted.

This is intentionally **Git release archive synchronization**, not full repository mirroring. It does not preserve arbitrary branch/ref history, does not support submodules, and does not verify signed tags/commits. Those boundaries, apt/yum/dnf/Python/Ansible repository protocols, and actual Kubespray/K3s/RKE2 provider-worker consumption remain open.


## Dev.5 Ansible collection archive continuation

`ansible-collection` artifacts now have a typed candidate runtime for digest-pinned Galaxy-style collection tarballs from the controlled local artifact root or allowlisted HTTPS sources into the controlled mirror root. The ChangeSet-bound runtime plan carries only the exact `ansible_namespace`, `ansible_name`, version and SHA-256 identity required for execution; classification/dependency labels are not copied into the executor plan.

Before publication, Hermes opens the gzip tarball without filesystem extraction, rejects absolute/traversal/duplicate paths and link/device members, requires root `MANIFEST.json` and `FILES.json`, binds `collection_info.namespace/name/version` to the approved plan, verifies the MANIFEST -> FILES SHA-256 binding, and verifies every regular file listed in `FILES.json`. Publication remains atomic, independently destination-hashed and idempotent.

This is intentionally exact collection-artifact synchronization, not a Galaxy API/server. Standalone role source archives, where required, are supplied by the bounded exact-tag `git-release` runtime and can be cataloged/bound through existing artifact labels; arbitrary Git history/submodules are not claimed. Collection dependency discovery from Galaxy APIs, signatures, apt/yum/dnf/Python repository metadata, and actual Kubespray/K3s/RKE2 provider-worker offline consumption/rewrite remain separate boundaries. This continuation is not a completed dev.5 slice until it has its own forward-only commit, push and exact-SHA `validate` success.

## 0.5.11-dev.5 Batch A — repository substrate + CI publication efficiency

The Ansible collection slice is committed/pushed and exact-SHA `validate` is green at `26855cbb6f45176ee99029cdbc29b7c847ae79b6` (run `32478857268`).

Batch A is intentionally merged as one larger closure unit. It removes `dev/**` from `publish-images.yml` while preserving `validate.yml` on `dev/**`, so future development pushes keep the exact-SHA branch gate without rebuilding/publishing seven Docker images. Tag/main/manual publication remains available.

The artifact runtime adds typed repository snapshot kinds `apt-repository`, `rpm-repository` and `python-repository`. A repository snapshot is a digest-pinned tar archive containing `HERMES-REPOSITORY-SNAPSHOT.json`; archive paths/links/devices are rejected and the exact file inventory, sizes and SHA-256 values are verified before native repository validation.

APT requires detached GPG verification of `dists/<distribution>/Release.gpg`, SHA-256 binding of supported `Packages` indexes from `Release`, and exact `.deb` size/SHA-256 verification from package stanzas. RPM requires detached GPG verification of `repodata/repomd.xml.asc`, SHA-256 verification of referenced repodata, primary metadata parsing, and exact `.rpm` hash/size verification. Python requires local PEP-503-compatible Simple pages whose distribution links carry exact `#sha256=` fragments; every wheel/sdist in the snapshot must be referenced.

HTTPS credentials and repository keyrings are trusted environment-mounted files below `HERMES_ARTIFACT_AUTH_ROOT`; raw content is never copied into plans, audit or evidence. Publication uses a staging directory plus rollback-safe rename, so partial extraction never becomes the active mirror.

This closes the intended package-repository substrate for Batch A only after its forward-only commit/push/exact-SHA CI. It does not claim that Kubespray/K3s/RKE2 have consumed or rewritten these references yet.


## 0.5.11-dev.5 Batch B — trusted existing-host cluster provider runtime

Batch B turns the exact READY offline artifact supply into constrained execution through the existing `node-agent` image, which now also exposes a dedicated provider-worker API. Provider execution is disabled by default and requires a bearer worker token plus the existing execution HMAC key. The Control Plane issues a short-lived exact ChangeSet/typed-plan ticket only after normal risk/policy/approval authorization; the worker verifies the signature, exact plan hash, `cluster-provider-worker` precondition and one-time ticket use before doing any work.

The worker supports only `kubespray`, `k3s` and `rke2` and only a fixed provider/operation matrix. It builds Ansible inventory exclusively from approved server snapshots, verifies each host remains configured/PASS, resolves only bounded `cred_*` SSH profiles from the mounted worker credential root, copies identity/known-host files into a private `0700` execution workspace with `0600` permissions, suppresses subprocess stdout/stderr, and deletes the workspace in `finally`. No SSH key material is copied into the ChangeSet, provider job, audit, verification result, UI or AI boundary.

Offline install/upgrade paths require the exact READY artifact manifest with `provisioner_rewrite_applied=true`. File artifacts are rehashed under the controlled mirror root before execution; OCI references must resolve to one offline registry. Kubespray is pinned to release `v2.28.1` with the bundled `ansible==9.13.0`, `cryptography==45.0.2`, `jmespath==1.0.1` and `netaddr==1.3.0` contract and requires configured internal file/APT/RPM/PyPI endpoints. K3s/RKE2 use role-aware fixed installation/rejoin paths and do not download from the public Internet.

Batch B provider-backed day-2 covers worker add/remove/replace, Kubernetes upgrades, certificate rotation and bounded existing-host maintenance. K3s/RKE2 embedded-etcd snapshot/restore and existing-host disaster recovery use the provider's direct embedded-etcd/server reset paths and active verification; there is no generic `kubectl exec etcdctl` shortcut. Provider verification checks the runtime binding, provider services, Kubernetes `/readyz`, snapshot existence and restore reset-state.

The boundary remains explicit: Kubespray direct-etcd recovery fails closed, and `cluster.decommission` is not a provider-runtime operation until Batch C can destroy/reconcile actual infrastructure capacity. Infrastructure scale, provider-capacity creation/destruction, capacity-backed template cloning, full provider-recreation DR and provider/bare-metal/network/cloud executors/collectors remain Batch C or final-audit work. Local/mock integration must not be presented as real-target evidence.


## 0.5.11-dev.5 Batch C — Redfish infrastructure runtime foundation (local continuation)

Batch C begins with a bounded infrastructure-provider worker path on the existing Node Agent image. Only Redfish `inventory.refresh`, `power.set`, `boot.set`, `virtual-media.insert`, `virtual-media.eject` and bounded `bios.apply` are runtime-capable in this accumulated local slice. Infrastructure execution is disabled by default. The Control Plane first asks the trusted worker for an active current-state preview, binds the credential-free state/diff and its hash into the exact typed plan, then uses the normal ChangeSet risk/policy/approval path. Execution requires a short-lived HMAC-signed one-time ticket naming `infrastructure-provider-worker`, and the worker re-probes the current Redfish state immediately before mutation; any drift from the approved preview fails closed.

Redfish credentials remain entirely worker-side under `HERMES_INFRASTRUCTURE_CREDENTIAL_ROOT`. A directory profile may use `<root>/<credential_ref>/profile.json` with local `username_file`, `password_file` and optional `ca_file` names. Kubernetes Secret mounts may instead use a flat `<credential_ref>.profile.json` plus referenced sibling key files. Profiles are fixed basic-auth metadata only; raw usernames/passwords/CA contents never enter ChangeSets, typed plans, preview evidence, audit or UI responses. HTTPS is required by default, redirects and cross-origin Redfish links are rejected, and TLS verification is never disabled. HTTP exists only behind the explicit worker-side `HERMES_INFRASTRUCTURE_ALLOW_HTTP=true` development switch.

`power.set` maps the approved desired state only to the fixed Redfish `ComputerSystem.Reset` action. `boot.set` maps only bounded boot target/enabled/mode fields to the system `Boot` object. `inventory.refresh` is read-only. Caller-supplied shell, SSH or arbitrary provider CLI is not accepted. Successful execution performs bounded active Redfish verification and returns typed safe evidence rather than raw provider output.

`virtual-media.insert` and `virtual-media.eject` use only the fixed Redfish VirtualMedia actions discovered through the selected system manager. Insert accepts only a credential-free HTTPS image URL and forces write protection; the image host must exactly match `capabilities.virtual_media_image_hosts`, while `manager_id`/`virtual_media_id` disambiguate multi-manager or multi-media BMCs. Unsafe current image references are redacted from evidence, and execution re-probes the exact virtual-media snapshot before mutation.

This is not Batch C closure and does not claim real-target evidence. IPMI/PXE, firmware/BIOS, disk/RAID, management/provisioning networking, switch/network runtime, VMware/OpenStack/AWS/Azure/GCP capacity execution, infrastructure-backed decommission/scale/template cloning/provider-recreation DR, matching provider collectors and Kubespray direct-etcd recovery remain open. Unsupported paths must remain contract-only or `SKIP`; `v0.5.11-dev.5` must not be tagged from this local continuation.


`bios.apply` accepts only a bounded map of BIOS attribute names to scalar string/integer/boolean values, and every requested name must be present in the exact provider snapshot `capabilities.bios_attribute_allowlist`. The worker discovers the selected system BIOS resource and, when exposed, its same-origin Redfish SettingsObject; planning snapshots only the requested attributes, execution PATCHes only the fixed `Attributes` object, and verification confirms the requested values are reflected by the BIOS/settings resource. This verifies provider-side desired/pending BIOS settings, not that a reboot-dependent setting has already become active hardware state; any required reboot remains a separately governed operation.


### Dev.5 Batch C Redfish firmware continuation

The accumulated local Batch C Redfish worker now also supports bounded `firmware.apply`. Firmware images must be credential-free HTTPS URLs with exact provider-snapshot host allowlisting, component IDs must be provider-allowlisted, and the expected version is bound into the typed plan. The worker follows only same-origin `UpdateService` / `FirmwareInventory` references, invokes fixed `#UpdateService.SimpleUpdate` with `ImageURI` and the exact component `Targets` URI, rejects non-updateable components, skips already-converged versions, and verifies convergence by re-reading the exact firmware inventory component. Separate bounded firmware verification attempt/delay settings are wired through Compose and Helm. IPMI/PXE, disk/RAID, management/provisioning networking, switch/network and cloud/virtualization provider capacity remain open Batch C work.

### 0.5.11-dev.5 Batch C5a — constrained IPMI fallback runtime

The infrastructure provider worker now supports `ipmi` `power.set` and `boot.set` through a fixed `ipmitool -I lanplus` argv surface. Provider endpoints are restricted to `ipmi://host[:port]`; passwords are loaded only from mounted `ipmi-lanplus` credential profiles and passed through the child environment, never argv/plans/audit. Preview reads normalized chassis power or boot parameter state, exact-state hashes are bound into approval/tickets, execution rejects drift/replay and active verification re-reads the same bounded state. Redfish remains preferred where available; PXE/unattended provisioning is closed locally by the following C5b slice.

### 0.5.11-dev.5 Batch C5b — private-offline PXE/iPXE unattended provisioning

The infrastructure provider worker now supports `pxe` `os.provision` and `os.reimage` through a fixed HTTPS provisioning-controller API. The provider must explicitly declare `capabilities.network_scope=private-offline` and `capabilities.artifact_delivery=shared-readonly-mirror`; HTTP, redirects, embedded credentials/query material and ambient proxy inheritance are not used. Planning requires exactly one registered Server with `provisioning_ip`, canonical `provisioning_mac`, `provisioning_nic` and `boot_provider_id` labels, and exact-binds that snapshot plus the referenced trusted Redfish/IPMI boot-provider snapshot. Reimage additionally requires an exact hostname confirmation.

PXE artifacts are resolved from exact artifact-mirror IDs into a READY `PXEProvisioningArtifactManifest`. At least `kernel`, `initrd` and `unattended` roles are required; every role must already have PASS/MIRRORED verification, an exact SHA-256 digest and an absolute local `file://` destination. The supply is hash-bound into the typed plan, re-resolved at operation-job authorization, and rehashed again by the worker under `HERMES_ARTIFACT_MIRROR_ROOT` immediately before mutation. Public-network artifact fetch is therefore not part of this path.

Unattended configuration is loaded only inside the worker from a bounded JSON profile referenced by `unattended_profile_ref`; arbitrary command/script fields are rejected. Callback tokens are loaded from worker-mounted files, while only the exact SHA-256 token binding is present in the plan. The worker prepares the node through the fixed controller API, reuses the existing constrained Redfish/IPMI adapter for one-time PXE boot and power transition, then requires the controller to prove the monotonic `requested -> booting -> installer-started -> installing -> complete` history with exact node/plan/artifact/callback bindings. A final bounded TCP readiness probe against the registered management IP/SSH port must pass before the execution result is `SUCCEEDED`. Replayed tickets, preview drift, artifact drift, callback drift, identity mismatch and failed/timeout state are fail-closed.

C5b is local/integration evidence only. It does not invent DHCP/TFTP/server or disposable-target evidence beyond the fixed private controller contract and tests. Disk/RAID, Secure Boot/SR-IOV/IOMMU/boot-order desired state, management/provisioning switch/network runtime, cloud/virtualization capacity, capacity-backed decommission/scale/cloning/DR and matching real-target collectors remain Batch C work. Keep C1-C5b uncommitted until the merged Batch C boundary; do not tag dev.5.

### 0.5.11-dev.5 Batch C6 — Redfish disk/RAID desired state

The accumulated local Batch C infrastructure worker now supports bounded Redfish `storage.volume.apply` and `storage.volume.delete`. Provider snapshots must declare an exact `storage_controller_allowlist` mapping each permitted controller to exact physical drive IDs, RAID types, volume names and an explicit destructive-delete boolean. Planning validates RAID minimum-drive counts and rejects non-allowlisted controller/drive/name/type input before the worker is contacted.

Active preview follows only same-origin Redfish System -> Storage -> Controller -> Drive/Volume references. It binds the exact controller plus bounded physical-drive identity (`Id`, `SerialNumber`, model/part/capacity/status) and current volume topology into the approved preview hash. RAID creation fails closed if a requested disk lacks a stable serial identity, is unhealthy/unavailable, appears with a duplicate serial, is already bound to another volume, or if the requested volume name already exists with different RAID/drives. An already exact volume is idempotent.

Creation uses only fixed Redfish VolumeCollection POST with `Name`, allowlisted `RAIDType` and exact discovered Drive links. There is no generated storage CLI or arbitrary Redfish body. RAID reshaping is not performed in-place: operators must plan a separate destructive delete before a replacement create. `storage.volume.delete` requires exact `volume_id == confirm_volume_id`, explicit provider `allow_volume_delete=true`, is classified CRITICAL by the risk engine, deletes only the exact same-origin volume URI discovered in preview, and actively verifies absence afterward. Exact-state drift and ticket replay remain fail-closed.

C6 is local/integration evidence only until the merged Batch C commit/push/exact-SHA CI and disposable-target evidence. Secure Boot/SR-IOV/IOMMU/boot-order state, management/provisioning networking, switch/network runtime, VMware/OpenStack/AWS/Azure/GCP capacity execution, provider-backed decommission/scale/template cloning/recreation DR and matching active collectors remain open. Keep C1-C6 uncommitted until the real Batch C boundary; do not tag dev.5.


### Batch C7 — Redfish platform firmware/security and persistent boot order

Batch C7 adds local **INTEGRATION-COMPLETE** trusted Redfish runtime for `secure-boot.apply`, `sriov.apply`, `iommu.apply` and `boot-order.apply`. Secure Boot uses the standard SecureBoot resource and requires `activation=reboot`; preview binds both `SecureBootEnable` (next-boot policy) and `SecureBootCurrentBoot` (active current-boot state), while execution performs only a fixed `SecureBootEnable` PATCH plus the provider-declared `GracefulRestart`/`ForceRestart` action and does not PASS until the active post-reboot state matches.

SR-IOV and IOMMU are intentionally not open-ended BIOS mutation aliases. Each provider must map the feature to one exact BIOS attribute plus exact enabled/disabled scalar values, the mapped attribute must also be in `bios_attribute_allowlist`, and the provider fixes whether activation is immediate or reboot. Persistent boot order uses only `Boot.BootOrder`; the provider supplies an exact `boot_order.allowlist`, and preview actively resolves the BootOptions collection and rejects missing, disabled, duplicate or unsafe `BootOptionReference` values. When the provider declares reboot activation, the worker requires the system to be powered on and uses only the fixed provider reset type.

Reboot verification has a separate bounded poll budget and tolerates only transient 502/503 BMC unavailability during the reboot window. Preview-state hash drift, ticket replay and credentials/CLI/shell exposure remain fail-closed. This is local/mock integration evidence until exercised against a disposable Redfish target.

Per the user-requested provider plan expansion, `proxmox` and `vmware-workstation` are now explicit cloud/virtualization **CONTRACT-ONLY** provider kinds. Proxmox is intended as a first-class VM capacity target; VMware Workstation is intended for local/lab clone-based capacity. Neither is represented as runtime-complete until a constrained trusted worker and active collector are implemented.
