# 0.5.11-dev.5 — Scope Closure + Runtime Integration

`0.5.11-dev.5` is a forward-only scope-closure milestone on top of frozen
`v0.5.11-dev.4` (`d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`). It does not rewrite dev.4.

## Slice 1: Radar read runtime

This slice replaces the Radar snapshot-only boundary with a real, bounded,
read-only runtime adapter:

- Radar is a first-class `integration` kind.
- Hermes speaks Radar's HTTP MCP endpoint using JSON-RPC initialization and
  `tools/call`.
- Hermes exposes only an explicit read allowlist: dashboard, issues, resource
  list/detail, search, topology and neighborhood.
- Unknown tools and unknown arguments are rejected before network I/O.
- Radar write tools are not exposed. Any infrastructure mutation remains a
  Hermes ChangeSet/policy/approval/exact-hash execution path.
- `AUTO`, `RADAR`, and `NATIVE` context modes are executable.
- `AUTO` tries a configured same-environment Radar integration first and falls
  back to a same-environment Kubernetes target through the existing trusted
  Kubernetes Broker.
- `RADAR` fails closed when Radar is unavailable or misconfigured.
- `NATIVE` does not contact Radar.
- Provider output is redacted before it can reach Web/AI consumers. Kubernetes
  Secret bodies and direct workload environment values are suppressed.
- Direct Control Plane Radar access intentionally does not resolve credential
  material. Authenticated Radar endpoints require a future credential-service
  to provider-worker path rather than pulling secrets into the Control Plane.

## Native fallback coverage in this slice

Native fallback is deliberately bounded to the existing Kubernetes Broker
inventory and supports dashboard, list, resource detail, search, issues and an
inventory topology. It is not presented as feature-equivalent to Radar.

## Remaining dev.5 closure

Radar alone did not close the roadmap. The follow-on slices below close Hubble,
native diagnostics, Operator Center UI, bounded Kubernetes day-2 execution, active
unified verification, and the first executable air-gap blob-mirroring runtime.
Provider/Cluster Factory executors and full registry/repository protocol mirroring
remain subsequent `0.5.11-dev.5` work unless explicitly deferred by the user.

## Slice 2 — Cilium/Hubble live-network runtime

This follow-on dev.5 slice moves Hubble from stored-summary contracts to a real bounded runtime path:

`Cilium/Hubble -> Hubble Relay -> pinned Hubble CLI in Kubernetes Broker -> namespace authorization -> typed redaction/aggregation -> Control Plane bounded history/SSE -> Hermes-native Network Live UI`

Security properties:

- Hubble Relay access runs in the trusted Kubernetes Broker so kubeconfig material does not enter UI/AI-facing components.
- The broker executes a fixed `hubble observe --port-forward --output jsonpb` command with bounded `last`/`since_seconds` parameters; no arbitrary CLI arguments or shell execution are accepted.
- Raw L7 URLs, request/response headers, bodies, IP addresses and arbitrary protobuf bodies are discarded before broker output.
- Target namespace allow/deny scope is enforced on sanitized flow events before they leave the broker.
- The Control Plane rejects any batch that does not attest `raw_flow_bodies_returned=false`.
- Per-cluster flow history is deduplicated by sanitized-event fingerprint and bounded to 2,000 events.
- Network Live has a typed batch endpoint plus an authenticated SSE endpoint; browser UI receives only sanitized batches.
- No Hubble mutation path is introduced. Mutations remain normal Hermes ChangeSets.

Evidence in this slice is mock/simulation + local runtime-path testing. It is **not** real-target Cilium/Hubble evidence; live disposable-cluster verification remains required before classifying the complete 0.5.11 Hubble area as real-target verified.
## Slice 3 — executable Hermes-native diagnostics runtime

This slice replaces the static native-diagnostic catalog boundary with executable,
target-scoped read collectors in the trusted Kubernetes Broker. It does not add a
`kubectl-aban-plugin` runtime dependency.

Implemented diagnostic families:

- node readiness/pressure, pod readiness/restarts/OOM, workload availability and rollout health
- metrics.k8s.io CPU/memory top-consumer summaries, PVC health and Warning-event correlation
- Cilium pod readiness, Hubble Relay reachability/policy-drop summary, CoreDNS visibility, Ingress and NetworkPolicy checks
- dangerous RBAC rules, privileged containers, dangerous Linux capability additions, hostPath use, exposed Services, Ingress TLS and admission-webhook baseline checks
- Argo CD Application sync/health plus compatibility checks for cert-manager Certificates and Velero Backups when those CRDs are visible

Security/runtime properties:

- only fixed `kubectl get`/metrics API collectors are constructed; there is no user-provided command, shell, `exec`, log or mutation passthrough
- namespace allow/deny scope and `cluster_read` are enforced before collection
- Secrets are never requested, event messages are not returned, workload environment values are not returned, and hostPath paths are not returned
- Hubble diagnostics reuse the sanitized Hubble collector and attest `raw_flow_bodies_returned=false`
- output is a bounded typed finding schema with `PASS`/`WARN`/`FAIL`/`SKIP`; the Control Plane rejects malformed results, mutation attestation changes, oversized results and sensitive evidence keys
- every Control Plane diagnostics run is audited

Evidence is local runtime-path/mock/simulation evidence, not real-target cluster evidence.


## Slice 4 — Hermes-native Operator Center UI scope closure

This slice closes the promised operator-navigation surface without conflating UI
coverage with backend runtime completion. A typed `/v1/operator-center/contracts`
map now covers every original Kubernetes, Cluster Factory, infrastructure,
operations and governance page and reports `ui_state` separately from
`runtime_state`.

Implemented UI surfaces include:

- Kubernetes Overview, Issues, Applications, Topology, Network Live, Resources,
  Workloads, Nodes, Storage, Ingress, Metrics, Logs, Timeline, Helm, GitOps, Cost,
  TLS, Security, RBAC and Audit
- Cluster Factory Clusters, Servers, Provision, Templates, Bare Metal and Images / Artifacts
- Infrastructure Kubernetes, VMware, OpenStack, AWS, Azure, GCP, Docker, Swarm and SSH
- Operations Diagnostics, Deployments, Upgrades, Backups, Recovery and Maintenance
- Changes, Approvals, Credentials, Agents, Integrations, Artifact Mirror, Audit,
  AI Routing and Settings

The UI renders live data where current Hermes runtime exists and reports
`PARTIAL`, `OPTIONAL_PROVIDER` or `CONTRACT_ONLY` for surfaces whose runtime is
not complete. In particular VMware/OpenStack/AWS/Azure/GCP, bare-metal and
artifact-mirror executor status is not upgraded by the presence of a page.

Security/governance properties:

- the Operator Center is observability/plan-inspection only; it does not add
  approval, execution, arbitrary kubectl/Helm or provider command controls
- credential material is never rendered; credential pages use metadata-only refs
- live Network and Diagnostics actions reuse the already-authorized Hubble and
  native diagnostics paths
- UI state and runtime state are explicitly separate so contract-only adapters
  cannot be mistaken for real-target integration evidence

Remaining dev.5 release blockers are runtime/executor work: remaining Cluster
Factory/day-2 provider operations, provider/bare-metal/network executors or
explicit deferral, complete OCI/repository air-gap protocol synchronization, and
provider-coupled verification extensions.


## Slice 5 — trusted Kubernetes day-2 execution + active verification

This slice converts a bounded subset of the dev.4 day-2 plan catalog into real governed execution through the existing trusted Kubernetes Broker. It does **not** claim that provider-worker operations are complete.

Runtime-complete in this slice:

- node cordon / uncordon / drain
- workload rollout restart
- Deployment / StatefulSet scale
- pinned Helm-backed `cluster.helm.apply`, add-on install and add-on upgrade

Governance and drift properties:

- the operator supplies a same-environment configured Kubernetes `native_target_id`; the full target snapshot is bound into the typed day-2 plan
- planning calls a read-only broker preview before ChangeSet creation; the preview contains only bounded safe state, an exact state hash and secret-suppression attestation
- the runtime preview/precondition is included in the typed plan hash, so the existing ChangeSet approval and signed execution ticket bind the exact previewed state
- execution re-reads the node/workload/Helm release and rejects drift before running the mutation
- the Control Plane accepts execution only for jobs whose executor is exactly `kubernetes-broker` and whose ticket/approval bindings remain valid
- broker commands are fixed argument vectors; there is no arbitrary shell, kubectl or Helm command passthrough
- namespace authorization remains enforced by the Kubernetes target scope
- successful broker execution must return typed active verification checks; Hermes persists them and marks the operation plan VERIFIED only on PASS
- broker failure, sensitive evidence, malformed verification or failed verification prevents a successful ChangeSet result

This slice intentionally left `cluster.worker.add/remove/replace`, GitOps sync, Kubernetes/Cilium upgrade, etcd snapshot, restore/DR, certificate rotation, maintenance provider steps, decommission, infrastructure scale and template clone on their explicit provider-worker contracts at that point; Slice 8 closes the trusted Argo CD sync and Cilium-upgrade subset, and Slice 9 closes a bounded one-shot Velero backup subset. The remaining operations stay release-blocking until a real executor exists or the user explicitly defers them.

## Slice 6 — Active unified cluster verification

This slice turns the dev.4 persisted verification-result contract into an active read runtime for the cluster surfaces Hermes can actually probe today.

The Control Plane now exposes `POST /v1/clusters/{cluster_id}/verify`. It:

- validates the requested cluster and same-environment native Kubernetes target;
- executes fixed read-only live collectors through the trusted Kubernetes Broker;
- maps native diagnostic probes into the canonical unified checks (`networking`, `api-server`, `nodes`, `cilium`, `hubble`, `dns`, `storage`, `ingress-tls`, `gitops`, `observability`, `baseline-security`);
- optionally performs an active MCP initialize/health exchange against a configured same-environment Radar integration;
- persists the typed result into `verification_results` and emits `verification.active.executed` audit evidence;
- preserves deterministic `PASS`, `WARN`, `FAIL`, and `SKIP` semantics, including `SKIP` when a real active collector does not exist.

This slice intentionally does **not** infer active success from stored host preflight state, agent enrollment state, provider contracts, or a persisted result model. Host/SSH, direct etcd-quorum, Hermes Agent, and provider-specific verification remain `SKIP` until their trusted runtime collectors exist. Kubernetes Metrics API evidence is not mislabeled as Prometheus health; observability remains `WARN` when only `metrics.k8s.io` is actively available.

All returned evidence is bounded and rechecked against the same forbidden sensitive-field rules used by native diagnostics. No mutation command path is introduced.

Provider-specific verification remains coupled to the still-open provider/bare-metal/network runtime work.


## Slice 7 — Trusted air-gap artifact blob synchronization runtime

This slice converts the dev.4 artifact inventory/plan contract into executable
ChangeSet-governed synchronization for digest-pinned blob artifacts that can be
fetched from a controlled local source tree or an explicitly allowlisted HTTPS
host and written into the controlled local mirror tree.

Runtime path:

```text
ArtifactMirrorItem
  -> typed ArtifactMirrorPlan
  -> ChangeSet / exact-hash approval
  -> signed operation execution ticket
  -> trusted artifact mirror runtime
  -> source SHA-256 verification
  -> atomic destination write
  -> destination SHA-256 verification
  -> persisted verification + audit
```

Security/runtime properties:

- the source must be `file://` below `HERMES_ARTIFACT_SOURCE_ROOT` or `https://` on an exact host listed in `HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST`; empty allowlist means network fetch is disabled
- the destination must be `file://` below `HERMES_ARTIFACT_MIRROR_ROOT`
- embedded URL credentials, redirects, root escapes and symlinked source/destination paths are rejected
- artifact size and network timeout are bounded by `HERMES_ARTIFACT_MIRROR_MAX_BYTES` and `HERMES_ARTIFACT_MIRROR_TIMEOUT_SECONDS`
- downloads stream into a temporary file; the source digest must match the pinned SHA-256 before an atomic `os.replace` publishes the destination
- the destination digest is independently re-read and verified after publication
- an already-correct destination is an idempotent PASS and does not rewrite the artifact
- a mismatched existing destination is fail-closed unless the exact approved plan sets `replace_existing=true`
- runtime output contains bounded typed verification and explicitly attests no arbitrary shell and no returned raw credentials
- `artifact_mirror_items.status` remains the operational enable/disable state; mirror success/failure is stored separately in `verification_json.sync_state`, so retry planning remains possible

This is deliberately **partial air-gap closure**, not a claim that every artifact
protocol is complete. The original blob-only slice did not close registry protocols. Later dev.5 slices add bounded OCI-image and typed Helm OCI registry-to-registry copy; OS/Python package repository metadata mirroring, broader signature policy, dependency/reference resolution, and generalized authenticated repository credential delivery remain release-blocking runtime work. Plans using unsupported
protocol pairs are retained for compatibility but receive executor
`artifact-mirror-contract` and cannot enter the trusted runtime execution path.


## Slice 8 — Trusted GitOps sync + Cilium lifecycle runtime

This slice extends the exact-preview-bound Kubernetes day-2 executor with two additional deterministic operations that do not require cloud/BMC credentials.

### Argo CD GitOps sync

`cluster.gitops.sync` now requires a same-environment Kubernetes target, an authorized Application namespace, an exact Argo CD `Application` name, and a full 40- or 64-character commit digest. Planning reads bounded Application state, validates the fixed merge patch with server-side dry-run, and binds the resulting Application state hash into the approved typed plan. Execution re-reads that state, rejects drift, applies only the fixed `Application.operation.sync` patch, waits for `status.sync.status=Synced`, and actively verifies both exact observed commit digest and Application health. No `argocd` CLI or arbitrary Kubernetes patch body is accepted from the caller.

### Cilium upgrade

`cluster.cilium.upgrade` now executes through the existing pinned Helm runtime only when the approved parameters target release `cilium`, namespace `kube-system`, a Cilium chart reference, and an explicit pinned version. The Helm release snapshot is exact-preview-bound before approval. After execution Hermes actively verifies Helm deployment state, Cilium agent Pod readiness, and sanitized Hubble Relay reachability through the trusted broker.

This remains partial day-2/Cluster Factory closure. Worker lifecycle, Kubernetes version upgrades, etcd snapshot/restore, certificate rotation, provider maintenance/decommission, infrastructure scale, disaster recovery and template cloning still require real trusted provider/provisioner executors or explicit user-approved deferral. Broader Flux/non-Argo GitOps execution also remains open.


## Slice 9 — Trusted one-shot Velero backup runtime

`cluster.backup.velero` is now executable through the trusted Kubernetes Broker without exposing backup-storage credentials to the Control Plane. Planning accepts only a fixed typed subset: a DNS-safe Backup name, Velero namespace, bounded included/excluded namespace lists, `snapshot_volumes`, and a bounded TTL in hours. The broker enforces target namespace scope; an all-namespace backup requires `cluster_read`.

Planning reads the existing `backups.velero.io` object (or its explicit absence), server-side dry-runs only Hermes' fixed `velero.io/v1` `Backup` manifest, and binds that backup-state hash into the approved ChangeSet. Execution re-reads the state and rejects drift. If the Backup does not exist, Hermes creates only that fixed CR; if it already exists, Hermes reuses it only when the live Backup spec exactly matches the approved namespace scope, snapshot setting and TTL and the object is not deleting or failed. The broker waits for `status.phase=Completed` and actively verifies terminal phase, zero errors, exact approved spec, and bounded volume-snapshot counters. Backup logs, Secret data, hooks, arbitrary CR fields, arbitrary `velero` CLI arguments, and arbitrary shell are not accepted or returned.

This is partial backup/restore closure. Scheduled Velero `Schedule` management, restore execution, etcd snapshot/restore, backup-storage-provider lifecycle, and provider-specific DR remain release-blocking.


## Slice 10 — CRITICAL bounded Velero restore runtime

`cluster.restore` now has a trusted Kubernetes Broker runtime for a deliberately bounded Velero recovery path. The caller must provide a DNS-safe Restore name, an exact Backup name, the Velero namespace, and 1–32 explicit target namespaces. Wildcard restore is rejected. `restore_pvs` defaults to false; enabling it additionally requires the Kubernetes target's `allow_cluster_scoped` permission.

Planning reads the source `backups.velero.io` object and requires `Completed` with zero errors. Requested namespaces must be covered by the source Backup and not excluded. Planning also reads any existing `restores.velero.io` object, rejects failed/deleting/mismatched reuse, server-side dry-runs only Hermes' fixed `velero.io/v1` Restore manifest, and binds both source-Backup state and pre-existing Restore state hashes into the exact typed plan. Execution rechecks both hashes and rejects drift before mutation.

Restore is intentionally classified `CRITICAL`, so the existing approval engine requires two distinct integrity-checked approvals. The runtime never accepts arbitrary Restore YAML, hooks, resource modifiers, namespace mappings, schedule selection, arbitrary `velero` CLI arguments or shell. Hermes fixes `existingResourcePolicy=none` (Velero's non-destructive existing-object behavior) and `preserveNodePorts=false`; when PV restore is disabled it also fixes `includeClusterResources=false`. The broker waits for `status.phase=Completed` and actively verifies zero errors, zero validation errors, zero failed RestoreItemActions, completion of attempted RestoreItemActions, exact approved source/scope/spec, and absence of a failure reason.

This is still partial disaster-recovery closure. Direct etcd snapshot/restore, full-cluster restore semantics, provider-specific DR, control-plane recovery and post-provider recovery orchestration remain release-blocking. Slice 11 closes the bounded recurring Velero Schedule definition path.


## Slice 11 — Trusted recurring Velero Schedule runtime

`cluster.backup.schedule` closes the bounded recurring-backup definition path through the trusted Kubernetes Broker. The caller provides a DNS-safe Schedule name, Velero namespace, a restricted 5-field numeric cron expression, bounded included/excluded namespace lists, `snapshot_volumes`, and a bounded TTL. The minute field must be a single integer from 0 through 59, so Hermes-created schedules run no more frequently than hourly. Namespace authorization is identical to the one-shot Backup path; an all-namespace schedule requires `cluster_read`.

Planning reads the existing `schedules.velero.io` object or its explicit absence, rejects deleting/validation-failed schedules and rejects any existing Schedule containing fields outside Hermes' bounded contract. In particular Hermes does not preserve or accept arbitrary hooks, resource selectors, storage-location overrides, resource policies or other arbitrary Backup template fields. Planning server-side dry-runs only a fixed `velero.io/v1` Schedule create or a fixed merge patch and binds the complete bounded live Schedule state hash into the exact ChangeSet plan.

Execution re-reads the Schedule and rejects drift before mutation. An absent Schedule is created from the fixed CR, an already-exact Schedule is an idempotent no-op, and a bounded differing Schedule is updated only through the fixed cron/template merge patch. Active verification re-reads the Schedule and requires exact approved cron/scope/snapshot/TTL, no deletion, no validation errors, no `FailedValidation` state and no fields outside the bounded contract. Runtime evidence exposes only bounded status such as phase and whether a prior backup exists; it never returns Backup logs, Secret data or backup-storage credentials. Arbitrary Schedule YAML, arbitrary `velero` CLI/shell and Schedule deletion are not accepted.

This closes bounded Velero recurring Schedule create/update semantics, not direct etcd snapshot/restore, provider backup-storage lifecycle, provider-specific DR or full Cluster Factory/provider execution.


## Slice 12 — Trusted OCI image registry synchronization runtime

This slice extends `artifact.mirror.apply` for artifact kind `oci-image` when both endpoints use `oci://registry/repository`. It is a constrained OCI image path, not a generic repository client.

Runtime path:

```text
ArtifactMirrorItem(oci-image, pinned sha256)
  -> exact typed ArtifactMirrorPlan / ChangeSet / execution ticket
  -> source/destination registry allowlist checks
  -> source raw-manifest digest verification
  -> fixed skopeo copy --all --preserve-digests
  -> destination tag + digest-reference raw-manifest verification
  -> typed verification / persisted audit
```

Security/runtime properties:

- source and destination registry hosts must be explicitly allowlisted; empty allowlists disable the OCI runtime
- `oci://` references contain only registry/repository; the approved SHA-256 is appended to the source internally and the approved artifact version becomes the destination tag
- arbitrary tags/digests embedded in caller endpoint strings are rejected
- the worker invokes only the fixed `skopeo` command through `subprocess.run` with `shell=False` semantics; no caller-provided CLI switches are accepted
- `--all` copies the full multi-platform image/index and `--preserve-digests` fails if digest identity cannot be maintained
- source and destination raw manifests are independently SHA-256 hashed; both the destination tag and destination digest reference must resolve to the approved digest
- an already-correct destination tag is an idempotent PASS; a mismatched existing tag fails closed unless the exact approved plan sets `replace_existing=true`
- optional source/destination authfiles are read only from trusted environment-mounted paths below `HERMES_ARTIFACT_AUTH_ROOT`; auth material never enters the plan, audit, or returned evidence
- stderr is never returned to the caller, and runtime evidence attests `arbitrary_shell=false` and `raw_credentials_returned=false`

This is still **partial air-gap closure**. A subsequent slice closes typed Helm OCI chart transport. OS/Python/package repository metadata, repository signatures/policy beyond Skopeo's configured trust behavior, dependency graph resolution, offline reference rewriting and generalized repository credential delivery remain open.


## Slice 13 — Trusted Helm OCI artifact synchronization runtime

This slice extends `artifact.mirror.apply` for artifact kind `helm-chart` when both endpoints use `oci://registry/repository`. It is deliberately a separate typed artifact path from OCI images even though both use the constrained Skopeo registry transport.

Runtime/security properties:

- source and destination registries remain exact allowlist entries and endpoint URIs remain repository-only, with no embedded tag, digest, credentials, query, or caller-controlled CLI switches
- the approved SHA-256 is the exact source OCI manifest digest and the source is addressed by digest, never by a mutable tag
- `version` must be an OCI-valid, SemVer-compatible immutable Helm chart tag; `latest` and other non-version tags are rejected
- before any copy, the source raw manifest must be schema version 2 with OCI image-manifest media type, Helm config media type, exactly one `application/vnd.cncf.helm.chart.content.v1.tar+gzip` layer, and no layer types other than the optional single Helm provenance layer
- a normal OCI image manifest cannot be relabeled as `helm-chart` and enter this path
- copy remains the fixed Skopeo command vector with no shell, environment-only bounded authfiles, retries, `--preserve-digests`, and no caller flags
- destination tag and digest references are both read back, independently SHA-256 verified against the approved digest, and revalidated for Helm media types
- an already-correct destination is idempotent; a mismatched destination tag fails unless the exact approved plan included `replace_existing=true`
- returned evidence identifies the typed Helm OCI path and media types without returning raw credentials or stderr

This remains **partial air-gap closure**. apt/yum/dnf repository metadata and packages, Python indexes/wheels/sdists, Ansible/Git-release mirroring where required, generalized authenticated repository delivery, broader signature/provenance policy, and provisioner-side offline reference rewriting remain open. A subsequent slice now adds deterministic ClusterBlueprint artifact binding, verified destination selection and dependency DAG ordering/resume evidence.


## Slice 14 — Deterministic ClusterBlueprint artifact dependency resolution

ClusterBlueprints now persist an explicit bounded list of artifact mirror item IDs. The binding is admin-controlled, rejects duplicate or malformed IDs, and requires each referenced artifact to exist. This does not infer authority from names or arbitrary repository content.

`GET /v1/cluster-blueprints/{id}/artifact-manifest` resolves the blueprint's exact provider pin, Kubernetes pin and required/selected add-on pins against those bound artifacts. Each artifact must carry non-secret `blueprint_component`, `blueprint_name`, and `dependency_key` labels, must match the exact blueprint version, and must have persisted `PASS` / `MIRRORED` verification. The resulting manifest deliberately omits source URLs and arbitrary labels and exposes only exact digest/version, verified offline destination reference and bounded verification identifiers. `file://` and `oci://` offline destinations are revalidated as credential-free references before selection.

Optional `depends_on` labels contain bound artifact IDs only. Hermes rejects self edges, unbound edges, duplicate dependency keys and graph cycles, then emits a deterministic topological `dependency_order`. If any bound artifact is unverified or otherwise invalid, the manifest is `BLOCKED` and includes `resume_from_artifact_id` for deterministic partial-sync continuation. The entire manifest is exact-hashed.

This closes the deterministic ClusterBlueprint-to-artifact selection/ordering layer and graph-level resume evidence. It does **not** yet mutate Kubespray/K3s/RKE2 inputs to consume the selected offline references, and it does not claim apt/yum/dnf or Python repository-metadata synchronization, Ansible/Git catalog closure, generalized repository credentials or broader signature/provenance policy.

## Slice 15 — READY artifact manifest binding into provisioning plans

Cluster provisioning now consumes the deterministic ClusterBlueprint artifact resolver instead of leaving it as a read-only catalog boundary. If a blueprint declares artifact dependencies, `POST /v1/clusters/{id}/provisioning-runs` resolves the manifest in the same database transaction and fails closed unless the manifest is `READY`, issue-free and integrity-valid.

The provisioning plan copies only bounded resolver output: artifact ID, component/name/dependency key, exact version and SHA-256 digest, dependency edges, and the verified `file://` or `oci://` offline destination. Source repository URLs, arbitrary labels, verification payloads and credential material are not copied into the ChangeSet or provider-job request. The exact manifest hash is bound into the typed plan, ChangeSet parameters and every per-node provider-job request.

Before a provider job can be authorized, Hermes re-resolves the current blueprint manifest and requires the same exact `READY` manifest hash. Mirror verification or dependency drift after approval therefore fails closed rather than silently changing the artifact supply. Existing online blueprints with no artifact dependency binding remain backward-compatible.

This closes the resolver-to-provisioning-plan consumption boundary only. `provisioner_rewrite_applied` remains false: trusted Kubespray/K3s/RKE2 provider workers still need to consume these bounded references and deterministically rewrite/install from offline mirrors. apt/yum/dnf and Python repository metadata synchronization, broader Ansible/Git catalogs, generalized authenticated repository delivery, and broader signature/provenance policy remain open.


## Current continuation — bounded exact-tag Git release archive mirror

`git-release` artifacts now have a bounded candidate runtime for allowlisted public HTTPS Git repositories. The ChangeSet-bound artifact plan carries only the exact immutable tag reference (`refs/tags/...`) and exact commit object ID needed by the worker. The worker disables credential helpers/prompts and all non-HTTPS Git protocols, disables HTTP redirects, uses fixed Git command vectors only, resolves the source tag before fetch, performs a depth-one exact-ref fetch, rejects repositories containing `.gitmodules`, and produces a canonical tar archive with `git archive`.

The canonical archive SHA-256 must equal the artifact's pinned digest before atomic publication. The destination is independently rehashed, an already-correct destination is idempotent, mismatched existing output is fail-closed unless the exact approved plan included replacement, network calls have a fixed two-attempt bound, and no raw Git stderr or credential material is returned.

This slice does **not** claim full Git repository mirroring, arbitrary ref/history preservation, submodule synchronization, or signed tag/commit provenance verification. It is a deterministic release-source prerequisite that can later supply a pinned Kubespray source archive; actual trusted Kubespray worker extraction/rewrite/install and apt/yum/dnf/Python/Ansible repository closure remain open. This continuation is not a completed dev.5 slice until it has its own forward-only commit, push, and exact-SHA `validate` success.
