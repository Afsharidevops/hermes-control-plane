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

This remains **partial air-gap closure**. apt/yum/dnf repository metadata and packages, Python indexes/wheels/sdists, broader Ansible Galaxy catalog/role handling where required, generalized authenticated repository delivery, broader signature/provenance policy, and provisioner-side offline reference rewriting remain open. A subsequent slice now adds deterministic ClusterBlueprint artifact binding, verified destination selection and dependency DAG ordering/resume evidence.


## Slice 14 — Deterministic ClusterBlueprint artifact dependency resolution

ClusterBlueprints now persist an explicit bounded list of artifact mirror item IDs. The binding is admin-controlled, rejects duplicate or malformed IDs, and requires each referenced artifact to exist. This does not infer authority from names or arbitrary repository content.

`GET /v1/cluster-blueprints/{id}/artifact-manifest` resolves the blueprint's exact provider pin, Kubernetes pin and required/selected add-on pins against those bound artifacts. Each artifact must carry non-secret `blueprint_component`, `blueprint_name`, and `dependency_key` labels, must match the exact blueprint version, and must have persisted `PASS` / `MIRRORED` verification. The resulting manifest deliberately omits source URLs and arbitrary labels and exposes only exact digest/version, verified offline destination reference and bounded verification identifiers. `file://` and `oci://` offline destinations are revalidated as credential-free references before selection.

Optional `depends_on` labels contain bound artifact IDs only. Hermes rejects self edges, unbound edges, duplicate dependency keys and graph cycles, then emits a deterministic topological `dependency_order`. If any bound artifact is unverified or otherwise invalid, the manifest is `BLOCKED` and includes `resume_from_artifact_id` for deterministic partial-sync continuation. The entire manifest is exact-hashed.

This closes the deterministic ClusterBlueprint-to-artifact selection/ordering layer and graph-level resume evidence. It does **not** yet mutate Kubespray/K3s/RKE2 inputs to consume the selected offline references, and it does not claim apt/yum/dnf or Python repository-metadata synchronization, broader Ansible Galaxy catalog/role closure, generalized repository credentials or broader signature/provenance policy.

## Slice 15 — READY artifact manifest binding into provisioning plans

Cluster provisioning now consumes the deterministic ClusterBlueprint artifact resolver instead of leaving it as a read-only catalog boundary. If a blueprint declares artifact dependencies, `POST /v1/clusters/{id}/provisioning-runs` resolves the manifest in the same database transaction and fails closed unless the manifest is `READY`, issue-free and integrity-valid.

The provisioning plan copies only bounded resolver output: artifact ID, component/name/dependency key, exact version and SHA-256 digest, dependency edges, and the verified `file://` or `oci://` offline destination. Source repository URLs, arbitrary labels, verification payloads and credential material are not copied into the ChangeSet or provider-job request. The exact manifest hash is bound into the typed plan, ChangeSet parameters and every per-node provider-job request.

Before a provider job can be authorized, Hermes re-resolves the current blueprint manifest and requires the same exact `READY` manifest hash. Mirror verification or dependency drift after approval therefore fails closed rather than silently changing the artifact supply. Existing online blueprints with no artifact dependency binding remain backward-compatible.

This closes the resolver-to-provisioning-plan consumption boundary only. `provisioner_rewrite_applied` remains false: trusted Kubespray/K3s/RKE2 provider workers still need to consume these bounded references and deterministically rewrite/install from offline mirrors. apt/yum/dnf and Python repository metadata synchronization, broader Ansible Galaxy catalog/role handling, generalized authenticated repository delivery, and broader signature/provenance policy remain open.


## Slice 16 — bounded exact-tag Git release archive mirror

`git-release` artifacts now have a bounded candidate runtime for allowlisted public HTTPS Git repositories. The ChangeSet-bound artifact plan carries only the exact immutable tag reference (`refs/tags/...`) and exact commit object ID needed by the worker. The worker disables credential helpers/prompts and all non-HTTPS Git protocols, disables HTTP redirects, uses fixed Git command vectors only, resolves the source tag before fetch, performs a depth-one exact-ref fetch, rejects repositories containing `.gitmodules`, and produces a canonical tar archive with `git archive`.

The canonical archive SHA-256 must equal the artifact's pinned digest before atomic publication. The destination is independently rehashed, an already-correct destination is idempotent, mismatched existing output is fail-closed unless the exact approved plan included replacement, network calls have a fixed two-attempt bound, and no raw Git stderr or credential material is returned.

This slice does **not** claim full Git repository mirroring, arbitrary ref/history preservation, submodule synchronization, or signed tag/commit provenance verification. It is a deterministic release-source prerequisite that can later supply a pinned Kubespray source archive; actual trusted Kubespray worker extraction/rewrite/install and apt/yum/dnf/Python/Ansible repository closure remain open. The slice is committed/pushed and exact-SHA `validate` is green at `395059d63d86316d3056cd28790941726c7e42dd` (run `32477791912`).


## Slice 17 — typed Ansible Galaxy collection archive mirror

`ansible-collection` artifacts use the bounded local-file/allowlisted-HTTPS -> controlled-file mirror transport but are not treated as arbitrary blobs. The exact approved plan carries only `ansible_namespace`, `ansible_name`, semantic version and SHA-256 identity.

Before atomic publication, Hermes validates the gzip tarball in-memory/streamed without extracting archive paths to disk. It rejects absolute/traversal/duplicate member names, symbolic/hard links and device/FIFO members; requires root `MANIFEST.json` and `FILES.json`; binds `collection_info.namespace`, `name` and `version` to the approved artifact; verifies the MANIFEST-declared SHA-256 of `FILES.json`; and verifies every regular file checksum declared in the file manifest. Existing destinations are accepted idempotently only after both outer digest and internal collection validation pass.

This slice is committed/pushed and exact-SHA `validate` is green at `26855cbb6f45176ee99029cdbc29b7c847ae79b6` (run `32478857268`). It closes exact Galaxy collection artifact validation/synchronization. Standalone Ansible role source archives, where required, are supplied through the already-bounded exact-tag `git-release` path and can be classified/bound by the ClusterBlueprint artifact catalog; Hermes does **not** claim a Galaxy role API/server or arbitrary Git history/submodules. Collection dependency discovery from Galaxy APIs, collection GPG/signature verification, apt/yum/dnf/Python repository metadata synchronization, generalized repository credentials, and the trusted Kubespray/K3s/RKE2 provider-worker remain separate boundaries.

## Batch A — signed package repository snapshots + CI publication efficiency

Batch A closes the remaining bounded package-repository substrate as typed snapshot artifacts rather than treating package files as generic blobs. New kinds are `apt-repository`, `rpm-repository` and `python-repository`, with `file://` or allowlisted/authenticated `https://` snapshot sources and controlled `file://` directory destinations.

Every snapshot is outer SHA-256 pinned and contains a root `HERMES-REPOSITORY-SNAPSHOT.json` that binds repository kind/ID/version and the exact regular-file inventory, size and SHA-256 for all repository content. Archive traversal, duplicate names, symlink/hardlink/device/FIFO members and expanded-byte overflow are rejected. Content is extracted only into a private staging directory, natively verified there, then atomically renamed into the mirror; replacement uses a rollback backup and retrying an already-valid destination is idempotent.

APT validation requires `Release` + detached `Release.gpg`, a trusted environment-mounted keyring verified through a fixed `gpgv` command, SHA-256/size binding of supported Packages indexes from Release metadata, and exact `.deb` hash/size verification from every package stanza. RPM validation requires signed `repomd.xml`, SHA-256/size verification of referenced repodata, primary metadata parsing and exact `.rpm` SHA-256/size verification. Python validation requires an offline Simple index with relative distribution links carrying exact `#sha256=` fragments; every mirrored wheel/sdist must be referenced and verified.

Authenticated HTTPS uses only a host-scoped Authorization value read from `HERMES_ARTIFACT_HTTPS_AUTHFILE` below `HERMES_ARTIFACT_AUTH_ROOT`; repository trust uses `HERMES_ARTIFACT_REPOSITORY_KEYRING` below the same root. Credentials/key contents are never returned or inserted into plans/audit. HTTPS fetches have a fixed two-attempt bound, all repository metadata has explicit byte limits, and evidence records atomic partial-sync recovery rather than claiming best-effort completion.

The same batch removes `dev/**` from `.github/workflows/publish-images.yml` while retaining `dev/**` in the `validate` workflow. Development pushes therefore continue exact-SHA branch validation without publishing seven Docker images. Main/tag/manual image publication behavior remains intact.

This batch supplies repository trees that later trusted Kubespray/K3s/RKE2 workers can consume. It does **not** set `provisioner_rewrite_applied=true` and does not claim provisioner execution, worker lifecycle, provider runtime or real-target evidence. Standalone Ansible role source archives are covered by the exact-tag `git-release` artifact path where required; no Galaxy role API/server is claimed. Full Git history/submodule semantics remain conditional on the final original-scope audit.


## Batch B — trusted Kubespray/K3s/RKE2 existing-host provider runtime

Batch B adds a deterministic provider-worker execution boundary without creating a new Hermes image: the existing Node Agent image exposes `/v1/provider/preview` and `/v1/provider/execute`, while execution stays disabled by default. The Control Plane binds approved ClusterProvisioningPlan/provider day-2 operations into exact typed plans and short-lived HMAC-signed execution tickets whose preconditions name `cluster-provider-worker`, the typed-plan hash, policy generation, provider-job identity and exact artifact-manifest hash. Replayed tickets are rejected.

The worker accepts only a fixed `kubespray`/`k3s`/`rke2` operation matrix. It derives inventory from approved server snapshots, requires PASS/configured hosts, validates host fingerprints through mounted credential profiles, stages SSH identity/known-host material only into a private temporary workspace, runs fixed `ansible-playbook` vectors with `shell=False` and suppressed stdout/stderr, performs a fixed active-verification playbook, and deletes the workspace regardless of success/failure. Raw credentials and arbitrary SSH/shell/CLI input are not returned or accepted.

For operations that install or upgrade software, the typed plan must contain the exact READY offline artifact supply with deterministic rewrite applied. Mirrored file artifacts are rehashed under the configured mirror root; all OCI dependencies must target one offline registry. Kubespray execution is pinned to provider release v2.28.1 and the compatible Ansible dependency set and requires internal file/APT/RPM/PyPI endpoints. K3s/RKE2 paths are role-aware and use only approved local artifacts/registry references.

Provider day-2 runtime coverage now includes worker add/remove/replace, Kubernetes upgrades, certificate rotation and bounded maintenance on already-approved hosts. K3s/RKE2 direct embedded-etcd snapshot/restore and existing-host DR use their fixed direct provider/server recovery paths; verification checks provider services, Kubernetes API readiness, snapshot presence and restore reset-state. Kubespray direct-etcd snapshot/restore/DR remains explicitly unsupported and fails closed.

Batch B intentionally does not claim infrastructure-capacity lifecycle. True cluster decommission, infrastructure scale/provider recreation, capacity-backed template cloning and full provider-recreation DR require Batch C's VMware/OpenStack/cloud/bare-metal/network executors. Direct etcd quorum collectors and the matching provider-specific collectors also remain open until their trusted runtime paths exist. Evidence from this slice is contract/mock/local-integration evidence unless a disposable real target is actually exercised.


## Batch C local continuation — bounded Redfish infrastructure runtime

The first Batch C runtime slice promotes only Redfish `inventory.refresh`, `power.set`, `boot.set`, `virtual-media.insert`, `virtual-media.eject` and bounded `bios.apply` from infrastructure contracts into trusted execution. Planning obtains an active safe Redfish system snapshot through the Node Agent worker and binds its exact hash plus deterministic desired-state diff into the typed plan. After normal ChangeSet authorization, execution requires a short-lived one-time HMAC ticket bound to the exact typed-plan hash and `infrastructure-provider-worker`; the worker re-reads the provider immediately before mutation and rejects current-state drift.

Credentials are resolved only from worker-mounted profiles below `HERMES_INFRASTRUCTURE_CREDENTIAL_ROOT`. Raw credential material is excluded from plans, audit and evidence. Redfish access is HTTPS-only by default with verified TLS, no redirects, no embedded URL credentials/query/fragment, and same-origin resource traversal. Mutation surfaces are fixed Redfish APIs rather than generated shell/SSH/provider CLI, and post-change state is actively verified with bounded safe evidence. Runtime execution remains disabled by default. Virtual-media insertion is additionally constrained to write-protected, credential-free HTTPS image URLs whose hostname is explicitly allowlisted in the provider snapshot; selected manager/media IDs are exact provider capabilities, and unsafe pre-existing media references are redacted from returned evidence.

Classification for this local slice: Redfish inventory/power/boot/virtual-media and BIOS settings staging are **INTEGRATION-COMPLETE locally, pending commit/push/exact-SHA CI and real-target evidence**. IPMI/PXE, firmware, disk/RAID, management/provisioning network, switch/network and VMware/OpenStack/AWS/Azure/GCP capacity paths remain contract-only/missing runtime as applicable. Infrastructure-backed decommission/scale/template cloning/provider-recreation DR and matching active collectors remain open. No unsupported collector is promoted from `SKIP`, no real-target evidence is invented, and Batch C/dev.5 is not declared complete by this slice.


BIOS settings are intentionally verified at the Redfish settings resource: only requested attribute keys are included in preview/evidence, values are restricted to bounded scalar strings/integers/booleans, names must be explicitly provider-allowlisted, SettingsObject links must remain same-origin, and a successful `bios.apply` means the provider accepted/reflected the desired or pending setting. It does not fabricate proof that reboot-dependent firmware state is already active; reboot/apply-time convergence remains a separate governed step.


### Batch C local continuation — bounded Redfish firmware update

Redfish `firmware.apply` is now integration-complete locally through the same trusted infrastructure-provider worker. The desired state is restricted to one credential-free HTTPS `image_url`, one exact `component_id`, and one bounded `expected_version`. Both the image hostname and firmware component ID must be explicitly allowlisted in the exact provider snapshot before the worker contacts the BMC.

The worker discovers `UpdateService`, `FirmwareInventory` and `#UpdateService.SimpleUpdate` through same-origin Redfish references, rejects a disabled update service or non-updateable component, and posts only the fixed `ImageURI` plus exact `Targets` vector. Preview binds the component's current version into the approved state hash; execution rejects drift, skips the mutation when the exact expected version is already present, and otherwise polls the same exact firmware inventory component until the expected version is observed or the bounded firmware verification window expires. Firmware polling has separate configurable attempt/delay bounds because device updates can take materially longer than ordinary BMC mutations.

This is local/integration evidence, not disposable real-target proof. Redfish firmware update does not close IPMI/PXE, disk/RAID, management/provisioning network, switch/network, cloud/virtualization capacity, provider-recreation lifecycle or their active collectors.

- Batch C5a adds locally integration-complete constrained IPMI LAN+ fallback for fixed power/boot operations. It is a fallback only; Redfish remains preferred. C5b below closes the local PXE/iPXE unattended runtime slice.

### Batch C5b — private-offline PXE/iPXE unattended provisioning

`pxe` `os.provision` and `os.reimage` are now **INTEGRATION-COMPLETE locally** through the existing trusted infrastructure-provider worker. The Control Plane requires a `private-offline` PXE provider using `shared-readonly-mirror` artifact delivery, one exact registered Server snapshot carrying provisioning IP/NIC/MAC plus a trusted Redfish/IPMI `boot_provider_id`, and a READY exact artifact supply. The PXE artifact resolver accepts only exact artifact-mirror IDs with PASS/MIRRORED verification, SHA-256 digests and local `file://` destinations; at least kernel/initrd/unattended roles are required. The artifact supply is exact-hash bound into the typed plan, re-resolved before execution authorization and rehashed under the configured artifact mirror root by the worker before any mutation.

The PXE worker credential profile is separate from plans/UI/audit. It contains the private controller bearer token and mappings to worker-side unattended-profile and callback-token files. Unattended profiles are bounded structured JSON and reject arbitrary command/script fields. Only the callback token SHA-256 and reference name are planned; raw token material is used only by the worker when calling the fixed private HTTPS controller. The controller node identity must exactly match the registered server ID, provisioning NIC/MAC and approved plan/artifact/callback bindings.

Execution reuses the already constrained Redfish/IPMI boot adapter to set one-time PXE boot rather than accepting a generated boot command. Completion requires a validated monotonic `requested -> booting -> installer-started -> installing -> complete` controller history and exact callback bindings, followed by a bounded active TCP readiness probe to the registered management endpoint. Replay, preview drift, artifact drift, path escape/symlink, controller-state regression, callback mismatch, identity mismatch, timeout and failed state are fail-closed. Evidence suppresses raw credentials/stdout/stderr and explicitly attests no arbitrary CLI/shell/iPXE script surface.

This remains local/mock integration evidence until exercised against a disposable real provisioning environment; no DHCP/TFTP/iPXE-server success is invented. Disk/RAID, Secure Boot/SR-IOV/IOMMU/boot-order state, management/provisioning switch/network runtime, cloud/virtualization capacity, infrastructure-backed decommission/scale/cloning/provider-recreation DR and matching active collectors remain open.

### Batch C6 — Redfish disk/RAID desired-state runtime

Redfish `storage.volume.apply` and `storage.volume.delete` are now **INTEGRATION-COMPLETE locally** through the trusted infrastructure-provider worker. The provider snapshot must explicitly allow each storage controller, exact physical drive ID, RAID type and volume name; destructive deletion additionally requires `allow_volume_delete=true`. Planning rejects arbitrary fields, unsafe identifiers, duplicate drives and invalid RAID minimum-drive counts before runtime preview.

Preview actively follows only same-origin Redfish Storage resources and binds the controller, physical-drive stable identity/serial/model/part/capacity/health/state and current volume topology into the exact approved current-state hash. Creation fails closed for missing/ambiguous/unhealthy drives, duplicate stable serials, drives already consumed by another volume, duplicate volume names or an existing same-name volume with different RAID/drives. Exact existing desired volumes are idempotent.

Execution creates only via a fixed Redfish VolumeCollection POST containing the approved `Name`, `RAIDType` and exact discovered Drive links; arbitrary storage CLI and caller-supplied Redfish bodies are not accepted. In-place RAID reshaping is intentionally unsupported. Volume deletion is a separate **CRITICAL** operation requiring exact repeated volume-ID confirmation and explicit provider deletion capability, and targets only the exact same-origin volume URI discovered during active preview. Post-change verification requires exact resulting RAID/drive membership for create or verified absence for delete. Replay and preview-state drift remain fail-closed.

This is local/mock integration evidence, not disposable-controller proof. Secure Boot/SR-IOV/IOMMU/boot-order state, management/provisioning network, switch/network, cloud/virtualization capacity, capacity-backed decommission/scale/cloning/provider-recreation DR and matching active collectors remain open.


### Batch C7 — Secure Boot, SR-IOV, IOMMU and persistent boot-order state

Local integration now includes trusted Redfish `secure-boot.apply`, `sriov.apply`, `iommu.apply` and `boot-order.apply`. Secure Boot is bound to the standard Redfish SecureBoot resource and must activate on reboot; PASS requires `SecureBootCurrentBoot` to match the requested state after the governed reset, not merely a pending `SecureBootEnable` value. SR-IOV/IOMMU are limited to provider-declared BIOS attribute/value mappings that are independently BIOS-allowlisted. Persistent boot order is limited to exact provider-allowlisted `BootOptionReference` values that are actively discovered and enabled, and only the fixed `Boot.BootOrder` body is patched.

Immediate/reboot activation is provider-fixed for mapped features and boot order; reboot paths require the system to be powered on, use only a fixed approved Redfish reset type, and poll active state with a bounded restart-specific verification window. Transient BMC unavailability is tolerated only during that bounded reboot verification window. No arbitrary BIOS attribute, Redfish body, shell or CLI surface is introduced.

This remains local/mock integration evidence. Management/provisioning network state, switch/network mutation, cloud/virtualization capacity workers, capacity-backed decommission/scale/cloning/provider-recreation DR and matching real-target collectors remain open. Proxmox VE and VMware Workstation are explicitly added to the provider plan as CONTRACT-ONLY targets; they are not runtime-complete.

### Batch C9 — constrained OpenConfig RESTCONF switch runtime

`network-switch` now has a deliberately narrow local/integration runtime for exactly one provider profile: `openconfig-restconf-v1` with API version `openconfig-restconf-1.0`. Only `vlan.ensure`, `port.configure`, and read-only `lldp.observe` enter the existing governed infrastructure-worker path. `bond.ensure`, `network.attach`, `network.detach`, and `bgp.configure` remain contract-only and are not dispatched to the trusted runtime.

Provider registration and planning require an HTTPS IP-literal endpoint at the exact `/restconf/data` root, the pinned profile/version pair, a bounded model identifier, and explicit unique port/VLAN/mode allowlists. Desired state is closed and typed: one bounded VLAN name, or one allowlisted access/trunk port configuration; LLDP accepts no caller fields. The worker owns all RESTCONF paths, methods, headers, bodies, and credential handling. It rejects userinfo, query/fragment/alternate roots, hostname endpoints, redirects, ambient proxies, oversized/non-object JSON, and arbitrary CLI/shell/NETCONF surfaces.

Planning binds a sanitized deterministic current-state snapshot and hash into the approved typed plan. Execution re-reads the same bounded state, rejects drift, uses ETag `If-Match` for fixed mutations when supplied by the device, and actively re-collects until exact VLAN/port convergence. LLDP performs collection and re-collection without mutation. Returned evidence keeps only bounded identifiers, ETags, and sanitized neighbor names/ports; it suppresses management addresses, chassis identifiers, free-form descriptions/capabilities, raw device configuration, and credentials.

This is local/mock integration evidence only. Execution is disabled by default. Disposable real-switch validation remains required for the exact profile, including TLS behavior, ETag behavior, preview drift rejection, idempotence, convergence, replay rejection, and redaction. NETCONF, generic RESTCONF, hostname endpoints, BGP, bonds, attach/detach, other vendor/model profiles, management/provisioning-network execution, and switch-capacity lifecycle remain open.

### Trusted host observation for unified verification

The canonical `hosts` check can now consume one fixed read-only collector contract, `host-network-local-v1`. The collector runs as a separate, disabled-by-default host-observer workload with its own bearer token. It mounts no SSH, infrastructure, provider, or execution credentials and exposes only health plus the fixed host-network collection route. Its evidence is bounded to interface name/state/MTU and bond/VLAN counts; MAC/IP addresses, routes, DNS, raw files, environment data, mount paths, credentials, arbitrary CLI, shell, plans, tickets, and mutation surfaces are excluded.

A fresh observer result is trusted only through an explicit persisted registered-server binding whose collector identity matches exactly. Cluster verification resolves bindings from the exact cluster profile server membership and does not infer association from names, IPs, labels, environments, Kubernetes nodes, preflight data, or old verification results. Missing/disabled bindings or absent host roots remain `SKIP`; configured observer failures, malformed/unsafe/stale data, and identity mismatch fail closed; partial multi-server coverage is `WARN`. One observer identity cannot be reused as active coverage for another server.

This is local contract/integration evidence only, not production host proof. Multi-node observer routing, direct etcd quorum collection, Hermes Agent verification, provider/cloud capacity collectors, and real-target C8/C9 evidence remain open.
