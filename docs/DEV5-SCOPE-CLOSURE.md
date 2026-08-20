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

This slice intentionally left `cluster.worker.add/remove/replace`, GitOps sync, Kubernetes/Cilium upgrade, etcd snapshot, restore/DR, certificate rotation, maintenance provider steps, decommission, infrastructure scale and template clone on their explicit provider-worker contracts at that point; Slice 8 closes the trusted Argo CD sync and Cilium-upgrade subset. Those operations remain release-blocking until a real executor exists or the user explicitly defers them.

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
protocol is complete. OCI registry-to-registry image copy, Helm OCI registry push,
OS/Python package repository metadata mirroring, and authenticated repository
credential delivery remain release-blocking runtime work. Plans using unsupported
protocol pairs are retained for compatibility but receive executor
`artifact-mirror-contract` and cannot enter the trusted runtime execution path.


## Slice 8 — Trusted GitOps sync + Cilium lifecycle runtime

This slice extends the exact-preview-bound Kubernetes day-2 executor with two additional deterministic operations that do not require cloud/BMC credentials.

### Argo CD GitOps sync

`cluster.gitops.sync` now requires a same-environment Kubernetes target, an authorized Application namespace, an exact Argo CD `Application` name, and a full 40- or 64-character commit digest. Planning reads bounded Application state, validates the fixed merge patch with server-side dry-run, and binds the resulting Application state hash into the approved typed plan. Execution re-reads that state, rejects drift, applies only the fixed `Application.operation.sync` patch, waits for `status.sync.status=Synced`, and actively verifies both exact observed commit digest and Application health. No `argocd` CLI or arbitrary Kubernetes patch body is accepted from the caller.

### Cilium upgrade

`cluster.cilium.upgrade` now executes through the existing pinned Helm runtime only when the approved parameters target release `cilium`, namespace `kube-system`, a Cilium chart reference, and an explicit pinned version. The Helm release snapshot is exact-preview-bound before approval. After execution Hermes actively verifies Helm deployment state, Cilium agent Pod readiness, and sanitized Hubble Relay reachability through the trusted broker.

This remains partial day-2/Cluster Factory closure. Worker lifecycle, Kubernetes version upgrades, etcd snapshot/restore, certificate rotation, provider maintenance/decommission, infrastructure scale, disaster recovery and template cloning still require real trusted provider/provisioner executors or explicit user-approved deferral. Broader Flux/non-Argo GitOps execution also remains open.
