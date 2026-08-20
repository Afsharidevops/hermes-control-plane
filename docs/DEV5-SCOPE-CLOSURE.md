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

Radar alone did not close the roadmap. The Hubble and diagnostics slices below close
two more runtime gaps, while broader operator UI, day-2/provider executors,
air-gap synchronization and active unified verification remain subsequent
`0.5.11-dev.5` work unless explicitly deferred by the user.

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

Remaining dev.5 release blockers are runtime/executor work: day-2/add-on active
execution and verification, Cluster Factory repeatability, provider/bare-metal/
network executors or explicit deferral, air-gap synchronization/integrity runtime,
and the active unified verification engine.


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

This slice intentionally leaves `cluster.worker.add/remove/replace`, GitOps sync, Kubernetes/Cilium upgrade, etcd snapshot, restore/DR, certificate rotation, maintenance provider steps, decommission, infrastructure scale and template clone on their explicit provider-worker contracts. Those operations remain release-blocking until a real executor exists or the user explicitly defers them.
