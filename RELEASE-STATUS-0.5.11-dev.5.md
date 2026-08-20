# Hermes Control Plane 0.5.11-dev.5 release status

Status: **IN PROGRESS — NOT TAGGED / NOT PUBLISHED**

Frozen parent boundary:

- commit: `d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`
- tag: `v0.5.11-dev.4`
- branch: `dev/0.5.11`

Do not amend, reset, squash, force-push, move or recreate the frozen dev.4 tag.

## Completed dev.5 runtime slices

- real read-only Radar HTTP MCP client
- MCP initialize/session handling
- fixed read-only tool allowlist
- executable `AUTO`, `RADAR`, `NATIVE` modes
- same-environment Radar/native Kubernetes target isolation
- AUTO fallback through the existing Kubernetes Broker
- strict RADAR fail-closed behavior
- defense-in-depth Secret/env/token redaction
- Hermes-native live intelligence controls
- dev.5 source/security/static gates and release guards anchored to frozen dev.4
- Cilium/Hubble live-network runtime through the trusted Kubernetes Broker, including namespace authorization, redaction/aggregation, bounded history, SSE and Hermes-native Network Live UI
- executable Hermes-native Kubernetes diagnostics for core health, OOM/metrics/storage/events, Cilium/Hubble/DNS/ingress/NetworkPolicy, RBAC/workload security, Argo CD and rollout checks
- diagnostics target-scope enforcement, fixed read-only collectors, bounded typed findings, no Secret/env/log reads, mutation attestation and Control Plane sensitive-evidence rejection
- Hermes-native Operator Center UI contract and navigation covering the complete promised Kubernetes, Cluster Factory, infrastructure, operations and governance surface map while keeping UI state separate from runtime/provider state
- live Operator Center views for current registries, ChangeSets/audit, Radar/Hubble intelligence summaries, native diagnostics, cluster/server/provisioning state and operation/verification data without adding mutation/approval bypass controls
- trusted Kubernetes Broker day-2 runtime for node cordon/uncordon/drain, workload restart/scale and pinned Helm-backed add-on/apply operations
- day-2 runtime planning now binds a broker-produced read-only live preview/precondition into the exact typed plan before approval, rejects live-state drift at execution, and persists active typed verification automatically
- active unified cluster verification engine that executes live Kubernetes Broker probes, persists typed PASS/WARN/FAIL/SKIP results, optionally checks configured Radar health, and explicitly SKIPs unsupported provider/host/etcd/agent probes rather than inventing evidence
- ChangeSet-governed artifact blob synchronization runtime for controlled `file://` or allowlisted `https://` sources into the local mirror root, with byte/time bounds, redirect/root/symlink rejection, atomic writes, idempotent retries and independent source/destination SHA-256 verification
- trusted Argo CD GitOps sync runtime bound to a full approved commit digest, with Application state-drift rejection, fixed server-side patching, sync wait and active sync/health verification
- trusted pinned Cilium Helm upgrade runtime with exact release-state preconditions plus active Helm, Cilium-agent and sanitized Hubble verification

## Still release-blocking for dev.5 scope closure

- remaining day-2/provider operations not covered by the trusted Kubernetes runtime (worker lifecycle, Kubernetes upgrades, etcd snapshot, restore/DR, certificate rotation, decommission; broader non-Argo GitOps remains open)
- Cluster Factory runtime/repeatability closure
- provider/bare-metal/network executors or explicit user-approved deferral
- remaining air-gap protocol closure: OCI registry-to-registry copy, Helm OCI publication, package-repository metadata sync and authenticated repository credential delivery
- provider-specific verification extensions coupled to the remaining provider/bare-metal/network runtimes

`v0.5.11-dev.5` must not be created until the full dev.5 closure scope is complete,
local validation passes, and branch CI succeeds on the exact intended tag SHA.
