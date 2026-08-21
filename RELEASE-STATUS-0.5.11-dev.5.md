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
- trusted digest-pinned OCI-image registry-to-registry synchronization with source/destination registry allowlists, full multi-arch copy, preserved digests, idempotent tag verification and no shell/raw-credential exposure
- trusted typed Helm OCI chart registry-to-registry synchronization with SemVer-compatible immutable tags, Helm config/chart-layer media-type validation, digest preservation, destination read-back verification, idempotency and non-Helm artifact rejection
- deterministic ClusterBlueprint artifact dependency resolution with explicit artifact-ID binding, required provider/Kubernetes/add-on version coverage, verified offline destination selection, dependency-key uniqueness, DAG ordering/cycle rejection, and partial-sync resume evidence without credential material
- offline provisioning-plan artifact binding that requires a READY integrity-checked ClusterBlueprint artifact manifest, copies only verified destination/digest metadata into the exact ChangeSet and per-node provider-job request, and rechecks the current manifest hash before provider-job authorization
- bounded exact-tag Git release archive synchronization for allowlisted public HTTPS repositories, with immutable tag+commit binding, fixed credential-free Git transport, submodule rejection, canonical archive SHA-256 verification, atomic publication and idempotent retry; exact-SHA `validate` is green at `395059d63d86316d3056cd28790941726c7e42dd` (run `32477791912`)
- typed digest-pinned Ansible Galaxy collection archive synchronization with exact namespace/name/SemVer identity, MANIFEST.json -> FILES.json checksum binding, per-file SHA-256 verification, unsafe tar member rejection and no filesystem extraction; exact-SHA CI green at `26855cbb6f45176ee99029cdbc29b7c847ae79b6` (run `32478857268`)
- merged Batch A delivery substrate is committed/pushed and exact-SHA `validate` CI-green at `aab6d31ac8af598ee7d9651543137776ca82391b` (run `32481855314`): signed APT repository snapshots (Release.gpg -> Release SHA256 -> Packages -> .deb), signed RPM repository snapshots (repomd.xml.asc -> repomd SHA256 -> primary -> .rpm), and PEP 503-style Python Simple snapshots with `#sha256=` distribution binding; atomic staging/rollback, idempotency, bounded HTTPS retries and environment-mounted auth/keyrings are enforced
- development Docker image publication is decoupled from `dev/**` pushes: `validate` remains branch-triggered while `publish-images` stays on main/tags/manual publication boundaries
- trusted Argo CD GitOps sync runtime bound to a full approved commit digest, with Application state-drift rejection, fixed server-side patching, sync wait and active sync/health verification
- trusted pinned Cilium Helm upgrade runtime with exact release-state preconditions plus active Helm, Cilium-agent and sanitized Hubble verification
- trusted one-shot Velero Backup runtime with exact backup-state preconditions, fixed CR creation, namespace-scope enforcement and active completion/error/snapshot-count verification
- trusted bounded Velero Restore runtime for explicit namespaces with CRITICAL two-person approval, exact source-Backup/Restore-state preconditions, fixed non-destructive CR creation and active completion/error/plugin-operation verification
- trusted Velero Schedule create/update runtime with fixed no-more-frequent-than-hourly cron, exact live-state binding, namespace scope enforcement, bounded Backup template fields and active validation/spec verification

- merged Batch B trusted existing-host cluster provider runtime: disabled by default on the existing Node Agent image; exact HMAC-signed ChangeSet/typed-plan tickets; one-time ticket replay rejection; private per-execution SSH credential staging; fixed no-shell/no-caller-CLI provider execution; Kubespray v2.28.1 plus pinned Ansible dependency contract; role-aware offline K3s/RKE2 server/agent installation; deterministic offline registry/file/package/PyPI binding; worker add/remove/replace; Kubernetes upgrades; certificate rotation; bounded existing-host maintenance; direct K3s/RKE2 embedded-etcd snapshot/restore and existing-host DR; active service/API/snapshot/reset-state verification; execution output and raw credentials suppressed

## Still release-blocking for dev.5 scope closure

- Batch C provider-capacity executors: infrastructure creation/destruction/scale, true cluster decommission and capacity-backed template cloning
- Kubespray direct-etcd snapshot/restore/DR remains fail-closed; Batch B direct embedded-etcd recovery is bounded to K3s/RKE2
- provider/bare-metal/network executors for the intended original scope, or explicit user-approved deferral where real runtime cannot be completed
- matching host/direct-etcd/provider/bare-metal/network/cloud active verification collectors; unsupported collectors remain SKIP
- broader non-Argo GitOps or full Git-history/submodule/Galaxy-role API behavior only if the final original-scope audit proves those capabilities were promised
- disposable real-target repeatability/evidence where available; never convert local integration into invented real-target evidence
- final full scope-conformance re-audit and dev.5 release gate

`v0.5.11-dev.5` must not be created until the full dev.5 closure scope is complete,
local validation passes, and branch CI succeeds on the exact intended tag SHA.
