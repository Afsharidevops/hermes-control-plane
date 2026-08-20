# Changelog

- Dev.5 artifact mirror runtime slice: ChangeSet-governed controlled file/allowlisted-HTTPS artifact blob synchronization, atomic publication, idempotent retry and independent source/destination SHA-256 verification; unsupported OCI/repository protocol pairs remain explicit contracts.
- Dev.5 active unified verification slice: live Kubernetes-broker probes mapped into deterministic PASS/WARN/FAIL/SKIP checks, optional active Radar health, bounded/redacted evidence, persistence and audit; unsupported host/etcd/agent/provider probes remain explicit SKIP instead of synthetic success.
- Dev.5 trusted Kubernetes day-2 runtime slice: exact-preview-bound node cordon/uncordon/drain, workload restart/scale and pinned Helm-backed add-on/apply execution through the Kubernetes Broker with drift rejection and persisted active verification.
- Dev.5 Operator Center UI slice: typed full-scope operator navigation for Kubernetes, Cluster Factory, infrastructure, operations and governance, with live data where available and explicit PARTIAL/CONTRACT_ONLY runtime states where executors are not yet complete.
- Dev.5 native diagnostics runtime slice: executable broker-owned read-only checks for node/pod/workload/OOM/metrics/storage/events, Cilium/Hubble/DNS/ingress/NetworkPolicy, RBAC/workload security, Argo CD and rollout health with target-scope enforcement and bounded typed evidence.
- Dev.5 Hubble runtime slice: trusted Kubernetes Broker collector, pinned Hubble CLI, namespace authorization, typed redaction/aggregation, bounded history, SSE, and Hermes-native Network Live batch UI.

## 0.5.11-dev.5 (in progress)

- begin scope-closure work on top of frozen `v0.5.11-dev.4` without rewriting frozen history
- add a real HTTP MCP Radar read adapter with initialization/session handling and a fixed allowlist for dashboard, issues, resource list/detail, search, topology and neighborhood
- make Radar a first-class integration kind and add executable `AUTO`, `RADAR`, and `NATIVE` cluster-intelligence query modes
- add same-environment Radar/native-target isolation, strict RADAR fail-closed behavior and AUTO fallback through the existing constrained Kubernetes Broker
- add defense-in-depth redaction for Kubernetes Secret bodies, direct workload environment values, authorization/token/password-shaped fields, and bounded provider responses
- explicitly forbid direct Control Plane credential-material resolution for authenticated Radar endpoints; authenticated provider access must use a credential-service/provider-worker boundary
- add Hermes-native live intelligence controls and dev.5 Radar runtime/security regression tests
- move guarded apply/validate/push scripts and CI source gates to the exact frozen dev.4 boundary and dev.5 version
- add trusted artifact blob synchronization runtime with no redirects or embedded credentials, source/destination root confinement, byte/time limits, exact digest verification, idempotent retry, persisted verification and audit; full registry/repository protocol synchronization remains open

## 0.5.11-dev.4

- add a shared typed Operations Center intent backend for Web/UI, Telegram, Hermes Bot/AI and API channels while keeping mutations bot-authenticated and ChangeSet-governed
- add centralized fleet views/selectors with exact cluster target snapshots and fail-closed target-drift authorization
- add advanced deterministic day-2 plan contracts for worker/node/workload/add-on/Helm/GitOps/upgrades/etcd/restore/certificates/maintenance/decommission/scaling/cloning/DR
- add first-class typed provider foundations for VMware, OpenStack, AWS, Azure and GCP with explicit API/provider-worker version pins and Credential Service references only
- add typed Redfish, IPMI and PXE bare-metal contracts plus switch/network desired-state contracts without arbitrary generated shell/CLI
- add digest-pinned OCI image, Helm chart, package and Git/release artifact mirroring plans with source/destination SHA-256 verification stages
- add generic constrained operation jobs with integrity-checked approvals, exact typed-plan/hash binding, short-lived HMAC-signed execution tickets, one-time approval consumption at execution start, and provider/cluster/artifact/fleet target-drift rejection
- add persisted unified typed verification results with secret-shaped evidence rejection
- add Hermes-native Operations Center fleet/provider/artifact/job/verification observability pages without mutation/approval bypass controls
- add dev.4 source-security/config-static gates and guarded apply/validate/push scripts bound to frozen dev.3; dev.4 tagging additionally requires the exact branch-CI-green SHA

## 0.5.11-dev.3

- add persisted typed ClusterBlueprint, ClusterProfile, Cluster, NodeRole, ProvisioningRun, AddonPlan, UpgradePlan and BackupPlan resources
- add deterministic production Kubespray, lab/edge K3s and hardened RKE2 execution-spec contracts sourced from Server Registry and PASS preflight state, with explicit provider-version pins
- bind cluster provisioning to HIGH-risk ChangeSets and exact-hash provider jobs per node
- make Cilium the Cluster Factory network contract and retain Hubble authorization/redaction/aggregation requirements
- add Hermes-native Cluster Factory and Radar/Hubble intelligence UI views without adding mutation bypasses
- add five deterministic operational profiles (`lab-minimal`, `lab-full`, `production`, `production-ha`, `production-hardened`) plus governed Cilium/Hubble, kube-vip, MetalLB, storage, ingress, TLS, GitOps, observability, cost and backup add-ons with explicit version-pin requirements
- add typed upgrade and backup planning foundations plus native read-only diagnostics inspired by useful Aban ideas without a kubectl-aban-plugin runtime dependency
- add dev.3 source/security and config/static gates and update apply/validate/push handoff scripts for the frozen dev.2 boundary

## 0.5.11-dev.2

- complete the isolated Credential Service with encrypted local storage, external references, safe metadata/name update, rotation, revocation, safe testing, metadata-only synchronization, audit and failure-closed behavior
- add Server Registry with environment/site/rack/zone labels, pinned SSH host fingerprints, duplicate-IP controls, SSH/BMC credential bindings and discovered inventory
- add deterministic fixed read-only SSH/host preflight ChangeSets and provider-job result binding
- add generic provider lifecycle descriptors for SSH, Kubespray, K3s, RKE2, Radar and Hubble
- add HIGH-risk bootstrap ChangeSet planning gated by PASS preflight, policy, approval and exact plan hash
- add provider-job stage events, SSE log/status streaming, pause/resume and bounded retry foundation
- make Radar/Hubble first-class while explicitly prohibiting governance bypass and requiring Hubble authorization/redaction/aggregation before AI/UI
- add the Credential Service to the GitHub Actions multi-arch Docker image matrix and use Docker Hub username/token from GitHub Secrets
- add dev.2 source/security and static configuration gates plus separate apply/validate/push handoff scripts
- keep local push logic source/tag-only; production image publishing remains GitHub Actions -> Docker Hub

## 0.5.11-dev.1

- add the compressed v0.5.11 completion roadmap
- add audited Application registry CRUD
- add shared adapter capability/security contract discovery
- add policy-bound signed agent task envelopes with capability enforcement
- add one-time agent task claim/replay protection and audited results
- add Docker/Helm/hermesctl wiring for a separate agent-task HMAC key
- add a dedicated 0.5.11-dev.1 source/security gate

## 0.5.10 (stable candidate)

- Server-authoritative policy generation with stale-plan invalidation.
- Two-person CRITICAL exact-hash approval; approval nonce/HMAC integrity and one-use consumption.
- Credential-reference secret rejection and audited rotation, including SSH/Kubernetes lifecycle coverage.
- Agent one-time enrollment, replay protection, capability heartbeat and revocation.
- Audit export/digest and retention controls.
- Integrity-checked backup/restore and single-active failover acceptance.
- Stable candidate image/runtime/migration gates and CI runtime-action maintenance.


## 0.5.10-rc.1 (development)

- fix Kubernetes discovery JSON handling so large structured results are parsed from stdout without silent 100 KB truncation
- add target-aware bundled kubectl 1.33-1.36 selection with exact-minor preference and supported one-minor fallback
- bind Kubernetes server version, selected kubectl version, binary SHA-256, and toolchain binding hash into live preview and signed execution tickets
- reject execution when the target/toolchain binding changes after preview, requiring a fresh preview and approval
- validate 35 non-destructive security/authorization checks and 32 controlled execution/drift/replay/rollback checks on the disposable sandbox target
- isolate Control Plane and Kubernetes Broker CI test environments because their dev requirement sets intentionally pin different pytest versions
- fix RC.1 stabilization R1 combo bootstrap abort: tolerate EOF from tiny action files under `set -e` and newline-terminate reconciliation plan files
- keep the R1 9router combo reconciliation design while ensuring first-run combo creation actually executes
- preserve Hermes Smart Router authentication with `api_key: ${OPENAI_API_KEY}` rather than clearing the config reference
- make `bot check` verify an authenticated Hermes -> Smart Router runtime request
- automatically reconcile 9router `ai`, `combo-fast`, `combo-standard`, and `combo-strong` routing objects from the current OpenCode free-model catalog
- preserve operator-customized tier combos after initial creation while refreshing the Hermes-managed `ai` combo when the catalog is available
- keep existing 9router combos usable during a temporary OpenCode catalog outage
- leave OmniRoute on its native `auto/best-*` routing path with no synthetic combo provisioning
- upgrade `router probe` from a model-list check to a real streaming chat-completion request
- preserve the original `managed_key_stale_ids` exit status so ambiguous active-key cleanup reports the dedicated fail-closed error
- document `router cleanup-keys` in CLI help

## 0.5.10-beta.1

- add isolated Kubernetes Broker image with kubectl/Helm
- add kubeconfig local-reference/fingerprint boundary for Docker/VM
- add ChangeSet schema v2 target snapshots and drift invalidation
- add Kubernetes discovery, server-side manifest dry-run/diff and guarded apply
- add Helm server dry-run, install/upgrade verification and rollback flow
- add signed short-lived exact-plan execution tickets
- keep Kubernetes and Control Plane execution disabled by default
- add Kubernetes-focused Operations Center workflows
- add hermesctl kubeconfig/version/upgrade commands
- add Docker Compose/Helm/CI wiring for Kubernetes Broker

## 0.5.10-alpha.2

- merged Integration Registry and ChangeSet milestones into one Management + Safety Core release
- added persistent Environment, Integration, Target and credential-reference registries
- added alpha.1 SQLite schema migration/backfill
- added starter Operations Center management UI at `/ui`
- added HTTP/HTTPS integration health-test foundation
- added deterministic canonical ChangeSet plan serialization and SHA-256 hashes
- added automatic READ/LOW/HIGH/CRITICAL risk classification
- added ChangeSet preview, expiry and state management
- added approval request/approve/reject/cancel flows bound to the exact plan hash
- blocked HIGH/CRITICAL requester self-approval
- added append-oriented audit events
- added Control Plane API tests to CI
- changed Docker publishing to GitHub Actions: `edge`/`sha-*` on main, semver tags on releases, `latest` only for stable versions
- kept privileged DevOps execution disabled pending beta adapters

## 0.5.10-alpha.1

- created Hermes Control Plane monorepo foundation
- migrated Smart Router and Execution Broker foundations
- added runtime-selectable 9router/OmniRoute gateway
- added Docker Compose and initial Helm deployment
- introduced isolated `hermes-control-plane-*` Docker image naming

- 0.5.11-dev.5: add exact-commit Argo CD GitOps sync and pinned Cilium upgrade execution through the trusted Kubernetes Broker with drift-bound previews and active verification.
- 0.5.11-dev.5: add bounded one-shot Velero Backup execution through the trusted Kubernetes Broker with exact state/spec binding and active completion verification.

- dev.5 scope closure: add CRITICAL two-approval explicit-namespace Velero Restore runtime with exact source/restore drift binding, fixed non-destructive Restore CR execution, PV permission gating and active terminal verification.
