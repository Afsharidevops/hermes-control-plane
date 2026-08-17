# Changelog

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
