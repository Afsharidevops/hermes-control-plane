# Hermes Control Plane — v0.5.11 Completion Plan

**Target:** `0.5.11`

**Development line:** `dev/0.5.11`

**Base:** published stable `v0.5.10` at `e73dd7c69767e709fb944a6356e47776a4464d92`

## Goal

Finish the remaining planned product surface without weakening the v0.5.10 trust model. v0.5.11 is a completion and hardening release, not an unrestricted-shell expansion.

All mutating operations continue to follow:

`request -> resolve references -> typed ChangeSet -> validate -> preview -> risk -> policy -> approval -> exact-hash binding -> broker/agent execution -> verify -> rollback -> audit`

## Release rules

1. Preserve all v0.5.10 security invariants and stable API behavior unless a migration is documented.
2. Prefer shared primitives over provider-specific implementations.
3. Every new mutation capability must declare its risk, credential class, connection mode, reversibility, approval behavior, and target restrictions.
4. No new adapter may bypass ChangeSet/policy/approval/audit.
5. No raw secrets may be returned to LLM-facing or normal management APIs.
6. `v0.5.10` is immutable. Any defect is fixed forward in `0.5.11`.

## Workstream 1 — shared product substrate

**Milestone:** `0.5.11-dev.1`

- Application registry and CRUD.
- Shared adapter capability contract and discovery endpoint.
- Agent capability enforcement.
- Signed agent task envelope foundation.
- One-time task claim/replay protection.
- Policy-generation binding for agent tasks.
- Audit events for application and agent-task lifecycle.
- 0.5.11 plan/checkpoint/release-gate scaffolding.

Exit gate:
- existing v0.5.10 tests stay green;
- new substrate tests pass;
- no raw secret or unrestricted execution path is introduced.

## Workstream 2 — credential service completion

**Milestone:** `0.5.11-dev.2`

- Dedicated credential-service boundary.
- Encrypted local/volume backend for self-hosted installations.
- Kubernetes Secret / External Secrets reference backend.
- Vault-compatible reference backend.
- Cloud secret-manager provider interface.
- Create/rotate/delete/test operations through constrained adapters.
- SSH and Kubernetes credential lifecycle through the credential boundary.
- Provider credential redaction tests.
- Rotation/revocation audit evidence.

Exit gate:
- raw secret retrieval is impossible through normal Control Plane APIs;
- credential operations require admin boundary and are fully audited;
- Smart Router/LLM-facing services never receive storage-master credentials.

## Workstream 3 — infrastructure adapters

**Milestone:** `0.5.11-dev.3`

### Kubernetes + Helm completion
- richer namespace/resource allow/deny policy;
- rollout restart/scale/delete/undo;
- rollback metadata and verification;
- agent-mode Kubernetes execution;
- Helm repository/OCI metadata, discovery, values preview, template, install, upgrade, rollback, uninstall.

### Docker + Compose
- list/inspect/logs;
- restart and image pull;
- structured container deployment;
- guarded delete;
- Compose validate/preview/pull/up/restart/down;
- Docker socket remains broker/agent-only.

### Swarm
- cluster/service/stack discovery;
- stack deploy;
- service scale/update;
- rollback;
- guarded stack remove.

### SSH
- profile CRUD in Operations Center/API;
- host fingerprint verification;
- credential rotation/reference lifecycle;
- enable/disable/delete;
- structured runbook execution only; no arbitrary unrestricted shell endpoint.

Exit gate:
- all mutations are ChangeSet-driven;
- HIGH/CRITICAL behavior follows policy/approval defaults;
- rollback/verification evidence is captured where supported.

## Workstream 4 — GitHub, GitLab, Applications and GitOps

**Milestone:** `0.5.11-dev.4`

- GitHub repository/branch/commit discovery.
- GitHub branch creation, controlled file changes, PR creation, check inspection, policy-gated merge.
- GitLab project/branch/commit discovery.
- GitLab branch creation, controlled file changes, MR creation, pipeline inspection/trigger.
- Application registry wired to source/target/deployment metadata.
- GitOps mode converts production mutations into controlled Git changes + PR/MR.
- deployment verification and rollback metadata.
- prefer GitHub App and minimum-scope GitLab credentials.

Exit gate:
- production GitOps flow can produce an auditable PR/MR without exposing repository credentials to the LLM;
- merge remains policy-gated.

## Workstream 5 — agent protocol + ChatOps completion

**Milestone:** `0.5.11-dev.5`

### Node Agent
- enrollment token and device identity lifecycle;
- device certificate interface;
- heartbeat and capability advertisement;
- signed task envelopes;
- replay protection;
- policy-generation checks;
- execution-event stream model;
- revocation;
- target/capability enforcement.

### Telegram
- Hermes Bot: discovery, planning, status, read operations, ChangeSet creation.
- Approval Bot: exact plan display, approve-once, deny, expiry-bound decision.
- ChangeSet-driven execution and verification.
- secrets rejected from normal Telegram setup paths.

Exit gate:
- Approval Bot identity remains isolated from execution identity;
- task/approval replay is rejected;
- stale policy/hash changes fail closed.

## Workstream 6 — routing, UI and CLI completion

**Milestone:** `0.5.11-dev.6`

### Routing
- generic OpenAI-compatible provider adapter;
- LiteLLM-compatible endpoint adapter;
- custom provider plugin contract;
- equivalent provider metadata/readiness contract;
- provider switching without Git branches or credential exposure.

### Operations Center
- Applications, Changes, Deployments, Infrastructure, Integrations, Agents, Approvals, Audit, AI Routing, Settings navigation.
- landing-page priority for pending changes, failed deployments, unhealthy targets, recent approvals and integration health.

### hermesctl
- `integration list`;
- `agent enroll`;
- application/acceptance helper commands where useful;
- preserve init/up/down/status/router/backup/restore/doctor behavior.

Exit gate:
- Docker and Kubernetes deployment modes expose equivalent product APIs for these surfaces.

## Workstream 7 — acceptance and release

**Milestone:** `0.5.11-rc.1` -> `0.5.11`

Automate and save evidence for:

- clean Docker Compose install;
- clean Helm/Kubernetes install;
- 9router, OmniRoute and generic OpenAI-compatible provider selection;
- provider credential isolation;
- Integration + Application CRUD audit;
- Kubernetes and SSH credential lifecycle;
- Kubernetes, Helm, Docker, Compose and Swarm ChangeSet enforcement;
- production HIGH approval;
- CRITICAL two-person approval;
- exact-hash/policy-generation stale invalidation;
- one-time Telegram approval;
- agent task replay/stale-policy rejection;
- Docker socket isolation;
- raw kubeconfig/private key/token retrieval denial;
- Docker -> Kubernetes API-equivalence/migration;
- v0.5.10 -> v0.5.11 upgrade, backup, rollback, restore, re-upgrade;
- broker/agent/network-loss failure injection;
- single-active SQLite failover posture;
- audit export/retention;
- amd64 + arm64 candidate and stable images.

Stable release only after all mandatory gates are PASS.

## Explicitly deferred beyond 0.5.11

The original broad non-goals remain deferred so this release can actually finish:

- Terraform;
- Ansible;
- broad AWS/Azure/GCP resource management;
- Proxmox/VMware full management;
- database administration;
- network-device configuration.

They should later use the same capability/ChangeSet/policy/approval framework.

## Fast path

The compressed route is:

`dev.1 shared substrate -> dev.2 credentials -> dev.3 infra adapters -> dev.4 GitOps -> dev.5 agent/ChatOps -> dev.6 routing/UI/CLI -> rc.1 full acceptance -> stable 0.5.11`

Do not create separate RCs per feature. Create another RC only if `rc.1` acceptance uncovers release-blocking defects.
