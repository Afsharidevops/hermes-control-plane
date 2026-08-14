# Hermes Control Plane — v0.5.10 Plan

**Target:** `0.5.10`

**Initial development release:** `0.5.10-alpha.1`

**Project:** `hermes-control-plane`

## 1. Vision

Hermes Control Plane evolves the Hermes Linux Stack into a self-hosted AI-assisted DevOps control plane. Operators should be able to manage infrastructure from the Operations Center UI, Telegram ChatOps, API, and CLI while keeping credentials and privileged execution outside the LLM trust boundary.

The platform must run in either of two forms without changing the product model:

1. On-premises VM or bare-metal host using Docker Compose.
2. Kubernetes using the official Hermes Helm chart.

The platform must support selectable LLM routing providers rather than provider-specific Git branches. v0.5.10 starts with 9router and OmniRoute, with an OpenAI-compatible provider interface planned for later releases.

## 2. Core product rule

The AI may **interpret, inspect, plan, explain, and request execution**. It must not receive unrestricted infrastructure credentials or directly execute arbitrary privileged shell commands.

All mutating DevOps operations must follow this pipeline:

```text
Request
  -> Resolve target and credentials by reference
  -> Build typed ChangeSet
  -> Validate
  -> Dry-run / diff / preview
  -> Risk classification
  -> Policy decision
  -> Approval when required
  -> Bind approval to exact ChangeSet hash
  -> Execute through broker/agent
  -> Verify
  -> Roll back when supported
  -> Audit
```

## 3. Security invariants

These are release-blocking requirements.

- Smart Router and the LLM do not receive Docker sockets.
- Smart Router and the LLM do not receive raw kubeconfigs.
- Smart Router and the LLM do not receive SSH private keys.
- Smart Router and the LLM do not receive GitLab/GitHub access tokens.
- Smart Router and the LLM do not receive registry passwords.
- Credentials are referenced by opaque IDs and redacted metadata.
- Approval credentials/signing keys are isolated from normal execution services.
- Approval is bound to the exact target, parameters, source revision/digest, policy generation, and ChangeSet hash.
- Any material change after approval invalidates that approval.
- Production destructive operations are deny-by-default until a policy explicitly permits them.
- Secrets may not be pasted into Telegram workflows.
- Audit events are append-oriented and include requester, planner, approver, executor, target, outcome, and hashes.

## 4. Repository strategy

Use one repository and one default branch. Do not maintain separate long-lived branches for 9router and OmniRoute.

```text
hermes-control-plane/
  control-plane/       Management API and orchestration metadata
  router-gateway/      Runtime-selectable upstream router adapter
  smart-router/        Existing Hermes Smart Router / Operations Center foundation
  execution-broker/    Existing isolated execution broker foundation
  node-agent/          Remote execution agent foundation
  charts/              Kubernetes Helm chart
  deploy/docker/       Docker deployment support
  scripts/             Build/release/operator scripts
  docs/                Architecture and operator documentation
```

## 5. Router abstraction

### Goal

Allow 9router, OmniRoute, or eventually any OpenAI-compatible upstream without changing Git branches.

### v0.5.10 implementation

Introduce `router-gateway` between Smart Router and upstream router software.

```text
Hermes -> Smart Router -> Router Gateway -> 9router
                                    \----> OmniRoute
```

The router gateway owns active-provider selection. Smart Router uses one stable upstream endpoint.

### Required provider contract

Each provider adapter should expose equivalent metadata:

- provider ID
- display name
- OpenAI-compatible base URL
- health URL
- optional API-key reference
- enabled/disabled state
- readiness state
- active/standby state

### Initial providers

- `nine-router`
- `omniroute`

### Later providers

- generic OpenAI-compatible endpoint
- LiteLLM-compatible endpoint
- custom provider plugin

## 6. Deployment model

### Docker / on-prem VM

Docker Compose is the first bootstrap target.

The operator selects router profiles with `COMPOSE_PROFILES` and chooses the active provider with `HERMES_ROUTER_PROVIDER`.

Expected deployment components:

- Hermes Agent
- Smart Router
- Router Gateway
- 9router and/or OmniRoute
- Hermes Control Plane API
- execution broker services as enabled
- node agent when local execution is enabled

Privileged execution features remain disabled by default.

### Kubernetes

Provide `charts/hermes-control-plane`.

The chart must support:

- namespace-scoped installation
- configurable images and tags
- 9router, OmniRoute, or both
- configurable active router
- Services for the Control Plane and Smart Router
- Ingress optional and disabled by default
- security contexts
- configurable persistence
- external Secrets integration later
- optional Hermes Agent deployment
- execution features disabled by default

The cluster running Hermes is a **runtime cluster**. Managed clusters are independent targets. A runtime cluster may be added as a managed target, but self-management operations receive elevated risk classification.

## 7. Control Plane domain model

### Integration

Represents a managed external system or connection.

Fields:

- ID
- name
- kind
- environment
- endpoint metadata
- credential reference
- connection mode (`direct` or `agent`)
- allowed scope
- labels
- status
- created/updated timestamps

Initial kinds:

- Kubernetes
- Docker
- Docker Swarm
- SSH
- GitHub
- GitLab
- OCI/container registry
- Helm repository/OCI registry

### Target

Represents a concrete execution target associated with an integration.

Examples:

- Kubernetes cluster + namespace
- Docker Engine
- Swarm cluster
- SSH host/profile
- GitLab project

### Application

Reusable deployment definition.

Example properties:

- source repository
- revision policy
- build context
- image repository
- deployment type
- target
- environment
- values files
- verification checks
- rollback strategy

### ChangeSet

Immutable plan envelope for a requested operation.

Minimum fields:

- ID
- requester
- source channel
- operation type
- adapter
- target ID
- source revision/digest
- normalized parameters
- preview/diff
- risk
- policy generation
- content hash
- approval state
- execution state
- verification state
- rollback metadata

### Approval

Approval must contain:

- ChangeSet ID
- ChangeSet hash
- approver identity
- approval policy ID/version
- issue time
- expiry time
- one-time nonce
- signature/MAC

## 8. Adapter contract

Every execution integration should converge on this interface:

```text
discover()
validate()
plan()
preview()
execute()
verify()
rollback()
```

Each action declares:

- capability ID
- read or write
- default risk
- reversible or irreversible
- required credential class
- supported connection modes
- approval requirement
- target restrictions

The planner selects adapters; adapters do not grant authority. Authority comes from policy plus target-scoped credentials.

## 9. Kubernetes roadmap

### Read operations

- cluster health/version
- namespaces
- nodes
- workloads
- events
- rollout status
- pod logs
- resource describe

### Mutations

- apply manifest
- restart rollout
- scale workload
- delete scoped resource
- rollout undo

### Helm

- repository/OCI registration
- chart discovery
- values preview
- template/render
- server dry-run where supported
- install
- upgrade
- rollback
- uninstall

### Guardrails

- namespace allowlists
- resource-kind allow/deny lists
- block secret-value reads by default
- block RBAC escalation by default
- block cluster-admin binding by default
- dry-run before mutation whenever the target supports it

## 10. Docker and Swarm roadmap

### Docker

- list/inspect containers
- logs
- restart
- image pull
- structured container deployment
- delete with approval

### Compose

- validate config
- preview images/services/networks/volumes
- pull
- up
- restart
- down with approval

### Swarm

- cluster info
- service list
- stack list
- stack deploy
- service scale/update
- rollback
- stack remove with approval

Direct Docker socket access belongs only to the local broker/agent process that requires it.

## 11. GitHub and GitLab roadmap

### GitHub

Prefer GitHub App authentication when possible.

Capabilities:

- repository discovery
- branch/commit reads
- create branch
- commit controlled file changes
- open PR
- inspect checks
- merge only when policy permits

### GitLab

Prefer project/group-scoped tokens or application integrations with minimum required scope.

Capabilities:

- project discovery
- branch/commit reads
- create branch
- controlled file changes
- create merge request
- inspect pipelines
- optionally trigger pipeline

### GitOps mode

Production should support a policy that converts a requested infrastructure mutation into a Git change and PR/MR instead of direct execution.

Example:

```text
"Set payment-api replicas to 6 in production"
  -> modify values-production.yaml
  -> commit to hermes/change-<id>
  -> open MR/PR
  -> CI/GitOps controller performs deployment
```

## 12. SSH roadmap

Move SSH profile management into Operations Center while preserving the existing execution isolation model.

UI operations:

- add profile
- edit metadata
- verify host fingerprint
- rotate credential
- enable/disable
- delete

The UI can display fingerprint, auth type, username, host and redacted credential state. It must not return private-key contents.

## 13. Credential service

Introduce a dedicated credential administration boundary.

Responsibilities:

- create credential
- rotate/replace credential
- delete credential
- test credential through constrained adapters
- return redacted metadata

It must not:

- receive arbitrary LLM prompts
- expose raw credential values after creation
- possess Docker socket access
- possess approval signing credentials

Storage backends are phased:

1. encrypted local/volume backend for self-hosted alpha
2. Kubernetes Secret/External Secrets integration
3. Vault-compatible provider
4. cloud secret managers

## 14. Agent architecture

Support both connection modes:

- `agent` — recommended
- `direct` — optional for small/self-hosted environments

A remote Hermes Node Agent should connect outbound to the Control Plane, authenticate using a device identity, receive only policy-authorized ChangeSets, and execute via local adapters.

Agent target examples:

- Kubernetes cluster
- Docker host
- Swarm manager
- restricted datacenter/jump host

Long term the agent protocol needs:

- enrollment token
- device certificate
- heartbeat
- capability advertisement
- signed task envelope
- replay protection
- policy generation checks
- streaming execution events
- revocation

## 15. Telegram ChatOps

Maintain two logical responsibilities:

### Hermes Bot

- conversation
- discovery
- planning
- status
- read-only operations
- ChangeSet creation

### Approval Bot

- approval display
- approve once
- deny
- view exact diff/details

Examples:

- "Show unhealthy workloads in production."
- "Deploy payment-api to staging."
- "Install nginx ingress in production-k8s."
- "Take GitLab project platform/monitoring and deploy it to swarm-production."
- "Roll back the last billing-api deployment."

Sensitive credential values are never accepted through Telegram as the normal setup path.

## 16. Risk model

Baseline classes:

- `READ`
- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Baseline behavior:

| Operation | Default risk | Default decision |
|---|---:|---|
| list pods / logs / Git read | READ | allow |
| staging restart | MEDIUM | confirm/policy |
| production scale | HIGH | approval |
| Helm production upgrade | HIGH | approval |
| resource delete | HIGH | approval |
| Kubernetes RBAC change | CRITICAL | strong approval |
| namespace deletion | CRITICAL | deny unless explicit |
| privileged container | CRITICAL | deny unless explicit |
| host root mount | CRITICAL | deny by default |
| read Secret values | CRITICAL | deny by default |
| protected-branch force push | CRITICAL | deny by default |

The data model should support two-person approval even if the first alpha ships single-approver workflows.

## 17. Operations Center information architecture

Recommended navigation:

```text
Overview
Applications
Changes
Deployments
Infrastructure
  Kubernetes
  Docker
  Swarm
  SSH
Integrations
  GitHub
  GitLab
  Registries
  Helm
Agents
Approvals
Audit
AI Routing
Settings
```

The landing page should prioritize pending changes, failed deployments, unhealthy targets, recent approvals, and integration health.

## 18. CLI

Provide one operator CLI entry point: `hermesctl`.

Planned commands:

```text
hermesctl init
hermesctl up
hermesctl down
hermesctl status
hermesctl router list
hermesctl router set <provider>
hermesctl integration list
hermesctl agent enroll
hermesctl backup
hermesctl restore
hermesctl doctor
```

The alpha repository includes the bootstrap/router subset and expands this command surface as services mature.

## 19. Release phases

### 0.5.10-alpha.1 — repository foundation

- new monorepo
- migrate Smart Router
- migrate execution broker
- router gateway
- 9router/OmniRoute runtime selection
- Control Plane API skeleton
- Node Agent skeleton
- Docker Compose bootstrap
- initial Helm chart
- Docker image build/push automation
- GitHub CI foundation
- architecture/security plan

### 0.5.10-alpha.2 — integration registry

- persistent integration metadata
- environment/target model
- CRUD API
- Operations Center integration pages
- credential references
- health testing

### 0.5.10-alpha.3 — ChangeSet engine

- typed plans
- canonical JSON serialization
- SHA-256 ChangeSet hashes
- risk engine
- preview store
- execution state machine
- approval binding
- audit events

### 0.5.10-alpha.4 — Kubernetes + Helm

- direct kubeconfig connection
- agent Kubernetes connection
- Kubernetes discovery
- manifest dry-run/diff/apply
- Helm plan/install/upgrade/rollback
- namespace/resource policy

### 0.5.10-beta.1 — Git + application deployments

- GitHub integration
- GitLab integration
- Application registry
- GitOps PR/MR workflow
- deployment verification
- rollback metadata

### 0.5.10-beta.2 — Docker/Compose/Swarm + SSH UI

- Compose plans/execution
- Swarm stack/service operations
- SSH UI CRUD
- target-level policy
- agent capability enforcement

### 0.5.10-rc.1 — hardening

- threat-model review
- credential rotation
- agent revocation
- backup/restore
- audit retention/export
- HA tests
- Docker-to-Kubernetes migration tests
- upgrade tests
- security documentation

### 0.5.10 — stable

Release only when the acceptance gates below pass.

## 20. Stable release acceptance gates

- Docker Compose install succeeds on a clean supported Linux VM.
- Helm install succeeds on a clean supported Kubernetes cluster.
- 9router and OmniRoute can each be selected without changing branches.
- Provider switching cannot expose stored provider credentials.
- Integration CRUD is functional and audited.
- Kubernetes credential add/rotate/delete is functional through the credential boundary.
- SSH credential add/rotate/delete is functional through the credential boundary.
- Kubernetes mutation requires a ChangeSet.
- Helm mutation requires a ChangeSet.
- Production high-risk mutation requires approval by default.
- Approved execution fails closed when the ChangeSet hash/policy generation changes.
- Docker socket is absent from Smart Router, Control Plane, Telegram and LLM-facing containers.
- Raw kubeconfig/private keys/tokens cannot be retrieved through normal management APIs.
- Telegram approval is one-time and expiry-bound.
- Docker and Kubernetes deployment modes expose equivalent product APIs.
- Upgrade and backup/restore documentation exists and is tested.

## 21. Non-goals for 0.5.10

Do not expand v0.5.10 until the core execution model is stable.

Deferred integrations include:

- Terraform
- Ansible
- AWS/Azure/GCP broad resource management
- Proxmox/VMware full management
- database administration
- network device configuration

They should later be implemented as adapters on the same ChangeSet/policy/approval framework.

## 22. Definition of the project

Hermes Control Plane is not an unrestricted AI shell.

It is a self-hosted DevOps management platform in which AI creates explainable plans and constrained brokers/agents execute policy-authorized, auditable ChangeSets.

## Docker image naming policy

The `hermes-linux-stack` Docker Hub repositories remain independent. This project must never publish to its legacy image repositories such as `hermes-smart-router` or `hermes-execution-broker`. Every image built by Hermes Control Plane uses the `hermes-control-plane-*` prefix:

- `hermes-control-plane-api`
- `hermes-control-plane-router-gateway`
- `hermes-control-plane-smart-router`
- `hermes-control-plane-execution-broker`
- `hermes-control-plane-node-agent`

This isolation applies to local builds, Docker Hub, Compose, Helm, and CI release workflows.
