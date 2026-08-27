# API Reference

**Runtime-complete / Integration/local evidence / Contract-only/deferred:** This reference spans all three maturity categories. A route or typed contract does not by itself prove that a real-target executor exists; consult [Feature status](feature-status.md) before enabling or relying on a privileged capability.

This reference is a source-derived operator map for the Hermes HTTP services. Routes require a bearer identity unless identified as health/public contract. Request bodies are strict typed models in service source; clients must reject unknown/secret-bearing fields and use the OpenAPI document of the deployed service for exact schema field definitions.

## Authentication and API safety

| Identity | Use |
|---|---|
| Control Plane admin | Administrative reads/configuration, registries, discovery, diagnostics, audit/export, credentials references, contract views, and non-mutation operations. |
| Hermes Bot | Kubernetes/Helm and operations planning/authorization/execution. Admin tokens are actively rejected for bot-only mutation routes. |
| Approval Bot | Separate approval/rejection decision endpoint only. Admin and Hermes Bot tokens are rejected. |
| Credential Service admin | Credential lifecycle routes. |
| Credential Service sync identity | Internal metadata-only Control Plane synchronization; not a public integration API. |
| Kubernetes Broker / Node Agent worker token | Control Plane-to-executor service calls. |
| Router Gateway admin | Router provider management. |
| Smart Router client/admin/session identity | Model traffic, system administration, and Operations Center access according to RBAC. |

Never send raw kubeconfig, SSH key, password, provider secret, ticket signing key, or router secret in a URL/query/log. Mutating Control Plane routes are governance inputs, not direct executor backdoors.

## Control Plane: public status, system, and policy

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/` | Root; serves UI index. |
| `GET` | `/ui` | UI entry point. |
| `GET` | `/health` | Liveness/version/runtime health. |
| `GET` | `/v1/system` | System metadata including current policy generation. |
| `POST` | `/v1/policy-generation/bump` | Admin policy-generation update; invalidates stale planning/approval conditions. |
| `GET` | `/v1/capabilities` | Safe capability/gate summary. |
| `GET` | `/v1/operator-center/contracts` | Operator Center UI/maturity contract. |
| `GET` | `/v1/operations-center/contracts` | Operations Center typed-contract catalog. |

## Control Plane: environments

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/environments` | List environment records. |
| `POST` | `/v1/environments` | Create environment record. |
| `PATCH` | `/v1/environments/{environment_id}` | Update environment metadata. |
| `DELETE` | `/v1/environments/{environment_id}` | Remove environment subject to dependency checks. |

## Control Plane: credential references

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/credential-refs` | List safe credential-reference metadata. |
| `POST` | `/v1/credential-refs` | Create credential reference; no raw material accepted. |
| `PATCH` | `/v1/credential-refs/{credential_id}` | Update credential reference metadata. |
| `POST` | `/v1/credential-refs/{credential_id}/rotate` | Rotate credential reference. |
| `DELETE` | `/v1/credential-refs/{credential_id}` | Remove credential reference. |
| `POST` | `/v1/internal/credential-refs/sync` | Internal Credential Service metadata sync only. |
| `DELETE` | `/v1/internal/credential-refs/{credential_id}` | Internal Credential Service metadata delete only. |

## Control Plane: integrations

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/integrations` | List controlled integration records. |
| `POST` | `/v1/integrations` | Create integration record. |
| `PATCH` | `/v1/integrations/{integration_id}` | Update integration metadata. |
| `DELETE` | `/v1/integrations/{integration_id}` | Remove integration. |
| `POST` | `/v1/integrations/{integration_id}/health` | Bounded integration health check/record. |

## Control Plane: targets

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/targets` | List target records. |
| `POST` | `/v1/targets` | Create target record with scope. |
| `PATCH` | `/v1/targets/{target_id}` | Update target scope/metadata. |
| `DELETE` | `/v1/targets/{target_id}` | Remove target. |

## Control Plane: agents and agent tasks

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/agents` | List agent records. |
| `POST` | `/v1/agents/enrollment-tokens` | Create one-time, expiry-bound enrollment token. |
| `POST` | `/v1/agents/enroll` | Enroll an agent from valid token. |
| `POST` | `/v1/agents/heartbeat` | Signed/replay-protected agent heartbeat. |
| `POST` | `/v1/agents/{agent_id}/revoke` | Immediate agent revocation. |
| `POST` | `/v1/agents/{agent_id}/tasks` | Create scoped task for agent. |
| `GET` | `/v1/agent-tasks` | List flat agent task records. |
| `GET` | `/v1/agents/tasks/next` | Dequeue next pending task. |
| `POST` | `/v1/agents/tasks/{task_id}/claim` | Claim a specific task. |
| `POST` | `/v1/agents/tasks/{task_id}/result` | Submit task result. |

## Control Plane: providers and preflight

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/providers` | List supported provider descriptors. |
| `GET` | `/v1/providers/{provider_id}` | Get single provider descriptor. |
| `GET` | `/v1/preflight/ssh/spec` | SSH preflight specification. |

## Control Plane: servers

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/servers` | List registered servers. |
| `GET` | `/v1/servers/{server_id}` | Get server metadata. |
| `POST` | `/v1/servers` | Register a server. |
| `PATCH` | `/v1/servers/{server_id}` | Update server metadata. |
| `DELETE` | `/v1/servers/{server_id}` | Remove server. |
| `GET` | `/v1/servers/{server_id}/host-observation-binding` | Get host observation binding. |
| `POST` | `/v1/servers/{server_id}/host-observation-binding` | Create host observation binding. |
| `PATCH` | `/v1/servers/{server_id}/host-observation-binding` | Update host observation binding. |
| `POST` | `/v1/servers/{server_id}/preflight-plan` | Produce typed SSH/host preflight plan. |
| `POST` | `/v1/servers/{server_id}/preflight-result` | Record preflight result. |
| `POST` | `/v1/servers/{server_id}/bootstrap-plan` | Produce typed bootstrap plan. |

## Control Plane: provider jobs

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/provider-jobs` | List provider job records. |
| `GET` | `/v1/provider-jobs/{job_id}` | Get provider job detail. |
| `GET` | `/v1/provider-jobs/{job_id}/events` | Get provider job event history. |
| `GET` | `/v1/provider-jobs/{job_id}/stream` | SSE event stream for provider job. |
| `POST` | `/v1/provider-jobs/{job_id}/authorize` | Bot authorization for provider job. |
| `POST` | `/v1/provider-jobs/{job_id}/execute` | Bot execute authorized provider job. |
| `POST` | `/v1/provider-jobs/{job_id}/transition` | Bot state transition. |
| `POST` | `/v1/provider-jobs/{job_id}/retry` | Controlled retry where lifecycle allows. |
| `POST` | `/v1/provider-jobs/{job_id}/resume` | Controlled resume where lifecycle allows. |

## Control Plane: applications

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/v1/applications` | List application records. |
| `POST` | `/v1/applications` | Create application record. |
| `PATCH` | `/v1/applications/{application_id}` | Update application metadata. |
| `DELETE` | `/v1/applications/{application_id}` | Remove application. |

## Control Plane: ChangeSets, approvals, and audit

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/changesets` | List ChangeSets. |
| `GET` | `/v1/changesets/{changeset_id}` | Inspect canonical plan, preview, risk, approvals, state, and safe evidence. |
| `POST` | `/v1/changesets` | Bot creates mutation ChangeSet. |
| `POST` | `/v1/changesets/{changeset_id}/rollback-plan` | Bot creates rollback plan. |
| `POST` | `/v1/changesets/{changeset_id}/preview` | Bot-only live preview for supported plan. |
| `POST` | `/v1/changesets/{changeset_id}/preview-live` | Bot-only live preview against current target state. |
| `POST` | `/v1/changesets/{changeset_id}/request-approval` | Bot requests approval for exact plan. |
| `POST` | `/v1/changesets/{changeset_id}/approve` | Approval Bot only. |
| `POST` | `/v1/changesets/{changeset_id}/reject` | Approval Bot only. |
| `POST` | `/v1/changesets/{changeset_id}/cancel` | Controlled cancellation before execution. |
| `POST` | `/v1/changesets/{changeset_id}/execute` | Bot-only; exact ticket/plan/gate/approval required. |
| `GET` | `/v1/changesets/{changeset_id}/approvals` | List approvals for a ChangeSet. |
| `GET` | `/v1/audit` | Filterable audit list. |
| `GET` | `/v1/audit/export` | NDJSON/export with integrity metadata. |
| `POST` | `/v1/audit/retention` | Retention pruning/administration; audit this action. |

## Control Plane: Kubernetes discovery and broker health

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/v1/kubernetes/targets/{target_id}/discover` | Admin-scoped target discovery through trusted broker. |
| `GET` | `/v1/kubernetes/broker-health` | Proxy/summarize Broker health. |

## Control Plane: Cluster Factory

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/cluster-factory/contracts` | Cluster Factory contract descriptors. |
| `GET` | `/v1/cluster-factory/operational-profiles` | List operational profiles. |
| `GET` | `/v1/cluster-blueprints` | List ClusterBlueprints. |
| `POST` | `/v1/cluster-blueprints` | Create ClusterBlueprint. |
| `POST` | `/v1/cluster-blueprints/from-operational-profile` | Create ClusterBlueprint from operational profile. |
| `GET` | `/v1/cluster-blueprints/{blueprint_id}` | Get ClusterBlueprint. |
| `PUT` | `/v1/cluster-blueprints/{blueprint_id}/artifact-dependencies` | Set artifact dependency bindings. |
| `GET` | `/v1/cluster-blueprints/{blueprint_id}/artifact-manifest` | Resolve READY artifact manifest. |
| `GET` | `/v1/cluster-profiles` | List Cluster Profiles. |
| `POST` | `/v1/cluster-profiles` | Create Cluster Profile. |
| `GET` | `/v1/cluster-profiles/{profile_id}` | Get Cluster Profile. |
| `GET` | `/v1/node-roles` | List NodeRole records. |
| `POST` | `/v1/node-roles` | Create NodeRole. |
| `GET` | `/v1/clusters` | List Cluster records. |
| `POST` | `/v1/clusters` | Create Cluster record. |
| `GET` | `/v1/clusters/{cluster_id}` | Get Cluster record. |
| `GET` | `/v1/provisioning-runs` | List provisioning run records. |
| `POST` | `/v1/clusters/{cluster_id}/provisioning-runs` | Create provisioning run (cluster provision plan). |
| `POST` | `/v1/provisioning-runs/{run_id}/refresh` | Refresh provisioning run state. |
| `GET` | `/v1/addon-plans` | List addon plan records. |
| `POST` | `/v1/clusters/{cluster_id}/addon-plans` | Create addon plan. |
| `GET` | `/v1/upgrade-plans` | List upgrade plan records. |
| `POST` | `/v1/clusters/{cluster_id}/upgrade-plans` | Create upgrade plan. |
| `GET` | `/v1/backup-plans` | List backup plan records. |
| `POST` | `/v1/clusters/{cluster_id}/backup-plans` | Create backup plan. |

## Control Plane: cluster intelligence, diagnostics, verification, and network

| Method | Route | Authority / purpose |
|---|---|---|
| `POST` | `/v1/clusters/{cluster_id}/intelligence/query` | Admin query Radar/native intelligence with AUTO fallback. |
| `POST` | `/v1/clusters/{cluster_id}/intelligence/radar` | Record validated Radar summary. |
| `POST` | `/v1/clusters/{cluster_id}/intelligence/hubble` | Record validated Hubble summary. |
| `GET` | `/v1/clusters/{cluster_id}/intelligence` | Read latest Radar/Hubble/diagnostic contracts. |
| `POST` | `/v1/clusters/{cluster_id}/diagnostics/run` | Run typed native diagnostics. |
| `POST` | `/v1/clusters/{cluster_id}/verify` | Active unified verification. |
| `POST` | `/v1/clusters/{cluster_id}/network/live` | Collect Hubble live network flows. |
| `GET` | `/v1/clusters/{cluster_id}/network/history` | Read stored Hubble flow history. |
| `GET` | `/v1/clusters/{cluster_id}/network/live/stream` | SSE stream of Hubble live flows. |

## Control Plane: Operations Center, providers, artifacts, and verification

| Method | Route | Authority / purpose |
|---|---|---|
| `GET` | `/v1/operations-center/overview` | Admin operations/fleet/provider/artifact summary. |
| `GET` | `/v1/fleet/clusters` | Admin fleet state. |
| `GET` | `/v1/infrastructure-providers` | List/register provider descriptor/configuration. |
| `POST` | `/v1/infrastructure-providers` | Create infrastructure provider record. |
| `POST` | `/v1/infrastructure-providers/{provider_id}/health` | Record safe provider health evidence. |
| `GET` | `/v1/artifact-mirror/items` | List artifact mirror items. |
| `POST` | `/v1/artifact-mirror/items` | Create artifact mirror item. |
| `GET` | `/v1/operation-plans` | List typed operation plans. |
| `GET` | `/v1/operation-jobs` | List operation job state. |
| `POST` | `/v1/operations-center/intents/plan` | Admin read query or Bot-only mutation planning by domain. |
| `POST` | `/v1/operation-jobs/{job_id}/authorize` | Bot issue short-lived ticket after drift/approval verification. |
| `POST` | `/v1/operation-jobs/{job_id}/execute` | Bot invoke trusted runtime executor. |
| `POST` | `/v1/operation-jobs/{job_id}/transition` | Bot state transition for supported lifecycle. |
| `GET` | `/v1/verifications` | List verification records. |
| `POST` | `/v1/verifications` | Bot-record typed verification evidence. |

`/v1/operations-center/intents/plan` supports `read`, `day2`, `fleet`, `cloud`, `bare-metal`, `network`, and `artifact` domains. A typed contract/UI entry does not create a runtime executor; see [Feature status](feature-status.md).

## Credential Service API

All `/v1/*` Credential Service routes require `HERMES_CREDENTIAL_ADMIN_TOKEN`; `/health` is status-only.

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Encryption configuration/health state. |
| `GET` | `/v1/backends` | Available local/external backend descriptors. |
| `GET` | `/v1/credentials` | List redacted credential records. |
| `POST` | `/v1/credentials` | Create credential record. |
| `GET` | `/v1/credentials/{credential_id}` | Get redacted credential record. |
| `PATCH` | `/v1/credentials/{credential_id}` | Update credential metadata. |
| `DELETE` | `/v1/credentials/{credential_id}` | Delete credential record. |
| `POST` | `/v1/credentials/{credential_id}/rotate` | Rotate local material or external reference. |
| `POST` | `/v1/credentials/{credential_id}/test` | Validate bounded credential/backend state. |
| `POST` | `/v1/credentials/{credential_id}/revoke` | Revoke and erase local ciphertext after metadata revoke sync. |
| `POST` | `/v1/credentials/{credential_id}/sync` | Retry metadata-only Control Plane sync. |
| `GET` | `/v1/audit` | Credential-service lifecycle audit. |

## Kubernetes Broker and Node Agent APIs

See [Kubernetes operations](kubernetes-operations.md) and [Infrastructure providers](infrastructure-providers.md) for schemas/gates.

| Service | Methods and routes |
|---|---|
| Kubernetes Broker | `GET /health`; `POST /v1/discover`; `POST /v1/diagnostics/run`; `POST /v1/hubble/collect`; `POST /v1/day2/preview`; `POST /v1/day2/execute`; `POST /v1/preview`; `POST /v1/execute`. |
| Node Agent | `GET /health`; `POST /v1/provider/preview`; `POST /v1/provider/execute`; `POST /v1/capacity/refresh`; `POST /v1/vm/inventory/refresh`; `POST /v1/infrastructure/preview`; `POST /v1/infrastructure/execute`. |
| Host observer | `GET /health`; `POST /v1/collectors/host-network`. |

## Execution Broker API

Execution Broker is a constrained service with `BROKER_MODE=docker|ssh|approver|admin`; it is not a general shell/Docker API.

| Method | Route | Mode / purpose |
|---|---|---|
| `GET` | `/health` | Common health/capability state. |
| `POST` | `/prepare` | Structured constrained operation preparation. |
| `POST` | `/execute` | Capability/ticket-bound execution. |
| `POST` | `/cancel` | Cancel a supported queued operation. |
| `POST` | `/discover` | Bounded discovery. |
| `POST` | `/approval-grant` | Common approval-grant lifecycle endpoint. |
| `POST` | `/request` | Approver mode request endpoint. |
| `GET` | `/admin/status` | Admin mode status. |
| `GET` | `/admin/audit` | Admin mode audit. |
| `PUT` | `/admin/features` | Admin mode feature policy. |
| `PUT` | `/admin/users` | Admin mode user administration. |
| `PUT` | `/admin/bot-token` | Admin mode bot identity configuration. |
| `POST` | `/admin/rotate-control-secret` | Admin mode control-secret rotation. |

## Router Gateway and Smart Router APIs

Router Gateway routes and aliases are documented in [ChatOps and routing](chatops-and-routing.md). Smart Router's public OpenAI-compatible routes are also documented there.

### Smart Router (public)

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Health check. |
| `GET` | `/ready` | Readiness probe. |
| `GET` | `/metrics` | Prometheus metrics. |
| `GET` | `/router/info` | Router information. |
| `GET` | `/router/policy` | Router policy (v0.5.1 compat). |
| `GET` | `/dashboard` | Flight Deck UI. |
| `GET` | `/dashboard/api/summary` | Dashboard usage summary. |
| `GET` | `/dashboard/api/traces` | Dashboard trace listing. |
| `GET` | `/dashboard/api/traces/{request_id}` | Single trace detail. |
| `GET` | `/v1/models` | OpenAI-compatible model listing. |
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat completions. |
| Mount | `/control` | Control plane sub-application (see below). |

### Smart Router Control (mounted at `/control`)

The Smart Router `/control` application covers local/OIDC login/logout/identity, onboarding/audit/system configuration, providers/routes/pipelines/policies/budgets/guardrails/model catalog/outcomes, users/groups/virtual keys/ACLs, knowledge/memory/pipelines, agents/teams/skills/plugins/marketplace, workflows/prompts/datasets/evaluations, and traces.

Use the deployed Smart Router control API's OpenAPI schema/UI for exact control subroute request models, because those panel APIs evolve independently of the Control Plane release package. Protect control endpoints with RBAC and do not grant them Control Plane executor authority.

### Router Gateway

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Health check. |
| `GET` | `/management/providers` | List providers (admin token). |
| `PUT` | `/management/router` | Select active provider (admin token). |
| All methods | `/v1/{path}` | Proxy to active upstream provider. |