# Control Plane Operator Center

Open the Control Plane UI at `/ui`. Enter the admin token locally in the browser when administrative read/configuration actions require it. The browser stores it only for the active browser context; never paste it into a chat, ChangeSet title, target metadata, or support report.

## Authority boundary

The Operator Center renders configuration, read-only state, discovery results, diagnostics, typed plan details, approval state, execution evidence, and audit. A visible button or `IMPLEMENTED` UI state is not authority to bypass ChangeSets. Kubernetes/Helm mutation requires the Hermes Bot identity; approval requires the separate Approval Bot identity. Every privileged operation must still satisfy gates, policy, preview/snapshot binding, approval, ticket, executor scope, verification, and audit.

## Top-level navigation

| Tab | What it is for | Typical safe actions |
|---|---|---|
| **Overview** | System posture and quick health summary | Review capability/gate posture, service health, recent activity. |
| **Operator Center** | Catalog of operational surfaces | Navigate read models, forms, plans, and maturity context. |
| **Infrastructure** | Environment, target, server, provider, and worker inventory | Register metadata, inspect capability, run permitted discovery/preflight. |
| **Cluster Factory** | Existing-host cluster design and provisioning records | Manage blueprints/profiles/node roles, inspect plans and provisioning runs. |
| **Operations Center** | Typed operations, fleet/provider/artifact view, verification | Inspect plans/jobs/results and governed operation status. |
| **Changes** | ChangeSet workflow | Inspect previews, risk, approvals, execution state, and audit links. |
| **Audit** | Tamper-evident operator trail | Filter/export approved audit views and review retention. |

## Operator Center surface catalog

The center organizes surfaces by domain. Each listed surface is a navigational/UI contract; consult its linked workflow before treating its corresponding executor as live.

### Kubernetes

| Surface | Data and operator use | Maturity / boundary |
|---|---|---|
| Overview | Target posture, discovery summary, broker state | **Runtime-complete** read path. |
| Issues | Normalized discovered conditions | Diagnostic/read model; no arbitrary remediation. |
| Applications | Workload/application inventory | Scoped discovery. |
| Topology | Cluster/workload relationship view | Observation, not a network controller. |
| Network Live | Sanitized network/Hubble information | Bounded data only; no raw flow bodies, L7 URL/headers/bodies, or IP detail. |
| Resources | CPU/memory/resource posture | Observation and bounded diagnostics. |
| Workloads | Deployments, StatefulSets, DaemonSets, rollout state | Governing mutations are bot-only/ChangeSet-bound. |
| Nodes | Node condition/capacity view | Cordon, uncordon, and drain are bounded day-2 operations. |
| Storage | Storage diagnostics/inventory | No arbitrary storage executor. |
| Ingress | Ingress/service exposure view | Observation and policy evidence. |
| Metrics | Available metrics summaries | Not a replacement for a full metrics backend. |
| Logs | Bounded diagnostic evidence | Never an arbitrary remote terminal. |
| Timeline | Event/operation timeline | Audit-adjacent observation. |
| Helm | Releases and typed Helm previews | Pinned charts and bounded values only. |
| GitOps | GitOps state and exact-revision sync planning | Commit must be an exact 40/64-hex identifier. |
| Cost | Cost/OpenCost-facing display | Depends on configured collection; interpret missing data as unavailable. |
| TLS | Certificate/TLS checks | Diagnostics and verification, not a certificate authority. |
| Security | Security findings | PASS/WARN/FAIL/SKIP diagnostics. |
| RBAC | Scoped RBAC diagnostics | No broad arbitrary RBAC editor. |
| Audit | Kubernetes-related audit correlation | Audit records do not disclose credentials. |

### Cluster Factory

| Surface | Data and operator use | Maturity / boundary |
|---|---|---|
| Clusters | Cluster records and provisioning state | Existing registered servers only. |
| Servers | Server Registry and preflight posture | Add metadata/credential reference; require PASS SSH preflight. |
| Provision | Provisioning plans/runs | Governed provider jobs; provider gate remains disabled by default. |
| Templates | Blueprints, profiles, node roles, addon plans | Typed configuration, not arbitrary installer scripts. |
| Bare Metal | BMC/PXE capability records | **Integration/local evidence** executor limits apply. |
| Images / Artifacts | Exact artifact inventory/manifests | Use pinned READY manifest binding. |

### Infrastructure

| Surface | Data and operator use | Maturity / boundary |
|---|---|---|
| Kubernetes | Target registration, discovery, broker health | **Runtime-complete** scoped Kubernetes path. |
| VMware | Provider descriptor/inventory model | **Contract-only/deferred** runtime. |
| OpenStack | Provider descriptor/inventory model | **Contract-only/deferred** runtime. |
| AWS | Provider descriptor/inventory model | **Contract-only/deferred** runtime. |
| Azure | Provider descriptor/inventory model | **Contract-only/deferred** runtime. |
| GCP | Provider descriptor/inventory model | **Contract-only/deferred** runtime. |
| Docker | Integration/target surface | Not an unrestricted Docker host controller. |
| Swarm | Integration/target surface | No generic remote executor. |
| SSH | Registered server and sealed-profile preflight surface | Existing-host worker contracts only. |

### Operations

| Surface | Data and operator use |
|---|---|
| Diagnostics | Runs bounded Kubernetes/native diagnostic families and displays typed results. |
| Deployments | Shows deployment plans/jobs and verification evidence. |
| Upgrades | Shows typed upgrade plans and governed execution state. |
| Backups | Shows backup plans/jobs and post-operation checks. |
| Recovery | Shows restore/recovery plans. Restore has CRITICAL approval requirements where supported. |
| Maintenance | Shows bounded node/workload/provider maintenance plans. |

### Governance

| Surface | Data and operator use |
|---|---|
| Changes | ChangeSet list/detail, risk, snapshot, preview, approval and ticket/execution outcomes. |
| Approvals | Approval status. A browser admin cannot submit a separate Approval Bot decision. |
| Credentials | Credential references, lifecycle state, backend/test/sync state; no normal secret-value display. |
| Agents | Enrollment, heartbeats, assigned task and revocation state. |
| Integrations | Registered integration health and configuration metadata. |
| Artifact Mirror | Artifact items, manifests, dependency resolution, verification state. |
| Audit | Filterable/exportable audit record view. |
| AI Routing | Router and routing-policy health/configuration context. |
| Settings | Safe operator settings and capability posture; no direct bypass of gates. |

## Reading panel state correctly

- **IMPLEMENTED** means the UI knows the view/contract; check [Feature status](feature-status.md) for executor evidence.
- **Unavailable**, **SKIP**, or missing evidence is not a successful result.
- A plan is not approved merely because it is displayed. Use [Governance and ChangeSets](governance-and-changes.md).
- A job marked failed after dispatch can still require operator remediation; see [Operations runbook](operations-runbook.md).

## Recommended navigation sequence

1. **Overview**: confirm all services/gates.
2. **Infrastructure**: register environment/target and obtain read-only discovery.
3. **Operator Center → Kubernetes**: inspect resources, issues, security, and diagnostic state.
4. **Changes**: review a generated typed plan and its preview before requesting approval.
5. **Operations Center** and **Audit**: confirm job verification and immutable history after execution.
