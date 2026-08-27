# Feature Status and Evidence Matrix

Use this matrix with the detailed guides. **Runtime-complete** means the bounded executor exists, not that your target has been validated. **Integration/local evidence** means local/mock evidence only. **Contract-only/deferred** must not be enabled or presented as an implemented target integration.

| Domain | Surface / executor | Default state | Evidence | Important boundary |
|---|---|---|---|---|
| Governance | ChangeSets, approvals, audit, tickets | Available; execution off | Runtime-complete | Exact hashes, policy generation, drift and replay checks apply. |
| Credentials | Credential Service metadata and encrypted local/external references | Available | Runtime-complete | No normal raw-secret readback. |
| UI | Control Plane seven tabs and Operator Center surfaces | Available | Runtime-complete UI; per-surface maturity varies | UI state is not provider-runtime evidence. |
| Kubernetes discovery | Kubernetes Broker | Read paths enabled with target | Runtime-complete | Scoped, secret-free discovery. |
| Kubernetes/Helm base mutations | Broker | `HERMES_EXECUTION_ENABLED=false`, `HERMES_KUBERNETES_EXECUTION_ENABLED=false` | Runtime-complete | Bot-only, live preview, exact ChangeSet, ticket. |
| Hubble / diagnostics / verification | Broker | Read-only target access | Runtime-complete | Sanitized, bounded output; local/runtime evidence is not cluster certification. |
| Kubernetes day-2 | Nodes, workloads, Helm/add-ons, Argo CD, Cilium, Velero | Gates disabled | Runtime-complete | Only listed operations and typed inputs; no arbitrary CLI. |
| Cluster Factory | Existing-host Kubespray/K3s/RKE2 | Provider gate disabled | Runtime-complete | PASS preflight, registered servers, exact artifact supply where required. |
| Cluster capacity lifecycle | Create capacity, full decommission/recreation DR | N/A | Contract-only/deferred | Existing-host factory is not capacity-backed lifecycle. |
| Artifact mirror | Blob, OCI image/chart, Git release, collections, APT/RPM/Python snapshots | Controlled operation path | Runtime-complete | Digest/version/allowlist/verification bound. |
| Redfish/IPMI/PXE | Node Agent infrastructure worker | Infrastructure gate disabled | Integration/local evidence | Fixed APIs only; disposable real-target evidence still required. |
| Host network / OpenConfig switch | Node Agent | Infrastructure gate disabled | Integration/local evidence | Narrow typed host and RESTCONF profiles only. |
| Proxmox capacity | Node Agent collector | Collection gate disabled | Integration/local evidence | Read-only capacity, not placement/lifecycle proof. |
| Proxmox VM inventory | Node Agent collector | Collection gate disabled | Integration/local evidence | Identity/power state only. |
| Proxmox QEMU mutations | Node Agent | Infrastructure and Proxmox gates disabled | Integration/local evidence | Exactly eight QEMU actions; no automatic rollback. |
| VMware, OpenStack, AWS, Azure, GCP | Provider contracts and UI | N/A | Contract-only/deferred | No established trusted mutation runtime. |
| Smart Router | OpenAI-compatible proxy, routing, operations panel | Observe mode by default | Runtime-complete | Separate service versioning; protect keys and control panel. |
| Router Gateway | 9router / OmniRoute selection and alias proxy | Selected router required | Runtime-complete | Management requires admin token. |
| Execution Broker | Docker/SSH/approver/admin modes | Deployment-specific | Runtime-complete bounded service | Not a general remote shell or Docker proxy. |

## Before enabling a gated feature

1. Confirm its executor and exact maturity in the relevant guide.
2. Use least-privilege worker-side credentials and explicit capability allowlists.
3. Validate the feature on a disposable target at the deployed image SHA.
4. Back up the platform and record a change window.
5. Enable only necessary gate(s), then confirm preview, approval, verification, and audit work.
6. Disable experimental gates after testing.
