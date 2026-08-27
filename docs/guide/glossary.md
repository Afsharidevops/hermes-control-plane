# Glossary

| Term | Meaning |
|---|---|
| ChangeSet | Immutable record that binds an intended operation to a canonical plan, risk, target snapshot, preview, approvals, and execution result. |
| Typed plan | A schema-limited, deterministic operation description; it is never an arbitrary shell, kubectl, Helm, or provider request body. |
| Snapshot | Canonical safe state captured during planning. A changed target, provider state, artifact manifest, policy generation, or plan hash invalidates authorization. |
| Preview | Deterministic or live dry-run/current-state comparison used before approval and execution. |
| Exact plan hash | SHA-256 identity of the approved canonical plan. Approval and tickets bind this hash. |
| Policy generation | Server-owned revision. A bump invalidates older pending ChangeSets and approvals. |
| Approval | Integrity-protected, expiring, exact-plan decision issued by the separate Approval Bot identity. HIGH and CRITICAL self-approval is prohibited; CRITICAL needs two distinct approvers. |
| Execution ticket | Short-lived HMAC-signed, one-time, executor-constrained grant. Replayed, expired, or mismatched tickets fail closed. |
| Credential reference | Metadata/fingerprint pointer to secret material; it is not a secret value. |
| Kubernetes Broker | Isolated kubeconfig, kubectl, Helm, Hubble, diagnostics, preview, and bounded Kubernetes execution boundary. |
| Node Agent | Provider, infrastructure, Proxmox, and host-observer service boundary. |
| Provider job | Persisted work item for cluster provider execution. |
| Operation job | Persisted execution item associated with an operations plan and a trusted executor. |
| Verification | Typed PASS/WARN/FAIL/SKIP checks recorded after observation or an operation. SKIP means no trusted active collector exists; it is not PASS. |
| Artifact manifest | Deterministic READY/BLOCKED selection of exact offline artifact identities bound to a blueprint and provisioning plan. |
| Runtime-complete | A governed executable path is implemented; consult its default gate and evidence limits. |
| Integration/local evidence | Bounded runtime code and local/mock verification exist, but no real-target proof is asserted. |
| Contract-only/deferred | Planner/UI/schema support without a trusted runtime, or intentionally postponed work. |

## Important states

- ChangeSets can become previewed, awaiting approval, approved, executed, failed, rejected, cancelled, expired, stale-policy, policy-denied, or preview-failed.
- Provider and operation jobs use RUNNING, PAUSED, SUCCEEDED, and FAILED state families with typed stages.
- Provider health uses HEALTHY, DEGRADED, UNREACHABLE, or UNKNOWN.
- Diagnostics and verification use PASS, WARN, FAIL, or SKIP.

## Identifier examples

Resource identifiers are generated server-side. Common prefixes include `cred_` for credential references, `srv_` for servers, `tgt_` for targets, `cbp_` for blueprints, `ipr_` for infrastructure providers, and `art_` for artifact items. Treat identifiers as references, not credentials.
