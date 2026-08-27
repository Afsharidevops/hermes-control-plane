# Operations Runbook

**Runtime-complete:** This runbook covers the supported platform lifecycle and safety controls. Treat optional provider and integration procedures according to their **Integration/local evidence** or **Contract-only/deferred** status in [Feature status](feature-status.md).

## Daily health and status

```bash
./hermesctl status
./hermesctl doctor
./hermesctl wait
./hermesctl execution status
./hermesctl router list
./hermesctl router probe
```

Use Control Plane **Overview**, **Operations Center**, **Changes**, and **Audit** to correlate a service condition with governed plans/jobs. A healthy container is not proof that a target, credential, policy, or executor is healthy.

## Safe enablement of execution gates

Default state is intentionally disabled:

```text
HERMES_EXECUTION_ENABLED=false
HERMES_KUBERNETES_EXECUTION_ENABLED=false
HERMES_PROVIDER_EXECUTION_ENABLED=false
HERMES_INFRASTRUCTURE_EXECUTION_ENABLED=false
HERMES_CAPACITY_COLLECTION_ENABLED=false
HERMES_VM_INVENTORY_COLLECTION_ENABLED=false
HERMES_PROXMOX_VM_RUNTIME_ENABLED=false
```

Before changing a gate:

1. Read the corresponding evidence label and exclusions in [Feature status](feature-status.md).
2. Back up the Control Plane and preserve a recovery plan for the target.
3. Validate credential scope, capability allowlists, private network/TLS, and target registration.
4. Test read-only discovery/diagnostics on a disposable or non-production target.
5. Enable the minimum gate(s), recreate affected services, and confirm health.
6. Execute a supported low-impact governed plan end-to-end, including independent approval where required, ticket validation, verification, and audit.
7. Disable temporary/testing gates after the window.

For the primary global/Kubernetes gates:

```bash
./hermesctl execution enable
./hermesctl execution status
./hermesctl execution disable
```

The CLI changes expected gates, recreates Control Plane/Kubernetes Broker, and waits for health. It never replaces ChangeSet, approval, ticket, or executor constraints.

## Router operations

| Situation | Safe response |
|---|---|
| Need a selected provider | `./hermesctl router set nine-router` or `./hermesctl router set omniroute`, then `router probe`. |
| Missing/invalid managed runtime key | `./hermesctl router provision <provider>`; it uses upstream management flow and avoids printing the key. |
| Stale duplicate upstream keys | `./hermesctl router cleanup-keys [nine-router|omniroute|all]`; it verifies active managed credential before cleanup. |
| Router Gateway unhealthy | Confirm selected upstream health, profile, internal networking, admin token configuration, and persisted router state. |
| Smart Router policy issue | Confirm `/health`, `/ready`, `/router/info`, provider health, mode/policy, guardrails, budgets, and identity configuration before changing routing behavior. |

## Backup and restore

### Backup

```bash
./hermesctl backup
```

The CLI uses SQLite's online backup mechanism and validates integrity. Record the artifact location through your approved backup system; do not publish host paths or copy a live database file while services are writing.

### Restore

```bash
./hermesctl restore <backup.sqlite3>
```

Restore validates the candidate and creates a safety backup before an atomic replacement. Stop/change-window coordination is still required. After restore, verify Control Plane health, audit availability, credential-reference metadata, agent/integration status, router state, and read-only target discovery. A database restore cannot undo already executed external infrastructure changes.

## Upgrade

```bash
./hermesctl version
./hermesctl version set <version>
./hermesctl upgrade <version>
```

`upgrade` verifies the published release, takes a backup, pulls images, and upgrades the stack. Pin release version and record the currently deployed image digests. Frozen tags—including `v0.5.11` and `v0.5.11-dev.5`—must never be moved/recreated. Before rollback, inspect database/schema compatibility and understand that rollback does not reverse external ChangeSets already executed.

## Job, verification, and recovery response

| Condition | Response |
|---|---|
| Preview failed / stale plan | Do not retry ticket. Correct target/policy/artifact/credential state and create a new plan. |
| Approval expired or policy changed | Request new approval for a fresh exact plan. |
| Ticket rejected/replayed | Investigate executor/audit records; never reuse an old ticket. |
| Job paused | Inspect typed job stage/events and dependencies; resume only through its supported governed path. |
| Job failed | Preserve evidence, inspect target state with read-only diagnostics, follow service-specific recovery, then create a fresh remediation plan. |
| Verification WARN/FAIL/SKIP | Treat as unresolved. Determine whether target state, collector access, or operation outcome requires remedial change. |
| Credential failure | Rotate/revoke/test through Credential Service; refresh references and re-plan. |

## Maintenance checklist

- Review service and dependency health regularly.
- Review audit retention/export policy and backup restore drills.
- Rotate service identities and worker credentials through approved secret-management procedure.
- Keep listener exposure private; verify ingress TLS and authentication after any network change.
- Re-test provider/infrastructure integrations when image, firmware, Kubernetes version, API, or credential policy changes.
- Run `docker compose config`, `helm lint`, and source validation gates before deployment changes.

See [CLI reference](cli-reference.md), [Kubernetes operations](kubernetes-operations.md), and [Governance](governance-and-changes.md).
