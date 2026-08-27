# Kubernetes Operations

**Runtime-complete, gated:** Hermes provides scoped Kubernetes discovery, native diagnostics, Hubble collection, preview, and a bounded day-2 executor. It does not provide arbitrary `kubectl`, arbitrary Helm values, arbitrary log streaming, or a browser bypass. Kubernetes and Helm mutation is restricted to the Hermes Bot identity and must pass the [ChangeSet flow](governance-and-changes.md).

## Register and discover a target

1. Import or provision a least-privilege kubeconfig reference as described in [Credentials](credentials-agents-integrations.md).
2. Register an environment and Kubernetes target with safe scope/credential-reference metadata.
3. Confirm Kubernetes Broker `/health` and target authorization.
4. Run scoped discovery. Discovery returns normalized allowed state rather than a copy of arbitrary cluster resources.
5. Review **Infrastructure → Kubernetes** and **Operator Center → Kubernetes** before attempting a plan.

The Docker broker uses a read-only kubeconfig mount. In Kubernetes, choose a scoped `kubernetesBroker.kubeconfigSecret` or an explicitly reviewed service-account identity; automatic service-account token mounting is off by default.

## Client compatibility

The broker contains kubectl patch versions for Kubernetes minors 1.33–1.36:

| Target minor | Bundled kubectl |
|---|---|
| 1.33 | `v1.33.13` |
| 1.34 | `v1.34.10` |
| 1.35 | `v1.35.6` |
| 1.36 | `v1.36.2` |

With `HERMES_DYNAMIC_KUBECTL_ENABLED=true`, Hermes probes the live API minor and selects an exact-preferred client; selection is cached for `HERMES_KUBECTL_CACHE_TTL_SECONDS`. Build image changes to patch versions must be validated against target clusters. The broker also bundles Helm `v4.2.2` and Hubble `v1.19.4`.

## Discovery, diagnostics, and verification

### Native diagnostics

Diagnostics return typed `PASS`, `WARN`, `FAIL`, or `SKIP`, not arbitrary remote command output. Families include:

- Cluster health, resource, storage, rollout, and namespace/workload observations.
- Cilium/Hubble and DNS checks.
- Ingress, TLS, service exposure, and webhook checks.
- RBAC, privileged workload, Linux capability, and hostPath checks.
- Argo CD/GitOps checks.

`SKIP` means the requested trusted signal was unavailable. Do not report it as healthy.

### Hubble collection

Hubble uses a bounded `hubble observe --port-forward --output jsonpb` collection path. `last` is 1–200 and `since_seconds` is 1–3600. Hermes sanitizes results: it excludes raw flow bodies, L7 URLs, headers, bodies, IP addresses, and arbitrary protobuf fields, and attests `raw_flow_bodies_returned: false`.

### Radar and unified verification

Radar intelligence and unified verification combine allowed discovery/diagnostic sources into safe findings. They are operational evidence, not an authorization to mutate and not an exhaustive security assessment.

## Preview before execution

Use the supported manifest/Helm preview route to obtain server-side dry-run/diff and target state binding. A fresh preview is required when the target, policy, artifact, credential reference, or plan material changes. Preview failure or inability to collect trusted state fails closed.

## Supported day-2 operations

All entries below require their documented plan schema, configured gate(s), target scope, bot identity, risk policy, approval(s), signed ticket, bounded executor, verification, and audit.

| Operation | Boundaries |
|---|---|
| `cluster.node.cordon` | Exact scoped node; no arbitrary command arguments. |
| `cluster.node.uncordon` | Exact scoped node. |
| `cluster.node.drain` | Fixed drain options and bounded timeout. |
| `cluster.workload.restart` | Deployment, StatefulSet, or DaemonSet only. |
| `cluster.workload.scale` | Deployment or StatefulSet only; 0–10,000 replicas. |
| `cluster.addon.install` | Catalogued addon with explicit pins where required. |
| `cluster.addon.upgrade` | Catalogued addon with explicit pins and compatibility review. |
| `cluster.helm.apply` | Pinned chart version and bounded typed values. |
| `cluster.gitops.sync` | Exact 40/64-hex commit revision required. |
| `cluster.cilium.upgrade` | Cilium chart only, `kube-system`, pinned version. |
| `cluster.backup.velero` | Bounded Velero backup parameters. |
| `cluster.backup.schedule` | Bounded Velero schedule parameters. |
| `cluster.restore` | Bounded restore workflow; CRITICAL and requires two distinct approvals. |

No automatic rollback is implied by a failed job. Capture backup/recovery options before upgrade or restore and inspect final verification.

## Safe execution procedure

1. Keep `HERMES_EXECUTION_ENABLED=false` and `HERMES_KUBERNETES_EXECUTION_ENABLED=false` until discovery, diagnostics, and a disposable target validation succeed.
2. Enable only the required gate(s) during a change window, then restart/recreate the affected services as instructed by `hermesctl execution enable`.
3. Generate and inspect a typed plan/preview from the permitted ChatOps/API path.
4. Use separate eligible approver identities; do not self-approve HIGH/CRITICAL operations.
5. Follow ChangeSet/job status to verification. Treat WARN/FAIL/SKIP as a review trigger.
6. Disable gates after temporary testing and retain audit/backup evidence.

## Kubernetes Broker API

| Method | Route | Use |
|---|---|---|
| `GET` | `/health` | Broker health/capability check. |
| `POST` | `/v1/discover` | Scoped discovery. |
| `POST` | `/v1/diagnostics/run` | Native diagnostics. |
| `POST` | `/v1/hubble/collect` | Sanitized bounded Hubble collection. |
| `POST` | `/v1/day2/preview` | Bounded day-2 preview. |
| `POST` | `/v1/day2/execute` | Ticket-bound day-2 execution. |
| `POST` | `/v1/preview` | Manifest/Helm preview. |
| `POST` | `/v1/execute` | Ticket-bound manifest/Helm execution. |

See [API reference](api-reference.md) for authentication boundaries and [Operations runbook](operations-runbook.md) for failure handling.
