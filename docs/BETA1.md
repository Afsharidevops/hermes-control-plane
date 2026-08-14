# 0.5.10-beta.1 development — Kubernetes + Helm vertical slice

This development snapshot is the first adapter implementation built on the alpha.2 ChangeSet safety core.

## Implemented in dev.1

- dedicated `hermes-control-plane-kubernetes-broker` image
- Kubernetes discovery without reading Secret objects
- local kubeconfig import on Docker/VM with SHA-256 fingerprint binding
- immutable ChangeSet target snapshots including credential metadata fingerprint
- Kubernetes manifest server-side dry-run and diff
- beta manifest kind allowlist; Secret/RBAC/webhook/CRD objects are denied
- target-level namespace allow/deny lists and resource-kind policy enforcement
- cluster-scoped Namespace mutation denied unless `scope.allow_cluster_scoped=true`
- writable ephemeral HOME/Helm cache under read-only broker root filesystem
- Helm install/upgrade server-side dry-run with `--hide-secret`
- Helm rollback planning via release history
- exact-plan signed HMAC execution tickets
- target/credential drift detection before preview and execution
- one-use execution tickets within a broker process
- Kubernetes/Helm execution opt-in, disabled by default
- Operations Center Kubernetes target/discovery and plan/approval/execute views
- `hermesctl kubeconfig import|list|remove`
- `hermesctl version`, `version set`, and guarded `upgrade`
- Docker Compose and Helm deployment wiring for Kubernetes Broker
- GitHub CI / Docker Hub matrix includes Kubernetes Broker

## Docker/VM kubeconfig boundary

The Control Plane API never receives kubeconfig contents. Import locally:

```bash
./hermesctl kubeconfig import production ~/.kube/prod.yaml
./hermesctl kubeconfig list
```

The kubeconfig is copied to `data/kubeconfigs/<credential-id>.yaml` with mode `0600`. The Control Plane stores only an opaque credential reference, file identifier, and SHA-256 fingerprint. Kubernetes Broker receives the directory read-only.

This is a beta boundary, not the final credential architecture. Encrypted external secret backends and UI rotation are RC work.

## Safe execution flow

```text
UI / API
  -> ChangeSet schema v2
  -> target + credential snapshot
  -> SHA-256 plan hash
  -> Kubernetes Broker live preview
  -> risk engine
  -> approval when required
  -> re-check target snapshot
  -> signed short-lived execution ticket
  -> Kubernetes Broker
  -> kubectl / Helm
  -> result + verification
  -> audit
```

`HERMES_EXECUTION_ENABLED=false` and `HERMES_KUBERNETES_EXECUTION_ENABLED=false` are the defaults. Both must be true for mutations.

## Beta safety floor

Manifest apply currently permits only a conservative set of common application resources. The broker denies Secrets, RBAC objects, admission webhooks, CSRs, and CRDs. This is intentionally restrictive.

Target scope can use `namespace_allowlist`, `namespace_denylist`, `kind_allowlist`, `kind_denylist`, `cluster_read`, and `allow_cluster_scoped`. Namespace/resource policy is enforced again inside Kubernetes Broker, not only in the UI or planner.

The beta slice does not yet implement Telegram approval, Git/GitLab, Docker/Compose/Swarm adapters, SSH UI CRUD, an encrypted credential service, or agent enrollment/revocation.

## Kubernetes deployment of the Control Plane

The Helm chart deploys Kubernetes Broker with service-account token automount disabled by default. For direct kubeconfig mode, mount an existing Kubernetes Secret with credential files and create matching metadata references. In-cluster management should use a dedicated least-privilege ServiceAccount; broad RBAC is intentionally not created automatically.


## Batch A — Kubernetes + Helm completion

The beta branch now includes guarded Kubernetes apply/update, delete preview/execution, captured before-state, signed live-state preconditions, generated rollback ChangeSets, workload rollout verification, Helm release preconditions, install/upgrade verification, rollback, and rollback-to-uninstall for first installs. These are development capabilities on `dev/0.5.10-beta.1`; they do not create an additional public version.
