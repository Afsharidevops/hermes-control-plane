# Kubernetes Deployment with Helm

The chart is [charts/hermes-control-plane/](../../charts/hermes-control-plane/). It deploys the Control Plane, Credential Service, Kubernetes Broker, Router Gateway, Smart Router, and selected upstream router. Node Agent, host observer, and the optional Hermes agent are off by default.

## Preconditions

- A Kubernetes cluster and a dedicated namespace.
- Helm 3 or later.
- An externally managed Kubernetes Secret containing the service identities and secrets listed in `values.yaml` under `secrets`.
- A persistence class if persistent Control Plane or Credential Service data is required.
- A private ingress, TLS, network policy, and secret-management review before any external exposure.

## Install safely

Create a values override that selects image versions, router, persistence, and one existing secret. Do not place literal secret values in a committed values file.

```yaml
imageNamespace: <registry-namespace>
imageTag: <approved-image-tag>
router:
  activeProvider: nine-router
persistence:
  enabled: true
  size: 5Gi
credentialService:
  persistence:
    enabled: true
    size: 1Gi
secrets:
  existingSecret: <namespace-secret-name>
```

```bash
helm upgrade --install hermes ./charts/hermes-control-plane \
  --namespace <namespace> --create-namespace \
  --values <safe-values-file>
helm status hermes --namespace <namespace>
```

The chart's `secrets.*` inline fields exist for bootstrap/testing compatibility. Prefer `secrets.existingSecret` for any environment that persists data or is shared. Never include a secret-bearing values file in source control or a ticket.

## Values reference

### Images and routing

| Values path | Default posture | Operator use |
|---|---|---|
| `imageNamespace`, `imageTag`, `imagePullPolicy` | project image defaults | Pin approved images and pull policy. |
| `router.activeProvider` | `nine-router` | Select `nine-router` or `omniroute`. |
| `routers.nineRouter.enabled`, `routers.nineRouter.image` | enabled | Configure upstream image. |
| `routers.omniroute.enabled`, `routers.omniroute.image` | disabled | Enable only when selected and secured. |
| `routerGateway.enabled`, `routerGateway.service` | enabled, ClusterIP | Internal router alias proxy. |
| `smartRouter.enabled`, `smartRouter.service` | enabled, ClusterIP | Internal OpenAI-compatible router and control UI. |

### Control Plane and artifacts

| Values path | Default posture | Operator use |
|---|---|---|
| `controlPlane.enabled` | enabled | Main API/UI. |
| `controlPlane.executionEnabled` | false | Global governed execution gate; do not enable alone. |
| `controlPlane.service.type`, `controlPlane.service.port` | ClusterIP / 8800 | Expose only through reviewed private routing. |
| `controlPlane.artifactMirror.*` | empty allowlists, bounded sizes | Configure exact HTTPS/OCI allowlists, mounted auth-secret names/files, and transfer limits. |

### Credentials and Kubernetes Broker

| Values path | Default posture | Operator use |
|---|---|---|
| `credentialService.enabled`, `credentialService.service` | enabled, ClusterIP | Credential lifecycle service. |
| `credentialService.persistence.*` | enabled, 1Gi | Retain encrypted local credential state where applicable. |
| `kubernetesBroker.enabled` | enabled | Scoped Kubernetes discovery/execution boundary. |
| `kubernetesBroker.executionEnabled` | false | Enables broker executor only; global governance still applies. |
| `kubernetesBroker.commandTimeout` | 60 seconds | Bounded command timeout. |
| `kubernetesBroker.kubeconfigSecret` | empty | Supply a reviewed secret only when needed. |
| `kubernetesBroker.inCluster.automountServiceAccountToken` | false | Keep false unless a narrowly scoped in-cluster identity is required. |

### Optional workers and observers

| Values path | Default posture | Operator use |
|---|---|---|
| `hermesAgent.enabled`, `hermesAgent.image` | disabled | Optional Hermes/Telegram service. |
| `nodeAgent.enabled`, `nodeAgent.executionEnabled`, `nodeAgent.sshProfileSecret` | disabled | Existing-host cluster provider worker. |
| `hostObserver.enabled`, `hostObserver.identity`, `hostObserver.service` | disabled | Read-only host-network collection boundary. |
| `nodeAgent.infrastructureExecutionEnabled`, `infrastructureCredentialSecret`, `infrastructureAllowHttp` | false | Gated BMC/PXE/switch/Proxmox integrations; HTTP remains false. |
| `nodeAgent.proxmoxVmRuntimeEnabled` | false | QEMU runtime gate; integration/local evidence only. |
| `nodeAgent.capacityCollectionEnabled`, `nodeAgent.vmInventoryCollectionEnabled` | false | Read-only Proxmox collectors; integration/local evidence only. |
| `nodeAgent.*Timeout`, `*Max*`, `*Verify*` | bounded defaults | Request-size, request-count, polling, and verification safety ceilings. |
| `nodeAgent.filesRepoUrl`, `aptRepoUrl`, `rpmRepoUrl`, `pypiUrl` | empty | Explicit offline provider repository sources. |

### Platform scheduling and exposure

| Values path | Default posture | Operator use |
|---|---|---|
| `persistence.enabled`, `size`, `storageClass` | disabled, 5Gi | Control Plane persistence selection. |
| `ingress.enabled` | false | Enable only with DNS, TLS, and access policy. |
| `ingress.className`, `host`, `tls`, `secretName` | placeholders / false | Ingress routing and TLS secret. |
| `resources`, `nodeSelector`, `tolerations`, `affinity` | empty | Standard workload placement/resource controls. |

## Secret mapping

The chart reads service identity keys from the existing Secret, including control admin, bot and approval identities, credential identities and master key, broker/provider/observer identities, execution HMAC, router/Smartrouter secrets, bootstrap password, and upstream router bootstrap/management encryption secrets. Match the exact key names in `values.yaml`; use a secrets manager/controller where possible.

## Upgrade and rollback

1. Back up first: use the procedure in [Operations runbook](operations-runbook.md).
2. Render before applying: `helm template` and `helm lint`.
3. Pin the tested image tag; do not use a mutable tag for an upgrade gate.
4. Run `helm upgrade --install` with the reviewed override.
5. Verify pod readiness, internal health endpoints, login/admin access, and read-only discovery before enabling any gate.
6. If rollback is necessary, use a Helm revision only after checking database/schema compatibility. A Helm rollback does not erase an already executed external operation.

See [Configuration](configuration.md), [Kubernetes operations](kubernetes-operations.md), and [Security policy](../../SECURITY.md).
