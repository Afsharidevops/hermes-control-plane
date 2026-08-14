# Hermes Control Plane — Development Handover

**Repository:** `Afsharidevops/hermes-control-plane`  
**Active development branch:** `dev/0.5.10-beta.1`  
**Frozen releases:** `v0.5.10-alpha.1`, `v0.5.10-alpha.2`  
**Current package:** `0.5.10-beta.1`

## Project purpose

Hermes Control Plane is a self-hosted AI-assisted DevOps management plane. It must run on a Docker/VM installation or Kubernetes and support runtime-selectable 9router or OmniRoute without separate router branches.

The key product rule is: AI plans; constrained brokers/agents execute. Raw infrastructure credentials must not be exposed to Smart Router/Hermes/LLM-facing services.

## Existing published image namespace

The new project is isolated from `hermes-linux-stack` by using only `hermes-control-plane-*` repositories:

- `afsharidevops/hermes-control-plane-api`
- `afsharidevops/hermes-control-plane-router-gateway`
- `afsharidevops/hermes-control-plane-smart-router`
- `afsharidevops/hermes-control-plane-execution-broker`
- `afsharidevops/hermes-control-plane-kubernetes-broker` (new in beta dev)
- `afsharidevops/hermes-control-plane-node-agent`

GitHub Actions uses `DOCKERHUB_USERNAME` as a repository variable and `DOCKERHUB_TOKEN` as an Actions secret. Main publishes `edge` + SHA tags; version tags publish the version; only stable tags publish `latest`.

## Alpha.2 state (frozen and validated)

Alpha.2 was merged into `main`, tagged correctly, published as multi-arch amd64/arm64 images, pulled from Docker Hub, and tested locally with both 9router and OmniRoute. A GitHub prerelease exists. Its development branch was deleted after merge.

Alpha.2 implemented Environment/Integration/Target registries, metadata-only credential refs, ChangeSet canonical JSON/SHA-256, risk classification, exact-hash approval binding, expiry, audit, and starter UI. Execution was disabled.

## Beta.1 dev.1 implemented in this package

### Kubernetes Broker

A new isolated `kubernetes-broker/` service/image contains kubectl and Helm. It has no Docker socket and no router authority.

Capabilities:
- Kubernetes discovery (`version`, namespaces, nodes, deployments/statefulsets/daemonsets)
- manifest server-side dry-run + diff
- guarded server-side apply
- Helm install/upgrade server dry-run with secret hiding
- Helm install/upgrade execution + status verification
- Helm rollback planning + execution
- conservative manifest kind allowlist
- explicit deny of Secrets, RBAC, admission webhooks, CSRs and CRDs
- broker-enforced namespace allow/deny and kind allow/deny target scopes
- Namespace mutation requires explicit `allow_cluster_scoped=true`
- discovery respects namespace scope and hides node inventory unless `cluster_read=true`

Execution defaults to disabled.

### Credential boundary for Docker/VM

`hermesctl kubeconfig import <name> <file>`:
- calls the Control Plane to create an opaque kubeconfig credential reference
- copies the kubeconfig locally to `data/kubeconfigs/<credential-id>.yaml` mode `0600`
- records only file ID + SHA-256 fingerprint in the Control Plane
- Kubernetes Broker receives the directory read-only

The Control Plane never receives the kubeconfig content. This is a beta file boundary, not the final encrypted credential service.

### ChangeSet schema v2

Plans now include an immutable target snapshot with credential metadata/fingerprint. Preview and execution fail if current target/credential metadata differs from the planned snapshot.

Live Kubernetes/Helm previews come from Kubernetes Broker, not user-supplied text.

Execution requires:
1. valid stored plan hash
2. live broker preview
3. valid exact-hash approval if risk requires approval
4. unchanged target snapshot
5. `HERMES_EXECUTION_ENABLED=true`
6. `HERMES_KUBERNETES_EXECUTION_ENABLED=true`
7. a short-lived HMAC-signed exact-plan broker ticket

Broker rejects in-process ticket replay.

### Operations Center

`/ui` now has Overview, Infrastructure, Changes and Audit views. It includes:
- environment management
- kubeconfig reference visibility
- Kubernetes target creation
- Kubernetes discovery
- manifest ChangeSet + live preview
- Helm ChangeSet + live preview
- approval and execute controls

### CLI

New commands:
- `hermesctl version`
- `hermesctl version set <version>`
- `hermesctl upgrade <version>`
- `hermesctl kubeconfig import <name> <file>`
- `hermesctl kubeconfig list`
- `hermesctl kubeconfig remove <credential-id>`

`upgrade` verifies published API/Kubernetes Broker image tags, takes a best-effort Control Plane DB backup, updates `.env`, pulls, health-starts, and restores the configured version on failure.

## Deployment

Docker Compose now runs Kubernetes Broker as a core internal service and mounts `./data/kubeconfigs` read-only.

The Helm chart deploys Kubernetes Broker too. ServiceAccount token automount is false by default. Direct kubeconfigs may be supplied via an existing Kubernetes Secret. The chart intentionally does not create broad Kubernetes RBAC.

## Current security limitations / remaining beta work

Do not treat dev.1 as feature-complete beta.1. Remaining work:
- dedicated encrypted credential service / external secret backend
- agent enrollment/identity/revocation and remote Kubernetes mode
- Telegram planning + separate approval bot integration
- GitHub/GitLab adapters and Application registry
- Docker/Compose/Swarm adapter
- SSH UI CRUD and credential rotation
- richer target policy, rollout verification/rollback metadata
- persistent replay protection / separate approval signing authority
- Node.js action warning cleanup

## Next implementation order

1. Test beta dev.1 on a disposable Kubernetes cluster with execution disabled: kubeconfig import, target creation, Discover, manifest live dry-run, Helm live dry-run.
2. Enable both execution switches only on that disposable cluster and validate exact approval -> apply -> audit.
3. Add Telegram approval integration using the exact ChangeSet hash.
4. Add GitHub/GitLab + Application registry.
5. Add Docker/Compose/Swarm, then SSH.
6. Merge to `main` only when beta acceptance tests pass; do not tag `v0.5.10-beta.1` from dev.1.

## Recommended continuation prompt

Upload the latest source ZIP and this HANDOVER.md, then say:

> Continue Hermes Control Plane from HANDOVER.md. Inspect the package first. Continue `dev/0.5.10-beta.1` from the current Kubernetes + Helm vertical slice without weakening the ChangeSet/credential/approval boundaries.

## Bot-only mutation architecture update

Kubernetes and Helm mutation is now intentionally bot-only.

- UI/admin: configuration + observability + discovery only.
- Hermes Bot: create/preview mutation ChangeSets, request approval, execute already-approved exact hashes, plan rollback.
- Approval Bot: separate token/identity; only it can approve/reject infrastructure mutation ChangeSets.
- Kubernetes Broker: unchanged credential/execution boundary.

The UI no longer contains manifest/Helm mutation editors or approval/execute buttons. Backend authorization also blocks admin-token mutation requests, so this is not a cosmetic restriction.

New env keys are generated by `./hermesctl init`:

- `HERMES_BOT_SERVICE_TOKEN`
- `HERMES_APPROVAL_BOT_TOKEN`
- `HERMES_CONTROL_PLANE_BOT_USERS` (operator-configured numeric Telegram allowlist)

New helper commands:

```bash
./hermesctl bot allow <numeric-telegram-user-id>
./hermesctl bot status
./hermesctl execution enable
./hermesctl execution disable
./hermesctl execution status
./hermesctl wait 90
```

The `control-plane-chatops` Hermes plugin is mounted read-only into the Hermes container and refuses mutation tools unless the session is interactive Telegram and the numeric user is allow-listed.

Current public-version policy: keep all work on `dev/0.5.10-beta.1`; do not create dev-version tags. Tag `v0.5.10-beta.1` only when the broad beta feature scope is integrated, then one `v0.5.10-rc.1`, then `v0.5.10` stable.
