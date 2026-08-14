# Hermes Control Plane — Chat Handover

**Last updated:** 2026-08-14 19:02 +03:30  
**Current implementation package:** `0.5.10-alpha.2`  
**Repository:** `Afsharidevops/hermes-control-plane`  
**Legacy project kept separate:** `Afsharidevops/hermes-linux-stack`

## How to resume in a later ChatGPT conversation

Upload this file (and, when useful, the latest project ZIP) and say:

> Continue Hermes Control Plane from HANDOVER.md. Inspect the current package/repository state first, preserve the security boundaries and Docker image naming policy, and continue with the next milestone.

## Product direction

Hermes Control Plane is the new project derived from Hermes Linux Stack. It is intended to become a self-hosted AI-assisted DevOps control plane with full management from UI/API/CLI/Telegram while keeping privileged credentials and execution outside the LLM trust boundary.

It must run in either deployment mode:

- on-prem VM/bare metal with Docker Compose
- Kubernetes with the Hermes Control Plane Helm chart

9router and OmniRoute are runtime-selectable providers in the same codebase. There must not be separate long-lived branches for each provider.

## Permanent naming/isolation rule

The new project must never overwrite Docker Hub repositories owned by `hermes-linux-stack`.

Legacy examples reserved for the old stack:

```text
afsharidevops/hermes-smart-router
afsharidevops/hermes-execution-broker
```

New project-owned repositories:

```text
afsharidevops/hermes-control-plane-api
afsharidevops/hermes-control-plane-router-gateway
afsharidevops/hermes-control-plane-smart-router
afsharidevops/hermes-control-plane-execution-broker
afsharidevops/hermes-control-plane-node-agent
```

This policy must remain consistent in Compose, Helm, local scripts, GitHub Actions and documentation.

## GitHub / Docker Hub state established by the operator

GitHub repository exists:

```text
https://github.com/Afsharidevops/hermes-control-plane
```

The operator authenticated GitHub CLI and successfully pushed `main` and `v0.5.10-alpha.1`.

Docker Hub contains the five isolated `hermes-control-plane-*` repositories above. Alpha.1 images were successfully pushed locally.

GitHub Actions has been connected to Docker Hub using:

```text
Repository variable: DOCKERHUB_USERNAME=afsharidevops
Repository secret:   DOCKERHUB_TOKEN=<Docker Hub PAT; value is not stored here>
```

Never request or record the token value in project files or this handover.

## CI/release policy

Normal image publishing is now GitHub Actions. `scripts/push-images.sh` remains an emergency/manual fallback.

Desired Docker tag behavior:

```text
Pull request        -> build only, no Docker Hub push
main push           -> :edge + :sha-<commit>
v0.5.10-alpha.2     -> :0.5.10-alpha.2 (+ sha tag)
v0.5.10-beta.1      -> :0.5.10-beta.1 (+ sha tag)
v0.5.10-rc.1        -> :0.5.10-rc.1 (+ sha tag)
v0.5.10             -> :0.5.10 + :latest (+ sha tag)
```

Alpha/beta/RC tags must never move `latest`.

The workflow file is `.github/workflows/publish-images.yml` and builds `linux/amd64,linux/arm64` with Buildx/QEMU.

## Important current Git/tag issue

The operator accidentally created and pushed `v0.5.10-alpha.2` before alpha.2 code was implemented. That tag points to alpha.1-era code plus the Docker publishing workflow.

Before publishing the real alpha.2, remove the premature tag:

```bash
git push origin :refs/tags/v0.5.10-alpha.2 || true
git tag -d v0.5.10-alpha.2 2>/dev/null || true
```

If Docker Hub already received a premature `0.5.10-alpha.2` image tag, it does not need a separate deletion; the correct tag-triggered build can replace the tag after the source release is fixed.

## Alpha.1 foundation completed

`0.5.10-alpha.1` established:

- monorepo
- migrated Smart Router foundation
- migrated Execution Broker foundation
- router gateway
- runtime 9router/OmniRoute selection
- Control Plane API skeleton
- Node Agent skeleton
- Docker Compose deployment
- initial Helm chart
- isolated Docker image naming
- local multi-arch push scripts
- GitHub validation/publishing foundation
- architecture/security plan

The operator tested Docker Compose locally. 9router and OmniRoute both started successfully and runtime switching worked.

## Alpha.2 implementation in the current ZIP

The accelerated roadmap merged the old Integration Registry and ChangeSet milestones into one release: **Management + Safety Core**.

Implemented in this package:

### Management registry

- persistent Environment Registry
- persistent Integration Registry
- persistent Target Registry
- credential-reference registry containing metadata only
- integration environment/scope/connection metadata
- HTTP/HTTPS connection health probe foundation
- starter Operations Center management UI at `/ui`
- alpha.1 SQLite migration/backfill

### ChangeSet safety core

- typed ChangeSet plan envelope
- deterministic canonical JSON
- SHA-256 plan hash
- risk levels: `READ`, `LOW`, `HIGH`, `CRITICAL`
- risk is computed by the server; callers cannot lower it in the request
- preview storage
- ChangeSet states used in alpha.2: `PLANNED`, `PREVIEWED`, `AWAITING_APPROVAL`, `APPROVED`, `REJECTED`, `CANCELLED`, `EXPIRED`
- approval bound to exact `plan_hash`
- HIGH/CRITICAL requester self-approval is blocked
- expiry
- append-oriented audit events
- no privileged execute endpoint

### Tests/validation

The generated package was validated in the artifact environment with:

```text
Control Plane tests: 5 passed
Python compileall: passed
Bash syntax checks: passed
YAML parsing: passed
```

Docker Engine and Helm were not available in the artifact environment, so Docker Compose runtime and `helm lint` must be confirmed by the operator/GitHub `validate` workflow after push.

## Security invariants that must not be weakened

- LLM/Smart Router must not receive Docker sockets.
- LLM/Smart Router must not receive raw kubeconfigs.
- LLM/Smart Router must not receive SSH private keys/passwords.
- LLM/Smart Router must not receive GitHub/GitLab tokens.
- LLM/Smart Router must not receive registry passwords.
- Credential objects in the general Control Plane are opaque references, not secret values.
- AI may interpret/plan/explain; brokers/agents execute only policy-authorized ChangeSets.
- Mutation must be plan-first and preview/dry-run-first where supported.
- Approval must bind to exact target/parameters/revision/policy generation/plan hash.
- Any material plan change invalidates approval.
- Critical/destructive behavior is deny-by-default.
- Secrets must not be pasted into Telegram as the normal credential setup path.
- Audit must identify requester/planner/approver/executor/target/outcome/hashes.

## Router design

Smart Router uses neutral aliases such as:

```text
hermes/observe
hermes/fast
hermes/standard
hermes/strong
hermes/coding
hermes/vision
```

`router-gateway` translates/forwards to the selected upstream provider.

Operator commands:

```bash
./hermesctl router list
./hermesctl router set nine-router
./hermesctl router set omniroute
```

The same repository and deployment packages support both providers.

## Deployment design

Docker/VM:

```bash
./hermesctl init
./hermesctl up
```

After official images are published, pull-only deployment is available in alpha.2:

```bash
./hermesctl up --pull
```

Kubernetes:

```bash
helm upgrade --install hermes-control-plane ./charts/hermes-control-plane \
  -n hermes-system --create-namespace
```

The runtime cluster (where Hermes runs) and managed clusters are separate concepts. Managing the runtime/self-hosting cluster later must receive elevated risk.

## Accelerated remaining roadmap

### 0.5.10-beta.1 — feature-complete DevOps adapters

Kubernetes/Helm:

- isolated credential backend for kubeconfig/service-account material
- direct Kubernetes connection
- Node Agent Kubernetes connection
- cluster/namespace/workload discovery
- logs/events/status
- manifest server-side dry-run/diff/apply
- rollout verify/rollback
- Helm repository/OCI, plan/install/upgrade/rollback
- namespace/resource allow/deny policy
- protect Secret values, RBAC escalation and cluster-admin by default

Git/applications:

- GitHub integration (prefer GitHub Apps where possible)
- GitLab integration (minimum-scoped project/group credentials)
- Application Registry
- branch/commit/PR/MR workflows
- GitOps mode
- deployment verification and rollback metadata

Docker/Compose/Swarm:

- structured container/Compose plans
- Compose validate/pull/up/down
- Swarm stacks/services/scale/update/rollback
- Docker socket only on isolated broker/agent

SSH:

- Operations Center SSH CRUD
- fingerprint verification
- credential rotation reference
- approved execution through isolated broker/agent

Telegram:

- Hermes bot for planning/status
- separate approval bot
- exact ChangeSet summary/hash/expiry in approval
- approved execution only through broker/agent

### 0.5.10-rc.1 — hardening

- threat-model review
- real credential service / secret backend and rotation
- agent enrollment/device identity/replay protection/revocation
- policy generation invalidation
- two-person critical approval
- backup/restore
- audit retention/export
- HA
- Docker-to-Kubernetes migration tests
- upgrade/rollback tests
- failure/network-loss tests
- security/operator docs

### 0.5.10 — stable

Release only after all acceptance gates in `plan.md` pass.

## Recommended next architectural task

Before implementing arbitrary `kubectl`, Helm, Docker, Git or SSH command execution, build the beta adapter contract around the alpha.2 ChangeSet model:

```text
discover()
validate()
plan()
preview()
execute()
verify()
rollback()
```

The planner chooses adapters. Adapters do not grant authority. Authority comes from policy plus target-scoped credentials and a valid approval envelope.

The first beta vertical slice should be Kubernetes + Helm because it exercises discovery, credentials, dry-run/diff, high-risk approval, execution, verification and rollback. Build it end-to-end for one safe namespace before adding broad Git/Docker/SSH mutation.

## Fast alpha.2 release commands

See `docs/UPGRADE-ALPHA2.md`. The intended flow is:

1. delete the premature alpha.2 tag
2. overlay the alpha.2 ZIP on the existing checkout
3. update existing `.env` to `VERSION=0.5.10-alpha.2`
4. run verification
5. commit/push directly to `main` for the fastest alpha release
6. wait for `validate`
7. recreate/push `v0.5.10-alpha.2`
8. let GitHub Actions publish all five multi-arch images
9. test `./hermesctl up --pull`

## Files to inspect first in the next chat

```text
HANDOVER.md
plan.md
SECURITY.md
docs/ALPHA2.md
docs/UPGRADE-ALPHA2.md
control-plane/src/hermes_control_plane/main.py
control-plane/src/hermes_control_plane/db.py
control-plane/src/hermes_control_plane/models.py
control-plane/src/hermes_control_plane/risk.py
.github/workflows/validate.yml
.github/workflows/publish-images.yml
docker-compose.yml
charts/hermes-control-plane/
```
