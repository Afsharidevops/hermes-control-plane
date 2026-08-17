# Hermes Control Plane 0.5.10 stable acceptance

`v0.5.10` is the first stable release. The stable tag is created only after the pre-tag candidate has passed the source gate and the real Docker/Kubernetes acceptance matrix.

## 1. Freeze a pre-tag candidate

Use the commit that has already passed CI and build all six Hermes images under a non-release tag:

```bash
sha="$(git rev-parse --short=12 HEAD)"
candidate="0.5.10-candidate.${sha}"
# Run the Build and Publish Docker Images workflow with candidate_tag=$candidate.
./scripts/acceptance/candidate-images.sh "$candidate"
```

The candidate-image gate requires both `linux/amd64` and `linux/arm64` for API, Router Gateway, Smart Router, Execution Broker, Kubernetes Broker, and Node Agent.

## 2. Source/security gate

```bash
./scripts/stable-source-gate.sh
```

This includes Control Plane/Kubernetes Broker tests, the full Smart Router regression suite, Python compilation, version alignment, shell syntax checks, and stable security/deployment invariants. Evidence is written to `release-evidence/stable-source-gate.txt`.

## 3. Clean Docker Compose install

Run on a disposable supported Linux VM with Docker Engine + Compose v2:

```bash
git checkout <validated-commit>
cp .env.example .env
./hermesctl init
./hermesctl version set "$candidate"
./hermesctl execution off
./hermesctl router set nine-router
./hermesctl up --pull
./hermesctl wait 180
./hermesctl doctor
./hermesctl router probe
```

Repeat from a clean Docker volume set with OmniRoute:

```bash
./hermesctl down
# Remove only the disposable acceptance VM's Hermes volumes.
./hermesctl router set omniroute
./hermesctl up --pull
./hermesctl wait 180
./hermesctl doctor
./hermesctl router probe
```

Keep mutation execution disabled for the install checks.

## 4. Clean Helm install

Run on a disposable supported Kubernetes cluster. Keep both execution gates disabled initially:

```bash
helm upgrade --install hermes ./charts/hermes-control-plane \
  --namespace hermes --create-namespace \
  --set imageTag="$candidate" \
  --set controlPlane.executionEnabled=false \
  --set kubernetesBroker.executionEnabled=false \
  --set persistence.enabled=true \
  --set router.activeProvider=nine-router
kubectl -n hermes rollout status deploy/hermes-hermes-control-plane --timeout=180s
```

Repeat the router-provider acceptance with `router.activeProvider=omniroute`, enabling the matching router and disabling the other if custom values changed their defaults.

## 5. Security/credential/approval acceptance

The source gate covers automated checks for these requirements:

- caller cannot select policy generation; policy bumps invalidate stale ChangeSets/approvals;
- CRITICAL requires two distinct exact-hash approvers and requester self-approval is forbidden;
- approval envelopes carry policy identity/generation, nonce, expiry and HMAC, and are consumed before broker execution;
- raw secret-bearing credential metadata is rejected;
- Kubernetes and SSH credential references can be created, rotated and deleted with auditable fingerprints/references;
- Agent enrollment tokens are one-time; heartbeat nonces reject replay; revoked agents lose access;
- audit export has a SHA-256 digest and retention pruning is audited;
- execution remains disabled by default;
- LLM-facing Compose services have no Docker socket.

For a live high-risk mutation acceptance, enable both execution gates only on the disposable target, create/preview/request approval/approve the exact ChangeSet, execute it, then disable execution again.

## 6. Backup/restore and failover

Create and verify an online Control Plane backup:

```bash
./hermesctl backup
./hermesctl restore backups/<selected-backup>.sqlite3
./hermesctl doctor
```

The supported 0.5.10 HA posture is **single-active SQLite with backup/restore failover**. Active-active Control Plane replicas sharing SQLite are not supported. Automated tests verify policy generation and audit state survive a single-active failover copy.

## 7. Docker -> Kubernetes migration

On the Docker source, create an integrity-checked backup. Restore that database into the Kubernetes Control Plane persistent volume while the destination Control Plane is stopped, then start the destination and compare state/API surfaces:

```bash
python3 scripts/acceptance/api-equivalence.py http://<docker-control-plane>:8800 http://<k8s-control-plane>
python3 scripts/acceptance/migration-acceptance.py http://<docker-control-plane>:8800 http://<k8s-control-plane>
```

The migration check requires equal version, authoritative policy generation, and registry counts. Credential **secret material is not in the Control Plane database**; migrate the referenced external Secret/Vault/local credential material separately and preserve its reference/fingerprint contract.

## 8. Upgrade/rollback matrix

On isolated installations, run both source paths against the same pre-tag candidate:

1. `v0.5.10-beta.1` -> `$candidate` -> verified restore/rollback -> `$candidate` again.
2. `v0.5.10-rc.1` -> `$candidate` -> verified restore/rollback -> `$candidate` again.

For each path, capture a pre-upgrade `./hermesctl backup`, record registry counts and policy generation before/after, run `./hermesctl doctor`, and verify one read-only Kubernetes discovery plus one approval-required preview flow. Rollback means restoring the pre-upgrade database and previous published image version, not forcing a newer schema into an older binary.

## 9. Promote stable

Only after all prior sections pass on the exact candidate commit:

```bash
git checkout main
git merge --ff-only <validated-development-branch-or-commit>
# Wait for validation CI on this exact main commit.
git tag -a v0.5.10 -m "Hermes Control Plane 0.5.10"
git push origin main v0.5.10
```

The tag workflow publishes `0.5.10`; stable policy may also publish `latest`. Do not retag or rebuild a different source commit after acceptance.
