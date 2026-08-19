# Hermes Control Plane 0.5.11-dev.2 status

## Baseline and branch rules

- Stable `v0.5.10` is historical and is not recreated by this package.
- `0.5.11-dev.1` baseline is commit `1764cad667717ec78156af8f9f3fcc30eb84c1f5` and is treated as an ancestor, not redone.
- Apply/push scripts require branch `dev/0.5.11` and verify that dev.1 commit is an ancestor.
- PR #2 is intentionally kept Draft. The local scripts never change pull-request state.

## 0.5.11-dev.2 completion

The dev.2 trust/bootstrap slice is implemented:

- isolated Credential Service with Fernet-encrypted local material, external-reference backends, safe tests, metadata/name update, rotate/revoke/delete lifecycle, redacted responses, audit, and fail-closed Control Plane metadata synchronization;
- Server Registry with management/provisioning/BMC addresses, duplicate-address protection, pinned SSH host fingerprint, connection mode, SSH/BMC credential references, environment/site/rack/zone metadata, inventory, and preflight state;
- deterministic fixed read-only SSH preflight plans with exact target/credential metadata snapshots and provider-job-bound results;
- generic provider lifecycle and provider-job foundation with ordered events, SSE stream, pause/resume, bounded retry, and exact ChangeSet/hash/policy-state revalidation;
- Kubespray/K3s/RKE2 bootstrap planning behind PASS preflight and HIGH-risk Hermes ChangeSets/approval;
- first-class Radar/Hubble provider contracts with no governance bypass; Hubble requires authorization/redaction/aggregation before AI/UI exposure;
- Aban remains an ideas-only reference and is not a runtime dependency.

## Image publication policy

Production image publication remains CI-owned. `.github/workflows/publish-images.yml` builds all seven Hermes image contexts for `linux/amd64` and `linux/arm64` and publishes non-PR builds to the user's Docker Hub using GitHub Secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Provenance and SBOM generation remain enabled.

`push.sh` only validates and pushes Git commits/source plus an optional Git tag. It has no Docker/GHCR publication path and does not change PR #2 out of Draft.

## Validation performed in this handoff environment

All locally executable dev.2 gates pass:

- dev.2 source/security gate: PASS
- dev.2 static Compose/chart/workflow gate: PASS
- Control Plane: 39 passed
- Credential Service: 12 passed
- Kubernetes Broker: 18 passed
- Execution Broker: 2 passed
- Smart Router: 117 passed
- Python compilation: PASS
- shell syntax: PASS

Docker and Helm executables are not installed in this sandbox, so local `docker compose config`, local container builds, and local `helm lint` could not be executed. `validate.sh` reports those environment-dependent checks as explicit SKIPs rather than claiming they ran. The GitHub `validate` workflow still executes Docker Compose configuration and Helm lint on branch/PR CI, and the image workflow performs the multi-architecture image builds after source/tag push.

Validation evidence is retained in:

- `release-evidence/0.5.11-dev.2-validation.txt`
- `release-evidence/0.5.11-dev.2-source-gate.txt`

## Handoff commands

1. Run `apply.sh` from the completed source snapshot (or set `HERMES_DEV2_SOURCE_DIR`) against the existing `dev/0.5.11` checkout.
2. Run `validate.sh` in the target checkout.
3. Run `push.sh --commit` to create/push the dev.2 source commit after validation.
4. Add `--tag` only when the `v0.5.11-dev.2` Git tag is desired. GitHub Actions, not the local script, owns image publication.
