# Hermes 0.5.11-dev.4 implementation evidence

Date: 2026-08-19

Status: **source implementation validated in the checkpoint workspace; real Git/CI/tag publication remains pending.**

Frozen prerequisite:

- `v0.5.11-dev.3` -> `8547c44de4f6e8116d70f2690b50a50c895eba34`
- dev.3 implementation commit -> `e51d7f99faa180974cb7a925e12b587d8432fd5b`
- PR `#2` remains Draft by policy.

## Validation evidence in this workspace

`./validate.sh` reached its PASS boundary with:

- dev.4 source/security gate: PASS
- dev.4 config/static gate: PASS
- Control Plane: 53 passed
- Credential Service: 12 passed
- Kubernetes Broker: 18 passed
- Execution Broker: 2 passed
- Smart Router: 117 passed
- Docker Compose config: SKIP because Docker is unavailable in this runtime
- Helm lint: SKIP because Helm is unavailable in this runtime

The Docker Compose and Helm checks therefore remain required on a validation host where those tools are installed before the dev.4 tag may be created.

## Dev.4 security/regression coverage added

The new Control Plane regression coverage exercises:

- one shared intent contract for UI/read and authenticated Telegram mutation planning;
- typed cloud/provider mutation planning;
- exact ChangeSet plan-hash and target-snapshot drift rejection;
- persisted typed-plan tamper rejection and integrity-checked approval MAC/expiry validation;
- short-lived HMAC-signed execution-ticket binding, exact approval consumption at execution start, and ChangeSet execution-state transitions;
- fleet selection snapshot binding and drift rejection;
- SHA-256-pinned air-gap artifact requirements;
- typed unified verification persistence;
- raw-secret-shaped desired-state rejection and embedded-URL-credential rejection.

The source/config gates also enforce the frozen dev.3 boundary, CI-owned production image publication, no arbitrary shell planner in the dev.4 operation contracts, required provider/version pins, a complete SHA-256 package manifest, and manifest verification before `apply.sh` copies source into a real Git checkout.

## Claims deliberately not made

This source-only workspace has no `.git` metadata, so it does not prove the real checkout branch, ancestry, commit SHA, dev.4 tag, GitHub branch CI result, tag publication result, or Docker Hub image publication.

No live VMware, OpenStack, AWS, Azure, GCP, Redfish/BMC, IPMI, PXE/iPXE or switch execution is claimed without separate disposable-target evidence.

## Required next release steps

1. Apply this source onto a clean real `dev/0.5.11` checkout that descends from frozen dev.3.
2. Run `./validate.sh` with Docker and Helm available; require every check to execute and pass.
3. Commit and push the intended dev.4 SHA without rewriting frozen history.
4. Confirm GitHub branch validation succeeds on that exact SHA.
5. Create `v0.5.11-dev.4` only through the guarded tag path using that exact CI-green SHA.
6. Verify all required GitHub Actions image publication jobs after the tag push.
7. Keep PR `#2` Draft unless explicitly instructed otherwise.
