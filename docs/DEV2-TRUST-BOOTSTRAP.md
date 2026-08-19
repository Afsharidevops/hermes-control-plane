# 0.5.11-dev.2 — Trust + Bootstrap Foundation

This milestone extends the already-green `0.5.11-dev.1` baseline without recreating it. It establishes the trust boundary and typed orchestration primitives needed by the later Cluster Factory milestone.

## Credential Service boundary

The dedicated Credential Service owns secret material. Local material is Fernet-encrypted at rest with a separately supplied master key. External backends store references only. Management responses are redacted and the Control Plane receives metadata only: identifier, kind/provider/status, fingerprint/version/key-version, safe labels/reference metadata and test status.

Credential lifecycle is admin-token protected and audited. Create, safe metadata/name update, rotate, revoke and delete synchronize with the Control Plane before committing destructive state changes; failures roll back/fail closed. Revocation synchronizes `revoked` metadata before local ciphertext is erased. Normal Control Plane, Smart Router and Hermes/LLM components have no raw-secret retrieval path.

## Server Registry

A server records management/provisioning/BMC IPs, SSH port/user, pinned OpenSSH SHA256 host fingerprint, connection mode, SSH/BMC credential references, architecture, environment/site/rack/zone labels, discovered inventory and preflight state.

Duplicate addresses are rejected across all three address classes. SSH references must be SSH credential kinds and active/configured; BMC references must be an allowed kind and active/configured. Credential reference deletion fails while a server still uses it.

## SSH / host preflight

Preflight checks are fixed product code, not model-generated shell. They cover connectivity/session execution, privilege, OS, CPU/RAM, disks, NIC/routes, DNS, NTP/time, kernel/modules, listening ports, container runtime/Kubernetes detection, filesystem capacity and hostname facts.

A preflight request creates a READ ChangeSet with a deterministic target snapshot containing the pinned host fingerprint and metadata-only credential snapshot. Agent-mode servers can execute via signed agent-task envelopes. Direct-mode servers produce a job for the constrained SSH provider-worker path; arbitrary shell is not exposed.

Preflight results must reference the corresponding preflight provider job, reject secret-shaped facts/evidence, and update only inventory/preflight metadata.

## Provider and bootstrap foundation

Provider descriptors expose a common lifecycle:

`discover -> validate -> plan -> apply -> verify -> upgrade -> rollback -> destroy`

Kubespray, K3s and RKE2 bootstrap foundations create deterministic `bootstrap.apply` HIGH-risk ChangeSets only after a server has PASS preflight status. Jobs start in `WAITING_APPROVAL`; authorization verifies current policy generation, required ChangeSet state and exact plan hash before moving to `READY`.

Provider jobs expose ordered stage events, a Server-Sent Events stream, pause/resume and bounded retry. These are orchestration metadata controls; they do not independently authorize infrastructure mutation.

## Radar and Hubble

Radar is a first-class Kubernetes intelligence provider. Hubble is a first-class live-network intelligence provider. Neither may bypass Hermes governance. Any future write uses Hermes ChangeSets/policy/approval/exact-hash execution controls. Hubble flow data must pass authorization, redaction and aggregation before AI/UI exposure.

Aban is not a runtime dependency. Useful diagnostics may be reimplemented natively in later milestones.

## Container image publication

The canonical path is unchanged:

`source commit/tag -> GitHub Actions -> Docker Buildx multi-arch -> user's Docker Hub`

`.github/workflows/publish-images.yml` builds all Hermes images, including Credential Service, and authenticates with GitHub Secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Provenance/SBOM remain enabled. Local `push.sh` only pushes Git source and optional tags.
