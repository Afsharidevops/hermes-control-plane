# Security Policy

Hermes Control Plane `0.5.10-rc.1` is the current stabilization candidate on top of the beta.1 Kubernetes/Helm vertical slice. It remains a development release and is not approved for unattended production mutation.

## Implemented boundaries

- Smart Router and Hermes do not receive raw kubeconfigs.
- On Docker/VM, kubeconfig material is stored locally outside the Control Plane database and mounted read-only only into Kubernetes Broker.
- The Control Plane stores credential references and fingerprints, not kubeconfig contents.
- ChangeSet schema v2 snapshots target metadata and credential fingerprint into the exact plan hash.
- Live Kubernetes/Helm preview must come from Kubernetes Broker before execution.
- Target or credential metadata drift invalidates the old plan.
- HIGH/CRITICAL approvals bind to the exact SHA-256 plan hash; requesters cannot self-approve.
- Execution tickets are short-lived, HMAC-signed, exact-plan-bound, and rejected on in-process replay.
- Kubernetes and Control Plane execution are disabled by default and require separate opt-in switches.
- Kubernetes Broker has no Docker socket, no Smart Router secrets, and no router-management authority.
- Manifest apply denies Secret, RBAC, admission webhook, CSR and CRD objects in this beta slice.
- Helm preview uses server-side dry-run and requests secret hiding.

## Beta credential limitation

Docker/VM kubeconfig files are protected by local filesystem permissions and fingerprint verification, but are not yet encrypted at rest by a dedicated credential service. The final product should add a separate encrypted credential service or external secret backend, rotation/revocation, and direct write-only UI flows.

## Never expose directly

Do not expose the Control Plane admin API, Kubernetes Broker, router gateway management API, execution broker, Docker socket, kubeconfig directory, SSH private keys, or provider management endpoints directly to the public Internet.

## Remaining production blockers

- dedicated credential service/external secret backend
- Telegram approval integration and separate approval authority
- agent enrollment/identity/revocation
- persistent replay protection and signed agent protocol
- policy-generation invalidation
- Git, Docker/Compose/Swarm and SSH adapters
- two-person critical approval
- backup/restore and HA testing
- network policy and production RBAC profiles
- audit retention/export and threat-model review

## Invariants

- no unrestricted AI shell
- no Docker socket in LLM-facing services
- no raw kubeconfig/private-key/token retrieval through normal management APIs
- plan and preview before mutation
- approval bound to exact ChangeSet
- least-privilege target credentials
- fail closed on drift or hash mismatch
- deny-by-default for critical/destructive actions
