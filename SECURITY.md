# Security Policy

Hermes Control Plane `0.5.10-alpha.2` implements the first management and safety boundary, but it is not yet a production-ready privileged execution system.

## Implemented in alpha.2

- environment, integration and target metadata are separated from execution
- credentials are represented only by opaque credential references; this API intentionally does **not** accept or store raw tokens, kubeconfigs, SSH private keys or passwords
- ChangeSet plans use deterministic canonical JSON and SHA-256 hashes
- the risk engine computes risk from the requested operation; callers cannot lower the risk in the API payload
- HIGH/CRITICAL approvals are bound to the exact plan hash
- HIGH/CRITICAL requesters cannot self-approve
- ChangeSets expire
- management mutations emit append-oriented audit events
- there is no privileged ChangeSet execute endpoint in alpha.2

## Never expose directly

Do not expose the Control Plane, Smart Router, router gateway management API, execution broker, Docker socket, kubeconfig files, SSH private keys, or provider management interfaces directly to the public Internet without reviewed authentication, TLS and network policy.

## Remaining release blockers

Before production infrastructure mutation is enabled, the project still needs the isolated credential service/secret backend, signed agent protocol, target-scoped brokers, adapter-generated dry-run/diff previews, Telegram approval integration, policy generation invalidation, Kubernetes/Docker/Git/SSH enforcement, revocation, and hardening described in `plan.md`.

## Design invariants

- no Docker socket in LLM-facing services
- no raw kubeconfig/private-key/token retrieval through normal APIs
- plan before mutation
- approval bound to exact ChangeSet
- least-privilege target credentials
- append-oriented audit events
- deny-by-default for critical/destructive actions
