# Security Policy

Hermes Control Plane is currently an alpha architecture foundation.

## Never expose

Do not expose the Control Plane, Smart Router, router gateway management API, execution broker, Docker socket, kubeconfig files, SSH private keys, or provider management interfaces directly to the public Internet without an authenticated reverse proxy and a reviewed policy.

## Alpha limitation

The complete credential service, immutable ChangeSet engine, approval binding, Kubernetes broker and remote agent security protocol described in `plan.md` are not yet implemented. Do not treat `0.5.10-alpha.1` as a production authorization boundary for infrastructure changes.

## Design invariants

- no Docker socket in LLM-facing services
- no raw kubeconfig/private-key/token retrieval through normal APIs
- plan before mutation
- approval bound to exact ChangeSet
- least-privilege target credentials
- append-oriented audit events
- deny-by-default for critical/destructive actions
