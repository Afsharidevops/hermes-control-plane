# Hermes Control Plane 0.5.11-dev.1 status

## Base

- Stable base: `v0.5.10`
- Stable commit: `e73dd7c69767e709fb944a6356e47776a4464d92`
- Development target: `0.5.11`
- Current development slice: `0.5.11-dev.1`

## Delivered in dev.1

- New compressed completion roadmap in `PLAN-0.5.11.md`.
- Application registry schema and CRUD API.
- Application lifecycle audit events.
- Shared adapter capability contract at `GET /v1/capabilities`.
- Capability metadata includes read/write mode, default risk, reversibility, credential class, connection modes, approval behavior and target restrictions.
- Agent task table and admin inspection API.
- Agent task issuance bound to an existing current-policy ChangeSet.
- Agent capability enforcement before task issuance.
- Agent-mode target enforcement before task issuance.
- Signed task envelopes using a dedicated `HERMES_AGENT_TASK_HMAC_KEY`.
- Task envelope binds agent, target, ChangeSet ID/hash, capability, policy generation, plan, expiry and nonce.
- One-time agent task claim with replay protection.
- Claim-time ChangeSet state/hash/policy revalidation.
- Audited task completion with secret-like evidence keys rejected.
- Docker Compose and Helm wiring for the separate agent-task signing key.
- `hermesctl init` generation support for the new signing key.
- Dedicated `scripts/0.5.11-dev1-source-gate.sh`.

## Validation

Latest source gate result:

- Control Plane: 31 passed.
- Kubernetes Broker: 18 passed.
- Execution Broker: 2 passed.
- Smart Router: 117 passed.
- Python compile checks: PASS.
- 0.5.11-dev.1 source security gate: PASS.
- Overall `0.5.11-dev.1-source-gate: PASS`.

## Next milestone

`0.5.11-dev.2` — credential-service completion:

- encrypted self-hosted backend;
- External Secrets/Kubernetes Secret reference backend;
- Vault-compatible backend;
- provider interface for cloud secret managers;
- constrained create/rotate/delete/test operations;
- Kubernetes and SSH credential lifecycle through the boundary.

Do not merge unfinished credential storage into the LLM-facing Control Plane process. The credential service must remain a separate trust boundary.
