# Security Policy — Hermes Control Plane 0.5.10

Hermes Control Plane 0.5.10 keeps planning/LLM services separate from privileged infrastructure execution. Mutation execution is disabled by default and must pass the ChangeSet, policy, approval and broker boundaries.

## Stable security boundaries

- Smart Router, Control Plane, Hermes/Telegram and Router Gateway do not receive a Docker socket.
- Raw kubeconfigs, SSH private keys, passwords and provider tokens are not retrievable through normal Control Plane management APIs. The Control Plane stores references/fingerprints/metadata, not raw secret material.
- Credential metadata rejects secret-bearing fields. Rotation replaces the external reference/fingerprint and is audited.
- ChangeSets bind target/credential snapshots and the server-owned policy generation into a canonical SHA-256 plan hash.
- A policy-generation change invalidates active older plans and approvals.
- Kubernetes/Helm mutation requires a live Kubernetes Broker preview and target snapshot match.
- HIGH/CRITICAL requester self-approval is forbidden. CRITICAL requires two distinct approvers.
- Approval records bind exact plan hash, policy generation/identity, expiry and a one-time nonce under an approval HMAC. Required approvals are consumed before the broker call so a network failure cannot replay the grant.
- Execution tickets are short-lived, HMAC-signed, exact-plan-bound and broker replay protected.
- Agent enrollment tokens are one-use and expiry-bound; agent heartbeat nonces are replay protected; identities can be revoked immediately.
- Audit can be exported as NDJSON with a SHA-256 digest and retention pruning is audited.
- SQLite backup/restore performs integrity checks. The supported 0.5.10 HA model is single-active failover; active-active SQLite replicas are unsupported.

## Credential backends

0.5.10 uses a credential-administration boundary that stores only redacted references. A reference can point to locally protected kubeconfig material or an externally managed backend such as Kubernetes Secret/External Secrets or Vault-compatible storage. Secret material must be provisioned/migrated in that backend independently of the Control Plane database.

## Approval and execution keys

Keep these identities/secrets distinct:

- `HERMES_CONTROL_ADMIN_TOKEN`
- `HERMES_BOT_SERVICE_TOKEN`
- `HERMES_APPROVAL_BOT_TOKEN`
- `HERMES_APPROVAL_HMAC_KEY`
- `HERMES_KUBERNETES_BROKER_TOKEN`
- `HERMES_EXECUTION_HMAC_KEY`

Do not reuse the Approval Bot token as the Hermes Bot/admin token, and do not reuse the approval HMAC key as a bearer token.

## Never expose directly

Do not expose the Control Plane admin API, Kubernetes Broker, router management endpoints, Execution Broker, Docker socket, kubeconfig directory, SSH private keys or secret-backend credentials directly to the public Internet.

## Invariants

- no unrestricted AI shell;
- no privileged credential readback to the LLM path;
- plan and preview before mutation;
- approval bound to the exact current plan/policy;
- least-privilege target credentials;
- fail closed on drift, stale policy, hash mismatch, invalid approval integrity or replay;
- deny by default for critical/destructive actions;
- both Control Plane and Kubernetes execution gates default disabled.

The stable runtime acceptance procedure is documented in `docs/STABLE-0.5.10-ACCEPTANCE.md`.
