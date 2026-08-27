# Governance and ChangeSets

**Runtime-complete:** The ChangeSet, policy, approval, ticket, and audit boundaries govern implemented mutation paths. A typed plan or UI surface is not an executor claim; consult [Feature status](feature-status.md) for **Integration/local evidence** and **Contract-only/deferred** capabilities.

Hermes treats a change as a governed, verifiable transaction—not a direct executor command.

```text
intent -> typed deterministic plan -> ChangeSet -> preview/current-state binding
       -> risk and policy -> approval(s) -> one-time signed ticket
       -> constrained executor -> active verification -> audit
```

## Authorities

| Actor | May do | May not do |
|---|---|---|
| Browser admin / Control Plane administrator | Configure non-secret metadata, inspect plans/evidence/audit, perform administrative read/configuration paths | Perform bot-only Kubernetes/Helm mutation or submit approval decisions. |
| Hermes Bot | Request permitted Kubernetes/Helm planning/execution through its service identity | Approve its own or any ChangeSet. |
| Approval Bot | Submit cryptographically bound approval/rejection decisions | Plan or execute as the Hermes Bot. |
| Broker / Node Agent | Execute only ticket-authorized, bounded typed plans in its scope | Accept arbitrary commands, broader targets, expired/replayed tickets. |

## Change lifecycle

1. **Intent and plan** — an operation request is canonicalized into a schema-limited deterministic plan. Plan inputs exclude raw secrets and arbitrary command fields.
2. **Current state and preview** — Hermes gathers allowed state and/or runs a live dry-run/diff. It binds the preview, target/fleet/provider/artifact details, and plan hash.
3. **Risk and policy** — policy classifies risk and evaluates current policy generation. A denied or failed preview cannot proceed.
4. **ChangeSet creation** — the durable record holds canonical plan identity, risk, preconditions, preview, approvals, lifecycle history, and later evidence.
5. **Approval** — required actors approve the exact plan hash under the current policy generation, before expiry.
6. **Ticket issuance** — Hermes creates a short-lived HMAC-signed, single-use ticket bound to one ChangeSet, plan hash, executor, and preconditions.
7. **Execution** — the intended broker/worker validates ticket signature, freshness, replay state, target scope, plan hash, and configured gate before bounded work.
8. **Verification and audit** — Hermes records structured executor status and active verification; records should include no raw credentials or unbounded command output.

## Risk and approvals

| Risk | Typical behavior |
|---|---|
| READ | Observation-only flow; no external mutation ticket. |
| HIGH | Requires approval. Requester self-approval is forbidden. |
| CRITICAL | Requires two approvals from distinct approvers. Requester self-approval is forbidden. |

Examples of CRITICAL behavior include Kubernetes restore and supported destructive Proxmox operations such as `vm.delete` or `snapshot.restore`. The exact risk is determined by server-side operation classification; do not infer it from a UI label.

## Invalidations and fail-closed behavior

A pending approval or ticket becomes unusable when any material condition changes, including:

- Canonical plan hash or executor identity changes.
- Preview/current-state, target, fleet, provider, artifact manifest, or credential reference state drifts.
- Policy generation changes.
- Approval or ticket expires.
- Ticket has already been consumed, including consumption before executor dispatch to prevent retry replay after an ambiguous network failure.
- An execution gate, capability allowlist, scoped target, or trusted worker identity is unavailable.

Create a fresh plan/preview and request new approval after invalidation. Never edit a persisted plan to force it through.

## States to interpret

| Record | States / implications |
|---|---|
| ChangeSet | Previewed/awaiting approval/approved/executed are forward states. Rejected, cancelled, expired, stale-policy, policy-denied, preview-failed, or failed require review/replanning. |
| Operation/provider job | RUNNING, PAUSED, SUCCEEDED, and FAILED states include typed stage/event history. A successful dispatch alone is not success. |
| Verification | PASS, WARN, FAIL, or SKIP. SKIP is evidence unavailable, not a health assertion. |

## Safe operator workflow

1. Establish read-only discovery and a target scope.
2. Choose a supported typed action in the relevant guide.
3. Generate and inspect plan, preview, risk, preconditions, target scope, artifact pins, and expected verification.
4. Request approval through the authorized separate identity.
5. Do not alter target/configuration/gates while approval is pending.
6. Follow execution and verification to a terminal state.
7. Review audit and remediation instructions. Revoke/disable gates after testing where appropriate.

## Policy, audit, and retention

Policy generation is server owned. Its purpose is to invalidate stale decisions when governance changes, not to grant a shortcut. Audit records provide traceability for administration, planning, approval, execution, agent/integration state, and credential-reference lifecycle. Audit export and retention administration must preserve the rule that secret material, raw kubeconfigs, provider credential contents, and unrestricted command output are excluded.

See [Kubernetes operations](kubernetes-operations.md), [Infrastructure providers](infrastructure-providers.md), and [API reference](api-reference.md).
