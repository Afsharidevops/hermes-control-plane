# Hermes Control Plane 0.5.10 threat model

## Assets

Highest-value assets are infrastructure credentials, approval authority, execution signing keys, target policy/scope, ChangeSet integrity, audit history, and external router/provider credentials.

## Trust boundaries

1. **LLM / Smart Router / Hermes Bot** — may interpret, inspect and request plans; must not possess infrastructure credentials or direct privileged execution authority.
2. **Control Plane** — authoritative registry, policy generation, ChangeSet state, approval validation and audit. It stores credential references/fingerprints, not raw secret values.
3. **Approval authority** — separate Approval Bot identity and approval integrity key. HIGH/CRITICAL requesters cannot self-approve; CRITICAL requires two distinct identities.
4. **Kubernetes Broker / execution brokers / remote agents** — constrained execution boundaries. They receive exact plans/tickets and target-scoped credentials required for their adapter only.
5. **External secret backend / local protected credential material** — owns raw kubeconfig, SSH key/password or provider token material.
6. **Operator runtime** — Docker/VM or Kubernetes/Helm environment, persistence and backup/restore authority.

## Primary threats and controls

| Threat | Stable control |
| --- | --- |
| LLM prompt injection obtains infrastructure credentials | raw credential material is outside LLM-facing services; management API rejects secret-bearing credential metadata |
| Caller selects an old/weaker policy | policy generation is server-owned, stored persistently and bound into canonical plan/hash |
| Approval reused after policy or plan changes | exact plan hash + policy generation/identity + expiry + nonce + HMAC; stale generations invalidate approval state |
| Approval replay after broker timeout/network loss | required approvals are marked consumed before the broker call; retry cannot reuse them |
| CRITICAL change approved by one person/requester | two distinct approvers required; HIGH/CRITICAL requester self-approval denied |
| Telegram callback replay | dedicated approval store resolves a delivered callback token only once and rejects expiry |
| Target/credential changed after preview | target/credential snapshot and toolchain/live-state bindings are checked before execution |
| Forged broker execution | signed short-lived execution ticket, exact plan binding and broker-side replay controls |
| Compromised/duplicated remote agent | one-time enrollment, hashed bearer identity, heartbeat nonce uniqueness and revocation |
| Audit deletion by retention operation hides action | retention is admin-protected and emits its own audit event; export carries an integrity digest |
| Corrupt backup/restore | SQLite online backup plus integrity checks, atomic restore and pre-restore safety backup |
| Docker socket reaches AI path | stable source gate rejects Docker socket mounts in Smart Router, Control Plane, Hermes and Router Gateway |
| Active-active SQLite corruption/split brain | 0.5.10 explicitly supports single-active failover only; active-active shared SQLite is unsupported |

## Residual risks / operational assumptions

- A host/root or Kubernetes cluster administrator can access local/cluster secrets and can replace running images; host/cluster hardening remains an operator responsibility.
- External secret backends must enforce their own authentication, authorization, rotation and availability controls.
- Stable runtime acceptance must be performed on the exact image/source commit before the official tag; source-unit evidence alone is insufficient to prove network, registry, Docker Engine or Kubernetes behavior.
- The broad Docker/Swarm/SSH/Git adapter roadmap is not granted new authority by this release; new privileged adapters must use the same ChangeSet/policy/approval pattern before production enablement.

## Release decision

The source threat controls are enforced by `scripts/stable-source-gate.sh`. Real deployment assumptions are checked using `docs/STABLE-0.5.10-ACCEPTANCE.md` before the official stable tag.
