# Hermes Control Plane 0.5.10 stable-candidate status

This source tree carries final `0.5.10` metadata and the complete checkpoint hardening implementation. It is a **local stable candidate**, not an official public `v0.5.10` release until the external runtime/promotion gates pass on the exact same commit.

## Implemented in this candidate

- Server-authoritative persistent policy generation bound into the canonical ChangeSet/hash.
- Policy-generation bump invalidates active stale ChangeSets and approvals and emits an audit event.
- CRITICAL changes require two distinct exact-hash approvers; HIGH/CRITICAL requester self-approval remains forbidden.
- Approval records include policy generation/identity, expiry, nonce and HMAC integrity; required approvals are consumed before broker execution, blocking network-loss replay.
- Credential references reject raw secret-bearing metadata and support audited external-reference/fingerprint rotation; Kubernetes and SSH reference lifecycles are tested.
- Agent one-time enrollment, bearer identity, nonce replay rejection, capability advertisement and revocation.
- Audit NDJSON export with SHA-256 digest plus audited retention pruning.
- Online SQLite backup, integrity checking, pre-restore safety backup and operator restore command.
- Single-active failover state preservation test and injected broker network-loss test.
- Docker/Helm Bot + Approval Bot + approval-HMAC identity parity.
- Stable pre-tag image candidate flow, source security gate, API-equivalence and Docker->Kubernetes migration checks.
- GitHub Actions moved to current Node-24-generation majors and the full Smart Router regression suite is included in CI.

## Locally verified

Run:

```bash
./scripts/stable-source-gate.sh
```

The evidence file is `release-evidence/stable-source-gate.txt`.

## External gates before the official tag

These require Docker/Kubernetes/registry/GitHub resources not present in this execution environment:

1. Publish all six `0.5.10-candidate.<sha>` multi-architecture images and run `scripts/acceptance/candidate-images.sh`.
2. Clean Docker Compose install with both 9router and OmniRoute selection.
3. Clean Helm install with persistent Control Plane storage and both router selections.
4. Live Docker->Kubernetes state migration and API-equivalence checks.
5. Upgrade/restore/rollback/re-upgrade from both `v0.5.10-beta.1` and `v0.5.10-rc.1`.
6. Real-topology failover/network-loss smoke in the acceptance environment.
7. Merge the exact validated commit to `main`, rerun CI, create annotated `v0.5.10`, and verify the official images.

See `docs/STABLE-0.5.10-ACCEPTANCE.md`. Do not create the stable tag before these gates pass.
