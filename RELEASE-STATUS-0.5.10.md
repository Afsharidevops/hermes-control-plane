# Hermes Control Plane 0.5.10 stable-candidate status

This source tree is prepared with final `0.5.10` version metadata but is **not an official published stable release until the external acceptance and promotion gates below pass**.

## Completed in this package

- Server-authoritative persisted policy generation.
- Stale policy generation invalidates active ChangeSets and bound approvals fail closed.
- Policy generation is bound into canonical plan/hash.
- Audited policy-generation bump endpoint.
- CRITICAL changes require two distinct exact-hash approvers; requester self-approval remains forbidden.
- Credential references reject raw secret-bearing metadata keys.
- Explicit credential reference rotation with fingerprint audit.
- Audit NDJSON export with SHA-256 response digest and retention operation.
- SQLite online backup + integrity-checked restore tooling with pre-restore safety backup.
- Existing target/credential/toolchain binding and execution default-off behavior retained.
- GitHub Actions dependency maintenance already present in the checkpoint (`checkout@v7`, `setup-python@v7`, Helm setup v5).

## Locally verified gates

Run `./scripts/stable-source-gate.sh` from the repository root. The package records local source/unit results in `release-evidence/`.

## External gates still required before official `v0.5.10`

These require infrastructure or credentials not available in the checkpoint execution environment:

1. Clean supported Linux VM Docker Compose install.
2. Clean supported Kubernetes cluster Helm install.
3. Docker-to-Kubernetes migration acceptance.
4. Upgrade/rollback matrix from `v0.5.10-beta.1` and `v0.5.10-rc.1` using published candidate images.
5. HA/failover and network-loss/failure-injection acceptance on real runtime topology.
6. Multi-architecture candidate image build/publish verification (`linux/amd64`, `linux/arm64`).
7. Merge validated source to `main`, rerun CI, create annotated `v0.5.10` tag, publish official images, and move `latest` only for stable-policy images.

Do not create the official stable tag until all seven external gates pass.
