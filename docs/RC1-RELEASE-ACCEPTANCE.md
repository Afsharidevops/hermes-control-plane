# v0.5.10-rc.1 release acceptance

## Validated development baseline

The RC.1 development branch completed the following live acceptance before release mechanics:

- 9router managed-key reuse and duplicate-key cleanup idempotence
- 9router automatic `ai`/tier combo reconciliation with operator tier preservation
- OmniRoute parity and router switch-back
- real Smart Router -> selected-router chat completions
- Hermes runtime Smart Router authentication and ChatOps plugin wiring
- Telegram read-only target listing
- kubeconfig mode `0600` and Kubernetes Broker read-only credential mount
- live Kubernetes discovery with 44 namespaces and 138 workloads on the sandbox checkpoint
- target-aware dynamic kubectl selection (sandbox API server 1.33 selected bundled kubectl 1.33)
- 35/35 intensive non-destructive security/authorization/preview checks
- 32/32 controlled execution, approval-expiry, target/credential/live-state drift, ticket-replay, ConfigMap rollback, Helm install/uninstall rollback, audit, and cleanup checks
- full `down -> up` persistence after the R4 client-selection change
- execution gates returned to disabled after controlled testing

## Remaining release-mechanics gate

Before the RC tag, complete all of the following against the final release-hardening commit:

1. GitHub `validate` workflow passes on the development branch.
2. Publish temporary multi-architecture candidate images for all six project-owned images.
3. Inspect each candidate manifest and confirm both `linux/amd64` and `linux/arm64`.
4. Fresh isolated Docker/VM install using candidate images passes initialization, health, router completion, bot runtime check, and disabled execution defaults.
5. Published `v0.5.10-beta.1` -> candidate upgrade passes with database backup and registry persistence.
6. Candidate upgrade preserves/reconciles router credentials and routing state.
7. Merge the validated branch to `main` without additional source changes.
8. GitHub validation passes on the merged `main` commit.
9. Create and push annotated tag `v0.5.10-rc.1`.
10. Confirm tag publishing creates versioned multi-architecture images and does **not** move `latest`.

Any failure in these items is release-blocking. Fix it on the development branch, rerun the affected release-mechanics checks, and only then merge/tag.
