# Changelog

- Isolated all Docker Hub image repositories under the `hermes-control-plane-*` prefix to prevent collisions with `hermes-linux-stack`.

## 0.5.10-alpha.1 — 2026-08-14

- Created the Hermes Control Plane monorepo foundation.
- Migrated Hermes Smart Router v0.5.9 source as the Operations Center/routing base.
- Migrated Hermes Execution Broker v0.1.3 source as the isolated execution base.
- Added runtime-selectable 9router/OmniRoute gateway with neutral Hermes model aliases.
- Added streaming OpenAI-compatible proxy support in the router gateway.
- Added Control Plane API foundation with integration metadata CRUD and immutable non-executable ChangeSet plan records.
- Added Node Agent foundation with execution disabled by default.
- Added unified Docker Compose deployment and `hermesctl` bootstrap/router commands.
- Added Kubernetes Helm chart foundation with router selection, generated/preservable bootstrap Secrets, optional persistence and optional Ingress.
- Added multi-platform Docker Hub build/push scripts and GitHub Actions workflows.
- Added `plan.md` defining the v0.5.10 DevOps control-plane roadmap and security invariants.
