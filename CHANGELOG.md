# Changelog

## 0.5.10-alpha.2

- merged Integration Registry and ChangeSet milestones into one Management + Safety Core release
- added persistent Environment, Integration, Target and credential-reference registries
- added alpha.1 SQLite schema migration/backfill
- added starter Operations Center management UI at `/ui`
- added HTTP/HTTPS integration health-test foundation
- added deterministic canonical ChangeSet plan serialization and SHA-256 hashes
- added automatic READ/LOW/HIGH/CRITICAL risk classification
- added ChangeSet preview, expiry and state management
- added approval request/approve/reject/cancel flows bound to the exact plan hash
- blocked HIGH/CRITICAL requester self-approval
- added append-oriented audit events
- added Control Plane API tests to CI
- changed Docker publishing to GitHub Actions: `edge`/`sha-*` on main, semver tags on releases, `latest` only for stable versions
- kept privileged DevOps execution disabled pending beta adapters

## 0.5.10-alpha.1

- created Hermes Control Plane monorepo foundation
- migrated Smart Router and Execution Broker foundations
- added runtime-selectable 9router/OmniRoute gateway
- added Docker Compose and initial Helm deployment
- introduced isolated `hermes-control-plane-*` Docker image naming
