# 0.5.10-alpha.2 — Management + Safety Core

This alpha combines the earlier Integration Registry and ChangeSet milestones so the project can move faster without enabling unsafe infrastructure mutation.

## Included

- persistent Environment Registry
- persistent Integration Registry with environment, credential reference, scope, connection mode and health metadata
- persistent Target Registry
- credential-reference CRUD (metadata only; no secret material)
- HTTP/HTTPS connection health probe foundation
- starter Operations Center page at `/ui`
- canonical ChangeSet plan serialization
- SHA-256 plan hashes
- automatic risk classification (`READ`, `LOW`, `HIGH`, `CRITICAL`)
- ChangeSet preview storage and state transitions
- approval request/approve/reject/cancel flow
- approval bound to exact plan hash
- HIGH/CRITICAL self-approval protection
- ChangeSet expiry
- append-oriented audit events
- alpha.1 SQLite migration/backfill
- CI tests for the safety core

## Intentionally not included

- raw credential storage
- privileged execution
- kubectl/Helm mutation
- Docker/Swarm mutation
- SSH command execution
- GitHub/GitLab write operations
- Telegram approval bot binding

Those arrive behind the alpha.2 safety contract in `0.5.10-beta.1`.

## Quick API check

```bash
source .env
curl -s http://127.0.0.1:8800/v1/system | python3 -m json.tool
```

Open the starter management UI locally:

```text
http://127.0.0.1:8800/ui
```

Paste `HERMES_CONTROL_ADMIN_TOKEN` only into the local UI token field. It is held in the browser tab and is not embedded in the page.
