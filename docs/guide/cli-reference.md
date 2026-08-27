# `hermesctl` Reference

**Runtime-complete / Integration/local evidence / Contract-only/deferred:** Commands expose the available control and contract surface; a command's presence does not enable a privileged runtime or establish real-target evidence. Check [Feature status](feature-status.md) and each command's prerequisites before use.

Run `./hermesctl <command>` from the repository root. Commands read local `.env`; protect that file. Commands that contact a service need it running and return nonzero on failed prerequisite/HTTP/health checks unless explicitly informational.

## Stack lifecycle

| Command | Requirements | Behavior and safety |
|---|---|---|
| `init` | Local checkout, Python/OpenSSL as needed | Creates/updates `.env`, generates missing local secrets/Fernet key, derives local broker UID/GID; never commit output. |
| `up` | Docker/Compose | Builds/starts core, Hermes profile, selected router; bootstraps router key/model/plugin; persists active gateway provider, waits for health. |
| `up --pull` | Docker/Compose, published images | Pulls selected profiles and starts without local build. |
| `down` | Docker/Compose | Stops profiles including both routers/Hermes/node-agent; does not delete named volumes. |
| `status` | Docker/Compose | Shows profile service status plus Control Plane, gateway, and Broker health responses. |
| `wait [seconds]` | curl | Waits for Control Plane and Kubernetes Broker health; default 60 seconds. |
| `doctor` | Python; Docker/Compose if available | Checks prerequisites, Compose rendering, UID/GID fit, router/client key configuration, and Telegram setup without printing tokens. |

## Execution gate

| Command | Behavior |
|---|---|
| `execution status` | Prints global and Kubernetes execution gate state. |
| `execution enable` | Sets `HERMES_EXECUTION_ENABLED=true` and `HERMES_KUBERNETES_EXECUTION_ENABLED=true`, force-recreates Control Plane/Broker, waits for health. |
| `execution disable` | Sets both values false, recreates and waits. |

This controls only two gates. It does not enable provider/infrastructure/Proxmox gates and does not bypass ChangeSets, bot-only identity, approval, ticket, scope, or verification requirements.

## Telegram and ChatOps

| Command | Behavior |
|---|---|
| `bot allow <telegram-id>` | Requires a numeric ID; updates mutation and Telegram allowlists. |
| `bot telegram` | Reads Telegram token via hidden terminal input, validates shape, writes private `.env`, and recreates running Hermes profile to load it. |
| `bot model-sync` | Ensures Hermes is configured for internal Smart Router `auto` model and recreates running Hermes service. |
| `bot status` | Reports configured/missing identities and allowlists, never values. |
| `bot check` | Validates mounted/discovered ChatOps plugin, Smart Router model wiring/auth, and plugin enablement. |

## Router control

| Command | Behavior and protection |
|---|---|
| `router list` | Calls authenticated gateway provider management endpoint and formats health/active provider state. |
| `router probe` | Tests Smart Router client auth, Gateway management auth, required managed key(s), and one real streamed chat completion without printing credentials. |
| `router set nine-router` | Updates selected provider, starts/readies it, provisions/reuses managed credential/combinations, recreates gateway, persists selection, stops prior provider unless both enabled. |
| `router set omniroute` | Same selection lifecycle for OmniRoute. |
| `router provision <nine-router|omniroute>` | Starts named router, provisions/repairs dedicated managed runtime key; 9router also reconciles routing combinations; recreates gateway/Smart Router then probes. |
| `router cleanup-keys [nine-router|omniroute|all]` | Removes only stale duplicates with the reserved managed name after proving the current managed key; ambiguity refuses deletion. |

## Version and release

| Command | Behavior |
|---|---|
| `version` | Prints repository, configured `.env`, and running Control Plane version. |
| `version set <version>` | Validates format and changes local `VERSION` only. |
| `upgrade <version>` | Validates/version-inspects published API and Broker images, creates online backup when Control Plane runs, sets version, pulls/starts; restores old configured value if start fails. |

Do not use this to move/recreate frozen tags. Review image digest, compatibility, backup, and rollback behavior first.

## Backup and restore

| Command | Requirements | Behavior |
|---|---|---|
| `backup` | Docker/Compose, running Control Plane | Runs SQLite online backup inside Control Plane, runs SQLite quick check and project DB validation, copies result to `backups/`. |
| `restore <backup.sqlite3>` | Docker/Compose, valid file | Validates source, makes pre-restore safety backup, stops service, makes atomic replacement after integrity check, restarts and waits; preserves prior DB on restore failure. |

Restore does not reverse external executions. Follow the [Operations runbook](operations-runbook.md) afterward.

## Agent and kubeconfig operations

| Command | Requirements | Behavior and boundary |
|---|---|---|
| `agent enroll <name> [ttl]` | Control Plane available; default TTL 900 seconds | Creates a one-time remote agent enrollment token through the admin API. Treat result as sensitive. |
| `kubeconfig import <name> <file>` | Local readable kubeconfig, Control Plane | SHA-256 fingerprints file, creates metadata reference, copies material locally as mode `0600`, sends only reference/fingerprint metadata. |
| `kubeconfig list` | Control Plane | Lists only kubeconfig credential references. |
| `kubeconfig remove <credential-id>` | Valid `cred_` identifier, Control Plane | Deletes reference then local imported file. Confirm it is unused before removal. |

For configuration details see [Configuration](configuration.md); for service/API interactions see [API reference](api-reference.md).
