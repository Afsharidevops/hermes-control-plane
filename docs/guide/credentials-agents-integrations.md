# Credentials, Agents, Servers, and Integrations

## Credential Service

The Credential Service owns secret material and lifecycle state. The Control Plane receives only reference metadata required for authorization, planning, and audit. Do not insert raw credential content into Control Plane APIs, Smart Router prompts, Router Gateway requests, ChangeSets, browser forms, or external issue trackers.

### Supported kinds and backends

| Credential kinds | Supported backends |
|---|---|
| `kubeconfig`, `ssh-key`, `ssh-password`, `token`, `registry`, `generic` | `local-encrypted`, `kubernetes-secret`, `external-secrets`, `vault`, `aws-secrets-manager`, `azure-key-vault`, `gcp-secret-manager` |

**Runtime-complete:** Local encrypted storage uses Fernet and requires a valid private `HERMES_CREDENTIAL_MASTER_KEY`. External backend support does not remove the responsibility to configure cloud/Vault policy, rotation, and network trust outside Hermes.

### Lifecycle

1. Create a credential record through Credential Service using a kind, backend, safe reference metadata, and secret material only at the credential boundary.
2. The service encrypts or references it in the selected backend and synchronizes metadata only to the Control Plane.
3. Use test status for a bounded credential/backend check where supported.
4. Rotate/revoke through the Credential Service lifecycle API; then synchronize/update dependent targets.
5. Delete only after dependent target/server/integration references have been removed or re-pointed.

Credential Service exposes `/v1/backends`, `/v1/credentials`, item lifecycle operations (`PATCH`, `rotate`, `test`, `revoke`, `sync`, `DELETE`), and its own audit. Control Plane internal metadata synchronization is service-to-service only; it is not a public secret upload API.

## Kubernetes kubeconfig handling

For Docker deployments, use the CLI importer:

```bash
./hermesctl kubeconfig import <name> <file>
./hermesctl kubeconfig list
./hermesctl kubeconfig remove <credential-id>
```

The importer stores local kubeconfig content with private filesystem permissions and sends only fingerprint/reference metadata to Control Plane. Kubernetes Broker reads the mounted local material read-only under its dedicated credential root. For Helm, provide a reviewed secret or scoped in-cluster identity; do not grant default cluster-admin access.

## Server Registry and SSH preflight

Cluster Factory works against pre-registered existing servers. A server record includes safe inventory/role metadata and a credential reference—not an SSH private key. Before a server may be assigned a node role or provider job:

1. Register the server and select a sealed worker-side SSH profile/credential reference.
2. Run SSH preflight from the permitted service path.
3. Require a **PASS** result, then assign the exact NodeRole.
4. Re-run preflight after host key, network, account, or credential rotation changes.

The Node Agent provider runtime uses fixed provider playbooks and private workspaces. It does not accept arbitrary SSH hosts, shell commands, playbooks, or copied credentials.

## Enrolled agents

Agents are distinct from Node Agent provider workers. The Control Plane supports enrollment tokens, agent records, heartbeats, tasks, task results, and revocation. Task envelopes are signed with `HERMES_AGENT_TASK_HMAC_KEY`.

Recommended sequence:

1. Create a short-lived enrollment token for a named agent.
2. Enroll from the intended controlled host.
3. Verify agent identity, heartbeat freshness, and permitted task scope.
4. Inspect task/result state in **Governance → Agents**.
5. Revoke on decommission, suspected compromise, or ownership change.

Do not treat enrollment as an authorization bypass. A task remains subject to its type, service identity, and ChangeSet/ticket requirements where applicable.

## Integrations and health

Integration records define controlled external relationships and their health probe state. Review endpoint ownership, TLS, token scope, and safe metadata before registration. `HERMES_HEALTH_TIMEOUT_SECONDS` bounds Control Plane health probes. Health status indicates reachability/contract behavior only; it is not proof that a privileged operation is permitted or safe.

Radar intelligence, diagnostics, Hubble, and verification are intentionally sanitized read models. Their results cannot be used to retrieve source credentials, raw packet/flow bodies, unrestricted cluster logs, or host filesystem data.

## Operator checklist

- Use a different credential/reference per environment and executor scope.
- Rotate/revoke through the service that owns the secret, then refresh dependent references.
- Use least privilege: read-only discovery credentials do not become mutation credentials.
- Validate a credential on a disposable/non-production target before changing an execution gate.
- Audit credential metadata actions, not secret values.

See [Cluster Factory](cluster-factory.md), [Kubernetes operations](kubernetes-operations.md), [Infrastructure providers](infrastructure-providers.md), and [Security policy](../../SECURITY.md).
