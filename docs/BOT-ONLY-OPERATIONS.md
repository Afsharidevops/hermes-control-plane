# Bot-only Kubernetes and Helm operations

Hermes Control Plane intentionally separates configuration/observability from infrastructure mutation.

## Authority model

- **Web UI / admin token**: environments, integration metadata, target metadata, kubeconfig references, discovery, ChangeSet inspection and audit. It cannot create, preview, approve, roll back, or execute Kubernetes/Helm mutation ChangeSets.
- **Hermes Bot service identity**: may create/preview mutation ChangeSets, request approval, create rollback plans, and execute an already-approved exact hash.
- **Approval Bot service identity**: may approve/reject HIGH/CRITICAL mutation ChangeSets. The Hermes Bot token cannot approve.
- **Kubernetes Broker**: holds read-only access to kubeconfig material and receives only signed execution tickets from the Control Plane.

The main Hermes plugin additionally fails closed unless the active session is an interactive Telegram session from an allow-listed numeric user.

## Configure

Generate missing service identities:

```bash
./hermesctl init
```

Configure the main Hermes Telegram bot token using hidden terminal input:

```bash
./hermesctl bot telegram
```

Allow your Telegram numeric user ID:

```bash
./hermesctl bot allow 123456789
./hermesctl bot status
```

Start Hermes:

```bash
./hermesctl up
```

`hermesctl up` enables the bind-mounted `control-plane-chatops` plugin before
gateway startup. Verify discovery with:

```bash
./hermesctl bot check
```

Do not paste service tokens or kubeconfigs into Telegram.

## Execution gate

Execution remains opt-in:

```bash
./hermesctl execution status
./hermesctl execution enable
./hermesctl execution disable
```

The enable/disable commands recreate the Control Plane and Kubernetes Broker and wait for health before returning. This avoids sending API calls while Uvicorn is still restarting.

## Hermes Bot tools

The `control-plane-chatops` plugin exposes:

- `hcp_list_targets`
- `hcp_get_changeset`
- `hcp_plan_kubernetes`
- `hcp_plan_helm`
- `hcp_request_approval`
- `hcp_execute_changeset`
- `hcp_plan_rollback`

The plugin contains only the Control Plane bot-service token. It has no kubeconfig, broker signing key, or approval token.

## Approval

HIGH/CRITICAL changes cannot be approved with either the UI admin token or Hermes Bot token. Approval requires the separate Approval Bot service identity and the exact current `plan_hash`.

Telegram Approval Bot transport wiring remains a beta.1 integration task; the service-identity and API boundary are already enforced by the Control Plane.
