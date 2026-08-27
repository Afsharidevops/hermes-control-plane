# Hermes Operator Guide

This guide documents the shipped Hermes Control Plane `0.5.11` product surface: local Docker deployment, Kubernetes deployment, the Control Plane Operator Center, Smart Router Operations Center, ChatOps, governance, provider workers, APIs, and recovery.

## Read this first

Hermes separates planning, credentials, approval, and execution:

```text
UI / Telegram / API intent
        -> Control Plane typed plan and ChangeSet
        -> preview, policy, approval, exact hash
        -> short-lived signed ticket
        -> scoped broker or worker
        -> active verification and audit
```

The UI is for configuration, observation, discovery, diagnostics, plan inspection, and audit. It is not a privileged shell or direct infrastructure-mutation interface. Raw kubeconfigs, SSH keys, passwords, provider credentials, and signing keys must remain outside browser, router, and audit payloads.

## Evidence labels

Every guide page uses these labels:

- **Runtime-complete** — a governed executable path exists. It may still be disabled by default and requires deployment-specific validation.
- **Integration/local evidence** — the bounded implementation and local/mock tests exist; it is not claimed as real-target proof.
- **Contract-only/deferred** — a UI, schema, planner, provider descriptor, or operation contract exists without a trusted runtime path, or is explicitly deferred.

Start at [Feature status](feature-status.md) before enabling any non-read-only capability.

## Choose a path

| Need | Start here |
|---|---|
| Run Hermes locally | [Getting started](getting-started.md) |
| Understand Docker services | [Docker deployment](deployment-docker.md) |
| Install into Kubernetes | [Helm deployment](deployment-kubernetes.md) |
| Configure all environment settings | [Configuration reference](configuration.md) |
| Navigate every UI panel | [Operator Center](operator-center.md) and [ChatOps and routing](chatops-and-routing.md) |
| Manage governed change | [Governance and ChangeSets](governance-and-changes.md) |
| Configure credentials, servers, agents, integrations | [Credentials, agents, integrations](credentials-agents-integrations.md) |
| Operate Kubernetes | [Kubernetes operations](kubernetes-operations.md) |
| Build clusters from existing servers | [Cluster Factory](cluster-factory.md) |
| Mirror offline artifacts | [Artifact mirroring](artifact-mirroring.md) |
| Use BMC, PXE, switch, or Proxmox facilities | [Infrastructure providers](infrastructure-providers.md) |
| Use Hermes CLI | [CLI reference](cli-reference.md) |
| Integrate programmatically | [API reference](api-reference.md) |
| Recover or maintain the platform | [Operations runbook](operations-runbook.md) |

## Safety baseline

1. Bind services to loopback or a private ingress until network controls and TLS are reviewed.
2. Run `./hermesctl init`; do not invent or reuse token values.
3. Keep every execution/collection gate disabled for initial deployment.
4. Configure least-privilege credentials in the Credential Service or worker-mounted backend; never put them in plans or chat.
5. Use a disposable target before enabling a privileged executor.
6. Keep a verified backup before upgrade, restore, or experimental worker activity.

See [Security policy](../../SECURITY.md), [Glossary](glossary.md), and [Feature status](feature-status.md).
