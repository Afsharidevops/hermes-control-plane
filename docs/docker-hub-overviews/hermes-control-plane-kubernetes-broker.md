# Hermes Kubernetes Broker

The trusted Kubernetes execution and observation boundary for **Hermes Control Plane**. It owns the live Kubernetes preview, target-scope enforcement, exact-ticket validation, and bounded Kubernetes/Helm diagnostics and operations.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-kubernetes-broker:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Reads kubeconfigs only from a private, read-only credentials mount.
- Enforces namespace and resource scope immediately before preview and execution.
- Selects a compatible bundled `kubectl` for Kubernetes 1.33–1.36 targets.
- Includes pinned Helm and Hubble tooling for supported governed operations and network observation.
- Performs live previews, drift checks, exact-ticket validation, and post-operation verification.
- Keeps Kubernetes mutation execution disabled by default.

## Quick start

Deploy it through the complete Hermes Control Plane Compose or Helm chart:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

## Runtime details

- Container port: `8830`
- Health endpoint: `GET /health`
- Kubeconfig mount path: `/credentials/kubeconfigs`
- Read-only root filesystem with a bounded `/tmp` tmpfs in the reference deployment.
- Runs as an unprivileged user.

## Security

Never expose this service publicly or bake kubeconfigs into the image. Enable `HERMES_KUBERNETES_EXECUTION_ENABLED` only after reviewing target policy, credentials, and the ChangeSet approval path.

See SECURITY.md and docs/KUBERNETES-CLIENT-COMPATIBILITY.md in the source repository.
