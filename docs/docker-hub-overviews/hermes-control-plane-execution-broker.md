# Hermes Execution Broker

A narrow security-boundary image for optional, approved execution tools in the Hermes ecosystem. It is **not** a general remote shell, arbitrary command runner, or Docker API proxy.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-execution-broker:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Runs constrained `docker`, `ssh`, `approver`, or `admin` modes.
- Binds operations to sealed structured requests and one-time, signed approval decisions.
- Supports isolated local Docker workflows and sealed SSH-profile execution.
- Separates Docker-socket authority, SSH profiles, approval signing keys, and Telegram approval credentials by mode-specific mounts.
- Provides an optional separate execution-admin boundary without access to the Docker socket, signing key, or SSH private credentials.

## Runtime details

- Container ports: `8750` and `8751`
- Health endpoint: `GET /health`
- Runs as an unprivileged user.
- Includes only the OpenSSH client and OpenSSL needed by its narrowly scoped modes.

## Deployment

Use a reviewed Compose configuration from the Hermes source repository. There are deliberately no safe standalone defaults: missing/misconfigured secrets, authority mounts, user policy, or execution policy cause readiness and operations to fail closed.

## Security

Do not publish broker or approver ports. Never mount the Docker socket outside Docker mode; never mount SSH credentials outside SSH mode; never mount an approval private key or approval-bot token into Hermes or the broker modes. Pin a versioned image tag or immutable digest for production rather than relying on mutable `latest`.

See execution-broker/README.md and SECURITY.md in the source repository for the full authority model.
