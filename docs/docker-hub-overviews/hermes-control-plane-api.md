# Hermes Control Plane API

The primary API and Operations Center for **Hermes Control Plane**. It provides governed infrastructure and Kubernetes operations through immutable ChangeSets, deterministic previews, policy evaluation, approvals, short-lived exact-plan execution tickets, verification, and audit records.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-api:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Hosts the Hermes Operations Center UI and REST API.
- Stores control-plane state in a persistent SQLite volume by default.
- Coordinates the Credential Service, Kubernetes Broker, and Node Agent; it does not directly hold raw infrastructure credentials.
- Supports governed Kubernetes, artifact-mirror, Redfish/IPMI/PXE, Proxmox observation, and narrow Proxmox QEMU runtime workflows.
- Keeps mutation execution disabled by default.

## Quick start

Use this image as part of the complete Hermes Control Plane deployment, not as an isolated public service:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

Open the Operations Center at `http://127.0.0.1:8800/ui`.

## Runtime details

- Container port: `8800`
- Health endpoint: `GET /health`
- Persistent path: `/data`
- Runs as an unprivileged user.
- The reference Compose deployment binds the API to loopback by default.

## Security

The API accepts credential references and metadata, never raw kubeconfig/provider secret material through normal management APIs. Protected mutations require an exact approved ChangeSet and valid execution ticket. Keep it on a trusted private network; do not expose the administrative API to the public Internet.

See the repository README and SECURITY.md for deployment and security guidance.
