# Hermes Router Gateway

The upstream routing adapter for **Hermes Control Plane Smart Router**. It provides a controlled OpenAI-compatible bridge to a selected 9router or OmniRoute backend while keeping upstream routing credentials outside client-facing services.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-router-gateway:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Selects the configured router provider: `nine-router` or `omniroute`.
- Proxies OpenAI-compatible model requests to the selected upstream router.
- Exposes an admin-protected gateway boundary and health endpoint.
- Persists gateway state under `/data`.
- Is designed to run behind the Hermes Smart Router, not as a public standalone model gateway.

## Quick start

Run it through the complete Hermes Control Plane deployment:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

## Runtime details

- Container port: `8090`
- Reference Compose host binding: `127.0.0.1:8790`
- Health endpoint: `GET /health`
- Persistent path: `/data`
- Runs as an unprivileged user with dropped Linux capabilities in the reference deployment.

## Security

Keep the Router Gateway on the internal Hermes networks. Configure the provider-specific URLs and access keys through deployment secrets. Do not expose its management endpoint or upstream router credentials publicly.

See the repository README for router selection and bootstrap instructions.
