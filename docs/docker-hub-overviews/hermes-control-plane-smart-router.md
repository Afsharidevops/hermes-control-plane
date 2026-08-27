# Hermes Smart Router

An OpenAI-compatible `/v1` proxy for **Hermes Control Plane**. Smart Router applies deterministic routing policy to choose the configured upstream model route while preserving capability, context, tool, vision, authentication, and output-budget safeguards.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-smart-router:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Exposes OpenAI-compatible model endpoints and a router dashboard.
- Routes `auto` requests through configurable `fast`, `standard`, `strong`, `coding`, and `vision` profiles.
- Supports deterministic heuristic policy and optional offline-trained learned proposals.
- Keeps client API keys at the Smart Router boundary and does not forward them downstream.
- Persists router and cost-ledger state in `/data`.

## Quick start

Use with Router Gateway and the full Hermes Control Plane deployment:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

## Runtime details

- Container port: `8080`
- Reference Compose host binding: `127.0.0.1:8787`
- Endpoints: `/health`, `/ready`, `/metrics`, `/v1/models`, and `/v1/chat/completions`
- Persistent path: `/data`
- Default safe policy: `SMART_ROUTER_MODE=observe` and `SMART_ROUTER_POLICY=heuristic`

## Security

Use a client API key and trusted private networking or HTTPS. Do not publish port `8080` directly to the Internet. Only load learned-policy artifacts from a trusted training process because model serialization may execute code while loading.

See smart-router/README.md in the source repository for profile and policy configuration.
