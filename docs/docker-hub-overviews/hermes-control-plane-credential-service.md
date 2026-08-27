# Hermes Credential Service

A dedicated credential-administration boundary for **Hermes Control Plane**. It keeps credential references, protected storage metadata, rotation state, and narrow synchronization separate from the main control-plane API.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-credential-service:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Maintains credential metadata and protected credential-service storage.
- Lets the Control Plane synchronize metadata-only references.
- Supports rotation, revocation, safe testing, auditing, and failure-closed behavior.
- Prevents raw infrastructure credentials from entering the normal Control Plane, Smart Router, or LLM request path.

## Quick start

Deploy this image only with the complete Hermes Control Plane Compose or Helm configuration:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

## Runtime details

- Container port: `8082`
- Reference Compose host binding: `127.0.0.1:8789`
- Persistent path: `/data`
- Requires distinct admin, service, and master-key configuration supplied by the deployment secrets.
- Runs as an unprivileged user.

## Security

Do not run this image with placeholder keys or publish it directly to the Internet. Use the deployment secret mechanism for `HERMES_CREDENTIAL_MASTER_KEY` and service tokens; never pass secret values in image tags, Dockerfile arguments, public documentation, or logs.

See SECURITY.md and docs/DEV2-TRUST-BOOTSTRAP.md in the source repository.
