# Hermes Node Agent

The trusted provider-worker image for **Hermes Control Plane**. It executes only exact-ticket-bound, allowlisted provider and infrastructure operations after the Control Plane has completed planning, preview, policy, approval, and drift checks.

## Image tags and platforms

```bash
docker pull afsharidevops/hermes-control-plane-node-agent:0.5.11
```

- `0.5.11` is the stable release tag.
- `latest` is published from stable, non-prerelease version tags.
- `edge` follows the `main` branch; use it only for evaluation.
- `sha-…` tags identify individual source commits.
- Published for `linux/amd64` and `linux/arm64`, with OCI provenance and an SBOM.

## What this image does

- Hosts the internal provider-worker API used by the Control Plane.
- Supports existing-host provider workflows, Redfish/IPMI/PXE operations, controlled artifact consumption, and read-only Proxmox capacity and VM-inventory collectors.
- Includes the disabled-by-default QEMU-only Proxmox runtime for exactly `vm.create`, `vm.clone`, `vm.update`, `vm.delete`, `vm.power`, `network.attach`, `snapshot.create`, and `snapshot.restore`.
- Uses fixed HTTPS/API request builders, bounded polling, ticket replay protection, drift rejection, and active readback verification.
- Does not accept arbitrary shell commands, arbitrary CLI arguments, raw provider payloads, or credential readback.

## Quick start

Run this image only through the complete Hermes Control Plane Compose or Helm deployment:

```bash
git clone https://github.com/Afsharidevops/hermes-control-plane.git
cd hermes-control-plane
cp .env.example .env
./hermesctl init
VERSION=0.5.11 ./hermesctl up
```

## Runtime details

- Container port: `8810`
- Health endpoint: `GET /health`
- Private credential mount paths: `/credentials/ssh` and `/credentials/infrastructure`
- Persistent work path: `/var/lib/hermes-provider`
- Read-only root filesystem with a bounded `/tmp` tmpfs in the reference deployment.
- Provider and infrastructure execution flags default to `false`.

## Security

Keep this service on the internal Hermes network and bind it to loopback only if a host mapping is required. Provision credentials as read-only worker mounts; never send them through the Control Plane, UI, audit evidence, or model path. The Proxmox runtime remains disabled until both infrastructure execution and its dedicated Proxmox flag are explicitly enabled with narrow capability allowlists.

See SECURITY.md and docs/PROXMOX-VM-RUNTIME-VALIDATION.md in the source repository.
