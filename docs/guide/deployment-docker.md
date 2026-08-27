# Docker Compose Deployment

**Runtime-complete:** Docker Compose provides the supported local control-plane deployment path. Optional provider integrations retain their individual **Integration/local evidence** or **Contract-only/deferred** classifications in [Feature status](feature-status.md).

## Services, profiles, and ownership

| Service | Profile / port | Purpose and boundary |
|---|---|---|
| `nine-router` | `nine-router` profile | Optional upstream router. |
| `omniroute` | `omniroute` profile | Optional upstream router. |
| `router-gateway` | loopback `8790` -> container `8090` | Selects upstream router and translates only neutral aliases. |
| `smart-router-init` | init service | Initializes Smart Router state before router operation. |
| `smart-router` | loopback `8787` -> `8080` | OpenAI-compatible routing, panel, policy, RAG, metrics. |
| `kubernetes-broker` | loopback `8830` | Kubeconfig, kubectl/Helm, Hubble, diagnostics and bounded execution boundary. |
| `control-plane` | loopback `8800` | UI/API, registries, ChangeSets, policy, audit. |
| `credential-service` | internal/private service | Encrypted or external credential-reference lifecycle. |
| `hermes` | `hermes` profile | Optional Telegram/Hermes gateway. |
| `node-agent` | worker port `8810` | Provider, infrastructure, Proxmox, and optional host-observer boundary. |

`smart-router-init` is an initialization unit, not an interactive endpoint. The exact active profiles are selected by `hermesctl` from router settings.

## Networks and volumes

- `app-net` carries application service traffic.
- `router-net` isolates routing service traffic.
- `credential-net` is internal; Credential Service synchronization is not an Internet-facing API.

Named volumes preserve router state, Smart Router state, Control Plane SQLite data, credential state, Hermes data, and provider-worker state. Back up the Control Plane database using `./hermesctl backup`; do not copy a live SQLite file manually.

## Hardening posture

Most published ports bind to `127.0.0.1` by default. The Credential Service is on the internal network. Kubeconfig and worker credential mounts are read-only. Node Agent uses a read-only root filesystem with bounded writable working storage. Router-facing services drop Linux capabilities and use no-new-privileges. Do not add Docker socket mounts to the Control Plane, Smart Router, Router Gateway, or Hermes service.

## Lifecycle

```bash
./hermesctl up          # start selected profiles and bootstrap routing
./hermesctl up --pull   # pull before start
./hermesctl wait        # wait for health
./hermesctl status      # report service status
./hermesctl down        # stop services
```

Use `docker compose config` to render configuration before changing deployment variables. Read [Configuration](configuration.md) before enabling profiles or gates.
