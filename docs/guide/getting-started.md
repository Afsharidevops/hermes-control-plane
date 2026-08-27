# Getting Started

**Runtime-complete:** This path installs and validates the local Hermes control-plane stack. Privileged provider capabilities remain disabled by default and may be **Integration/local evidence** or **Contract-only/deferred**; review [Feature status](feature-status.md) before enabling them.

## Prerequisites

For Docker/VM deployment install Docker Engine with Compose support, Bash, Python 3, and Git. For Kubernetes deployment install Helm and access to a namespace. Start with an isolated development environment; privileged execution is disabled by default and should remain disabled.

## Local Docker quick start

```bash
cp .env.example .env
./hermesctl init
./hermesctl up
./hermesctl wait
./hermesctl status
```

`init` creates missing local service secrets and a Credential Service master key without printing usable secret material. Protect `.env`, mounted secret directories, and `data/` from other local users.

Open the Control Plane at `http://127.0.0.1:8800/ui`. Check the API health at `http://127.0.0.1:8800/health`. The default bind addresses are loopback; do not change them to public addresses without an authenticated reverse proxy, TLS, network controls, and a security review.

## First-run checklist

1. Run `./hermesctl doctor`; resolve Docker, Compose, permissions, and kubeconfig UID/GID findings.
2. Confirm `./hermesctl execution status` reports disabled gates.
3. In the UI, add an environment and non-secret integration/target metadata only.
4. If managing Kubernetes locally, import rather than upload a kubeconfig:
   ```bash
   ./hermesctl kubeconfig import <name> <path-to-kubeconfig>
   ./hermesctl kubeconfig list
   ```
5. Create the Kubernetes target in **Infrastructure**, then run **Discover**. Do not enable execution simply to discover state.
6. Run `./hermesctl router probe` only after the selected upstream router reports ready.

## Choose the upstream router

Nine Router is selected by default. Switch safely:

```bash
./hermesctl router list
./hermesctl router set omniroute
./hermesctl router set nine-router
```

`up` provisions/reuses a managed runtime key for the selected router. It does not require copying a dashboard key into chat. See [ChatOps and routing](chatops-and-routing.md).

## Initial troubleshooting

| Symptom | Check |
|---|---|
| Service does not become healthy | `./hermesctl status`, then `./hermesctl doctor`; verify port conflicts and image availability. |
| Router probe fails | Check selected provider with `router list`, then provider health and `router provision <provider>`. |
| UI cannot make administrative calls | Enter the Control Plane admin token generated in `.env`; it remains only in browser memory. |
| Kubernetes discovery fails | Verify local import, target scope, broker health, file permissions, and Kubernetes version compatibility. |
| A mutation is blocked | This is expected until gates, a valid preview, policy, approval, and an executor-bound ticket all exist. |

Continue with [Docker deployment](deployment-docker.md), [Configuration](configuration.md), and [Governance](governance-and-changes.md).
