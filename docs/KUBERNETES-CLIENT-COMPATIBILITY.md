# Kubernetes client compatibility

Hermes Kubernetes Broker supports multiple Kubernetes API server minor versions from one installation by carrying an approved matrix of `kubectl` binaries and selecting a compatible client per target at runtime.

The default RC.1 image contains clients for Kubernetes 1.33, 1.34, 1.35, and 1.36. The exact patch releases are Docker build arguments and can be changed without changing broker code.

Runtime behavior:

1. Resolve the target and its kubeconfig credential boundary.
2. Probe the target API server version.
3. Prefer a `kubectl` with the same minor version.
4. If exact minor is unavailable and selection mode is `exact-preferred`, use an installed client within the Kubernetes-supported one-minor skew, preferring the older client on a tie.
5. Fail closed if no compatible client exists.
6. Record the selected client version, target server version, and binary SHA-256 in the live broker preview.
7. Bind that toolchain fingerprint into the signed execution ticket and re-resolve it before execution. If the target server version or selected client binary changes after preview, execution is rejected and a new preview/approval is required.

Docker/VM configuration:

```text
KUBECTL_V1_33=v1.33.13
KUBECTL_V1_34=v1.34.10
KUBECTL_V1_35=v1.35.6
KUBECTL_V1_36=v1.36.2
KUBECTL_BOOTSTRAP_MINOR=1.34
HERMES_DYNAMIC_KUBECTL_ENABLED=true
HERMES_KUBECTL_SELECTION_MODE=exact-preferred
HERMES_KUBECTL_CACHE_TTL_SECONDS=10
```

Changing a `KUBECTL_V1_*` value changes the binary bundled in the broker image and therefore requires rebuilding that image. No per-target rebuild is needed: once the matrix exists in the image, selection is automatic for every target.

`exact` mode may be used instead of `exact-preferred` when operators want mutation to fail unless an exact-minor client is bundled.

The bootstrap client is used only to query the stable Kubernetes version endpoint so the broker can choose the operational client. Normal discovery, preview, diff, apply, delete, rollout, and verification commands use the selected per-target client.
