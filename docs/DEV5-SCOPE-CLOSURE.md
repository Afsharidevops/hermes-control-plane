# 0.5.11-dev.5 — Scope Closure + Runtime Integration

`0.5.11-dev.5` is a forward-only scope-closure milestone on top of frozen
`v0.5.11-dev.4` (`d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`). It does not rewrite dev.4.

## Slice 1: Radar read runtime

This slice replaces the Radar snapshot-only boundary with a real, bounded,
read-only runtime adapter:

- Radar is a first-class `integration` kind.
- Hermes speaks Radar's HTTP MCP endpoint using JSON-RPC initialization and
  `tools/call`.
- Hermes exposes only an explicit read allowlist: dashboard, issues, resource
  list/detail, search, topology and neighborhood.
- Unknown tools and unknown arguments are rejected before network I/O.
- Radar write tools are not exposed. Any infrastructure mutation remains a
  Hermes ChangeSet/policy/approval/exact-hash execution path.
- `AUTO`, `RADAR`, and `NATIVE` context modes are executable.
- `AUTO` tries a configured same-environment Radar integration first and falls
  back to a same-environment Kubernetes target through the existing trusted
  Kubernetes Broker.
- `RADAR` fails closed when Radar is unavailable or misconfigured.
- `NATIVE` does not contact Radar.
- Provider output is redacted before it can reach Web/AI consumers. Kubernetes
  Secret bodies and direct workload environment values are suppressed.
- Direct Control Plane Radar access intentionally does not resolve credential
  material. Authenticated Radar endpoints require a future credential-service
  to provider-worker path rather than pulling secrets into the Control Plane.

## Native fallback coverage in this slice

Native fallback is deliberately bounded to the existing Kubernetes Broker
inventory and supports dashboard, list, resource detail, search, issues and an
inventory topology. It is not presented as feature-equivalent to Radar.

## Remaining dev.5 closure

This slice does not close the remaining roadmap by itself. Hubble live traffic,
executable native diagnostics, broader operator UI, day-2/provider executors,
air-gap synchronization and active unified verification remain subsequent
`0.5.11-dev.5` work unless explicitly deferred by the user.

## Slice 2 — Cilium/Hubble live-network runtime

This follow-on dev.5 slice moves Hubble from stored-summary contracts to a real bounded runtime path:

`Cilium/Hubble -> Hubble Relay -> pinned Hubble CLI in Kubernetes Broker -> namespace authorization -> typed redaction/aggregation -> Control Plane bounded history/SSE -> Hermes-native Network Live UI`

Security properties:

- Hubble Relay access runs in the trusted Kubernetes Broker so kubeconfig material does not enter UI/AI-facing components.
- The broker executes a fixed `hubble observe --port-forward --output jsonpb` command with bounded `last`/`since_seconds` parameters; no arbitrary CLI arguments or shell execution are accepted.
- Raw L7 URLs, request/response headers, bodies, IP addresses and arbitrary protobuf bodies are discarded before broker output.
- Target namespace allow/deny scope is enforced on sanitized flow events before they leave the broker.
- The Control Plane rejects any batch that does not attest `raw_flow_bodies_returned=false`.
- Per-cluster flow history is deduplicated by sanitized-event fingerprint and bounded to 2,000 events.
- Network Live has a typed batch endpoint plus an authenticated SSE endpoint; browser UI receives only sanitized batches.
- No Hubble mutation path is introduced. Mutations remain normal Hermes ChangeSets.

Evidence in this slice is mock/simulation + local runtime-path testing. It is **not** real-target Cilium/Hubble evidence; live disposable-cluster verification remains required before classifying the complete 0.5.11 Hubble area as real-target verified.
