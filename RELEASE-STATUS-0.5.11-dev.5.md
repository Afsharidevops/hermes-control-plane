# Hermes Control Plane 0.5.11-dev.5 release status

Status: **IN PROGRESS — NOT TAGGED / NOT PUBLISHED**

Frozen parent boundary:

- commit: `d4eb9b7ab2564301c09b8c0d36a2e9d53b843273`
- tag: `v0.5.11-dev.4`
- branch: `dev/0.5.11`

Do not amend, reset, squash, force-push, move or recreate the frozen dev.4 tag.

## Completed in the first dev.5 slice

- real read-only Radar HTTP MCP client
- MCP initialize/session handling
- fixed read-only tool allowlist
- executable `AUTO`, `RADAR`, `NATIVE` modes
- same-environment Radar/native Kubernetes target isolation
- AUTO fallback through the existing Kubernetes Broker
- strict RADAR fail-closed behavior
- defense-in-depth Secret/env/token redaction
- Hermes-native live intelligence controls
- dev.5 source/security/static gates and release guards anchored to frozen dev.4

## Still release-blocking for dev.5 scope closure

- Hubble Relay live-network collector/stream path
- executable Hermes-native diagnostics
- operator UI scope closure
- day-2/add-on executor and active verification closure
- Cluster Factory runtime/repeatability closure
- provider/bare-metal/network executors or explicit user-approved deferral
- air-gap mirror synchronization/integrity runtime
- active unified verification engine

`v0.5.11-dev.5` must not be created until the full dev.5 closure scope is complete,
local validation passes, and branch CI succeeds on the exact intended tag SHA.

- Dev.5 Hubble runtime slice: trusted Kubernetes Broker collector, pinned Hubble CLI, namespace authorization, typed redaction/aggregation, bounded history, SSE, and Hermes-native Network Live batch UI.
