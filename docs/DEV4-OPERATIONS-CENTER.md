# 0.5.11-dev.4 — Full Operations Center + Next-Deploy Infrastructure

Hermes `0.5.11-dev.4` extends the frozen dev.3 Cluster Factory with a single governed operations substrate for Web, Telegram, AI, fleet, cloud/virtualization, bare-metal, switch/network and air-gap workflows.

## Frozen baseline

Dev.4 must be applied only on `dev/0.5.11` at or above the frozen dev.3 boundary:

- dev.3 implementation: `e51d7f99faa180974cb7a925e12b587d8432fd5b`
- dev.3 final/tag boundary: `8547c44de4f6e8116d70f2690b50a50c895eba34`
- frozen tag: `v0.5.11-dev.3`
- PR #2 remains Draft unless explicitly changed by the user.

No dev.3 commit/tag is amended, moved or republished by the dev.4 handoff scripts.

## Shared Operations Center intent backend

`/v1/operations-center/intents/plan` is the shared planning entry point for the supported Web/UI, Telegram, Hermes Bot/AI and API channels.

Read-only operations produce typed query plans without a ChangeSet. Mutation operations produce deterministic typed plans and then enter the existing Hermes invariant:

`intent -> typed plan -> ChangeSet -> deterministic preview/diff -> risk -> policy -> approval -> exact-hash binding -> constrained signed execution ticket -> provider/broker/agent -> verification -> audit`

The browser Operations Center remains configuration/observability oriented. It does not contain raw infrastructure mutation or approval controls. Web-originated mutations must still be submitted through the trusted bot/service identity and the same backend contract.

## Fleet registry and exact target snapshots

The fleet view derives a centralized registry from persisted Cluster Factory resources and exposes:

- environment and labels;
- provider and state;
- sites/zones derived from registered cluster servers;
- Radar-derived health when available;
- agent/provider connectivity metadata.

Fleet mutation planning resolves selectors to an exact, sorted list of cluster snapshots. The operation job authorization step recomputes every target snapshot and fails closed if any target changed after planning/approval. It also revalidates integrity-protected approval records and the persisted typed-plan hash before issuing a short-lived HMAC-signed execution ticket bound to the exact ChangeSet, operation job, executor, policy generation and typed-plan hash.

## Advanced day-2 typed plans

The dev.4 planner includes deterministic contracts for:

- worker add/remove/replace;
- node cordon/uncordon/drain and maintenance;
- workload restart/scale;
- add-on install/upgrade;
- Helm and GitOps operations;
- Kubernetes and Cilium/Hubble upgrades;
- etcd snapshots and restore;
- certificate rotation;
- cluster decommission;
- infrastructure scaling;
- template cloning;
- disaster recovery.

These are plan/execution-job foundations. They do not add arbitrary shell or unrestricted CLI endpoints.

## Cloud and virtualization provider foundations

First-class typed contracts are present for:

- VMware;
- OpenStack;
- AWS;
- Azure;
- GCP.

Each provider record references a Credential Service credential, explicit API version and explicit provider-worker implementation version. Plans include only credential references/metadata and never raw credential material.

## Bare-metal and network foundations

Typed providers cover:

- Redfish/BMC power, boot, BIOS and firmware desired state;
- constrained IPMI fallback power/boot operations;
- PXE/iPXE-style OS provision/reimage/recovery/decommission planning;
- typed switch/network VLAN, port, bond and attach/detach desired state.

The contracts explicitly reject arbitrary generated shell/CLI as the primary execution surface.

## Air-gap artifact mirroring

Artifact inventory supports:

- OCI images;
- Helm charts;
- packages;
- Git/release artifacts.

Every artifact requires an explicit version and `sha256:` digest. The mirror plan contains source-digest verification and destination-digest verification stages before audit completion.

## Unified verification

`/v1/verifications` persists typed verification results associated with clusters, fleets, servers, providers, artifacts or infrastructure resources. The contract includes the major post-operation checks required by the dev.4 milestone, including hosts, networking, etcd/API/nodes, Cilium/Hubble, DNS, storage, ingress/TLS, GitOps, observability, Radar, Hermes Agent and baseline security.

Secret-shaped evidence is rejected before persistence/audit.

## Security additions

Dev.4 adds negative controls for:

- embedded `user:password@host` credentials in provider/artifact endpoints;
- secret-shaped intent desired state or parameters;
- secret-shaped verification evidence;
- stale policy generation;
- exact ChangeSet hash mismatch;
- persisted typed-plan tampering after planning;
- expired/tampered approval records;
- forged, tampered or wrong-job execution tickets;
- provider/cluster/artifact target drift after approval;
- fleet membership/target snapshot drift after approval.

## Validation status of this source package

The source package can validate deterministic contracts and mocks locally. It must not be described as having completed live VMware/OpenStack/AWS/Azure/GCP, Redfish/IPMI/PXE, switch or artifact-mirror execution unless those paths are separately exercised against suitable disposable infrastructure.

`validate.sh` runs all frozen regression suites plus the dev.4 security/static gates and dev.4 Control Plane tests. Docker Compose and Helm are validated when their local tools are available.

## Tagging rule

`push.sh --tag` refuses to create/push `v0.5.11-dev.4` unless the caller supplies the exact branch-CI-green HEAD SHA using `--branch-ci-green-sha` or `HERMES_BRANCH_CI_GREEN_SHA`.

Production container builds/pushes remain GitHub Actions responsibilities. PR #2 is not changed by the handoff scripts.
