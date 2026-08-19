# Hermes Control Plane — v0.5.11 Compressed Completion Plan

**Target:** `0.5.11`  
**Development branch:** `dev/0.5.11`  
**Stable release already complete:** `v0.5.10` — do not redo  
**Clean dev.1 baseline:** `1764cad667717ec78156af8f9f3fcc30eb84c1f5` — do not redo  
**Draft PR:** `#2` — keep Draft until explicitly requested otherwise

## Security invariant

Every infrastructure mutation remains:

`intent -> typed plan -> ChangeSet -> deterministic preview -> risk -> policy -> approval -> exact-hash binding -> constrained broker/agent/provider -> verification -> audit`

Raw infrastructure credentials never enter Smart Router, Hermes/LLM prompts, or normal Control Plane responses. Radar/Hubble are first-class intelligence providers but never governance bypasses. `kubectl-aban-plugin` is not a runtime dependency; only useful ideas/checks may be reimplemented natively.

## 0.5.11-dev.1 — shared substrate

**Status: COMPLETE / DO NOT REDO**

Baseline commit: `1764cad667717ec78156af8f9f3fcc30eb84c1f5`.

Includes shared application/adapter substrate, signed agent-task envelopes, replay protection, policy-generation binding, and existing v0.5.10 trust controls.

## 0.5.11-dev.2 — trust + bootstrap foundation

**Status: implementation complete in this handoff; validate/apply/push on `dev/0.5.11`.**

### Credential boundary

- dedicated Credential Service process/trust boundary;
- Fernet encrypted-at-rest local backend;
- external references for Kubernetes/External Secrets/Vault/AWS/Azure/GCP secret managers;
- Kubernetes, SSH, token, registry and generic credential classes;
- create, rotate, revoke, delete, safe test and metadata-sync lifecycle;
- redacted management responses and raw-secret-shaped metadata rejection;
- metadata-only Control Plane synchronization;
- reference-delete safety and audited lifecycle;
- fail-closed create/rotate/revoke/delete synchronization behavior.

### Server Registry

- environment/site/rack/zone/labels;
- management/provisioning/BMC addresses with duplicate-IP protection;
- SSH user/port and pinned OpenSSH SHA256 host fingerprint;
- SSH and optional BMC credential references;
- credential kind/status validation;
- discovered inventory and preflight status/facts.

### SSH / host preflight

- deterministic, product-coded read-only preflight contract;
- SSH/session connectivity, sudo/root, OS, CPU/RAM, disks, NIC/routes, DNS/NTP, kernel/modules, ports, runtime/Kubernetes detection, filesystem and hostname checks;
- pinned-host-fingerprint requirement;
- READ ChangeSet and exact target snapshot binding;
- agent execution path plus direct-SSH provider-worker foundation;
- preflight result metadata bound to its provider job; secret-shaped evidence rejected.

### Provider/bootstrap foundation

- generic `discover/validate/plan/apply/verify/upgrade/rollback/destroy` provider lifecycle;
- Kubespray, K3s and RKE2 bootstrap provider descriptors;
- deterministic HIGH-risk bootstrap ChangeSets;
- PASS-preflight prerequisite;
- provider jobs blocked on required ChangeSet approval;
- exact plan-hash/policy-generation authorization checks;
- ordered stage/log events, SSE stream, pause/resume and bounded retry foundation;
- Radar and Hubble first-class provider contracts with no governance bypass;
- Hubble authorization/redaction/aggregation required before AI/UI exposure.

### Image publication

Canonical production image path remains:

`git push/tag -> GitHub Actions -> multi-arch Buildx -> user's Docker Hub`

GitHub Actions uses `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` GitHub Secrets and builds every Hermes image including Credential Service. Local `push.sh` pushes source/commits/tags only and never publishes production images.

## 0.5.11-dev.3 — cluster factory + core infrastructure

Next milestone only after dev.2 is applied and CI-validated:

- ClusterBlueprint/ClusterProfile/Cluster lifecycle;
- production Kubespray, lab/edge K3s, hardened RKE2;
- Cilium + Hubble;
- Radar Kubernetes intelligence;
- storage, ingress, TLS, GitOps, observability, cost, backup and core day-2;
- useful diagnostics inspired by Aban implemented natively where valuable.

## 0.5.11-dev.4 — operations center + next-deploy infrastructure

- Web UI, Telegram and AI Operations;
- multi-cluster and advanced day-2;
- empty-disk bare metal, PXE/iPXE, Redfish/BMC, IPMI, BIOS and switch configuration;
- VMware, OpenStack, AWS, Azure, GCP;
- full air-gap artifact mirroring and advanced recovery/decommission.

## Release path

`dev.1 complete -> dev.2 trust/bootstrap -> dev.3 cluster factory/core infra -> dev.4 operations/next-deploy infra -> 0.5.11-rc.1 hardening -> 0.5.11`
