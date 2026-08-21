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

**Status: COMPLETE / FROZEN at `a71b03a54ed2f619d3605c0c08d46de35ad5911c`; do not redo.**

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

**Status: COMPLETE / FROZEN / PUBLISHED at `8547c44de4f6e8116d70f2690b50a50c895eba34`, tag `v0.5.11-dev.3`; do not redo or rewrite.**

Implementation commit: `e51d7f99faa180974cb7a925e12b587d8432fd5b`. The frozen/published boundary above supersedes historical pre-publication status text retained in the exact dev.3 source snapshot.

- persisted ClusterBlueprint/ClusterProfile/Cluster/NodeRole lifecycle resources;
- persisted ProvisioningRun/AddonPlan/UpgradePlan/BackupPlan resources;
- deterministic production Kubespray, lab/edge K3s and hardened RKE2 execution specs with explicit provider-version pins;
- Cilium + Hubble networking/visibility contracts;
- Radar Kubernetes intelligence with Hermes-native operational UI/contracts;
- deterministic lab-minimal/lab-full/production/production-ha/production-hardened operational profiles;
- governed Cilium/Hubble, kube-vip, MetalLB, storage, ingress, TLS, GitOps, observability, cost and backup add-on catalog with explicit version pins;
- backup-before-upgrade and restore-verification day-2 foundations;
- native diagnostics inspired by useful Aban ideas, with no kubectl-aban-plugin runtime dependency.

## 0.5.11-dev.4 — operations center + next-deploy infrastructure

**Status: source implementation prepared in this checkpoint workspace; NOT TAGGED OR PUBLISHED. Apply as new commits on top of frozen dev.3, run the full local validation suite, require green branch CI on the intended exact SHA, then use the guarded tag path.**

Implemented source foundations include:

- shared Web UI, Telegram, Hermes/AI and API intent planning through one governed operations backend;
- persisted multi-cluster/fleet views, selectors and exact fleet/target snapshot binding;
- typed advanced day-2 planning for worker/node, workload, add-on, Helm/GitOps, Kubernetes/Cilium upgrade, backup/restore, certificate, maintenance, decommission, clone and DR operations;
- typed provider foundations for VMware vSphere, VMware Workstation Pro, Proxmox VE, OpenStack, AWS, Azure and GCP with explicit provider/API pins and constrained operation contracts; VMware Workstation is treated as a local/lab clone-based provider and Proxmox as a first-class virtualization target;
- typed empty-disk bare-metal planning for Redfish/BMC, IPMI and PXE/iPXE plus network/switch contracts, without arbitrary generated shell execution;
- digest-pinned OCI/Helm/package/Git-release air-gap mirror items and governed mirror plans;
- persisted operation plans/jobs, short-lived HMAC-signed exact-plan execution tickets, one-time approval consumption at execution start, and unified typed verification results;
- exact ChangeSet plan-hash, current-policy-generation and current target/fleet snapshot authorization checks before operation-job authorization;
- negative security tests for raw-secret-shaped parameters, embedded URL credentials and target/fleet drift.

Live VMware vSphere/Workstation, Proxmox, cloud, BMC, switch or other provider execution is not claimed by this source checkpoint unless the corresponding trusted runtime exists and is backed by separate disposable-target evidence. Production images remain CI-owned.

## Release path

`dev.1 complete -> dev.2 trust/bootstrap -> dev.3 cluster factory/core infra -> dev.4 operations/next-deploy infra -> 0.5.11-rc.1 hardening -> 0.5.11`
