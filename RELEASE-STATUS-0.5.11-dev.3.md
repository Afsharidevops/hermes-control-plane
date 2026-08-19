# Hermes Control Plane 0.5.11-dev.3 — Development Handoff

Status: **implemented in checkpoint workspace; not tagged or published by this handoff**.

Implemented on top of the frozen dev.2 source snapshot:

- typed ClusterBlueprint / ClusterProfile / Cluster / NodeRole resources;
- typed ProvisioningRun / AddonPlan / UpgradePlan / BackupPlan resources;
- deterministic Kubespray, K3s and RKE2 execution-spec contracts with explicit provider-version pins;
- Cilium + Hubble + Radar first-class contracts;
- deterministic lab-minimal/lab-full/production/production-ha/production-hardened operational profiles;
- governed Cilium/Hubble, kube-vip, MetalLB, storage/ingress/TLS/GitOps/observability/cost/backup add-on catalog with explicit version pins;
- Radar summarized intelligence and Hubble aggregated/redacted flow-summary ingestion;
- native day-2 diagnostic catalog with no `kubectl-aban-plugin` runtime dependency;
- dev.3 source/security and config/static gates;
- updated dev.3 apply/validate/push handoff scripts.

The checkpoint ZIP did not include `.git`, so no dev.3 commit/tag was created here and no
claim is made that PR #2 or the remote branch changed. `push.sh` intentionally leaves PR
state untouched and production image publication remains GitHub Actions -> Docker Hub.
