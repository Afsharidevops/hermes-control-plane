import importlib
import os

import pytest

os.environ.setdefault("HERMES_KUBERNETES_BROKER_TOKEN", "test-token")
os.environ.setdefault("HERMES_EXECUTION_HMAC_KEY", "x" * 64)
main = importlib.import_module("hermes_kubernetes_broker.main")


def _typed(operation: str, parameters: dict, runtime_preview: dict | None = None) -> dict:
    typed = {
        "schema_version": 4,
        "kind": "NodeOperationPlan",
        "operation": operation,
        "targets": [
            {"kind": "kubernetes-cluster", "id": "clu_test", "snapshot_hash": "1" * 64},
            {"kind": "kubernetes", "id": "tgt_test", "status": "configured", "connection_mode": "agent", "scope": {"namespace_allowlist": ["apps"], "cluster_read": True}, "snapshot_hash": "2" * 64},
        ],
        "parameters": parameters,
        "runtime_preview": runtime_preview,
        "stages": ["preflight", "verify"],
        "verification_required": True,
        "mutation_gate": "changeset-exact-hash-approval",
        "arbitrary_shell": False,
    }
    typed["plan_hash"] = main.sha256_hex(typed)
    return typed


def _changeset(typed: dict) -> dict:
    return {
        "schema_version": 2,
        "operation": typed["operation"] + ".apply",
        "adapter": "kubernetes",
        "target_id": "clu_test",
        "parameters": {"resource_type": typed["kind"], "typed_plan": typed},
        "policy_generation": 1,
        "target_snapshot": {"kind": "kubernetes-cluster", "id": "clu_test", "status": "configured"},
    }


def test_day2_cordon_uses_fixed_command_and_active_verification(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})
    states = iter([
        {"metadata": {"uid": "node-uid"}, "spec": {"unschedulable": False}},
        {"metadata": {"uid": "node-uid"}, "spec": {"unschedulable": True}},
    ])

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return {"returncode": 0, "output": "ok", "duration": 0.01}

    def fake_json(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return next(states)

    monkeypatch.setattr(main, "_run", fake_run)
    monkeypatch.setattr(main, "_run_json", fake_json)
    before = {"node": "worker-1", "uid": "node-uid", "unschedulable": False}
    runtime_preview = {"preconditions": {"node_state_hash": main.sha256_hex(before)}}
    result = main._execute_day2(_changeset(_typed("cluster.node.cordon", {"native_target_id": "tgt_test", "node": "worker-1"}, runtime_preview)), {"executor": "kubernetes-broker"})
    assert ["kubectl", "cordon", "worker-1"] in calls
    assert result["verification"]["checks"][0]["id"] == "node-unschedulable"
    assert result["verification"]["checks"][0]["status"] == "PASS"
    assert result["verification"]["evidence"]["arbitrary_shell"] is False


def test_day2_scale_enforces_namespace_and_verifies_replicas(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})
    states = iter([
        {"metadata": {"uid": "dep-uid", "generation": 4}, "spec": {"replicas": 2, "template": {"metadata": {"annotations": {}}}}, "status": {"readyReplicas": 2}},
        {"metadata": {"uid": "dep-uid", "generation": 5}, "spec": {"replicas": 3, "template": {"metadata": {"annotations": {}}}}, "status": {"readyReplicas": 3}},
    ])

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return {"returncode": 0, "output": "ok", "duration": 0.01}

    def fake_json(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return next(states)

    monkeypatch.setattr(main, "_run", fake_run)
    monkeypatch.setattr(main, "_run_json", fake_json)
    before = {"kind": "deployment", "name": "api", "namespace": "apps", "uid": "dep-uid", "generation": 4, "replicas": 2, "restart_annotation": None}
    runtime_preview = {"preconditions": {"workload_state_hash": main.sha256_hex(before)}}
    plan = _changeset(_typed("cluster.workload.scale", {"native_target_id": "tgt_test", "kind": "deployment", "name": "api", "namespace": "apps", "replicas": 3}, runtime_preview))
    result = main._execute_day2(plan, {"executor": "kubernetes-broker"})
    assert ["kubectl", "scale", "deployment/api", "--replicas=3", "-n", "apps"] in calls
    checks = {item["id"]: item for item in result["verification"]["checks"]}
    assert checks["replicas-converged"]["status"] == "PASS"
    assert checks["rollout-complete"]["status"] == "PASS"


def test_day2_rejects_tampered_typed_plan_and_unpinned_helm():
    typed = _typed("cluster.node.cordon", {"native_target_id": "tgt_test", "node": "worker-1"})
    typed["parameters"]["node"] = "worker-2"
    with pytest.raises(Exception) as exc:
        main._day2_typed_plan(_changeset(typed))
    assert "hash" in str(exc.value).lower()

    with pytest.raises(Exception) as exc:
        main._day2_helm({"release": "cilium", "chart": "cilium/cilium", "namespace": "kube-system", "version": "latest"})
    assert "pinned" in str(exc.value).lower()


def _typed_with_namespaces(operation: str, parameters: dict, runtime_preview: dict, namespaces: list[str]) -> dict:
    typed = _typed(operation, parameters, runtime_preview)
    typed["targets"][1]["scope"]["namespace_allowlist"] = namespaces
    unhashed = dict(typed)
    unhashed.pop("plan_hash", None)
    typed["plan_hash"] = main.sha256_hex(unhashed)
    return typed


def test_gitops_sync_uses_fixed_argocd_patch_and_exact_revision_verification(monkeypatch):
    calls = []
    revision = "a" * 40
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})
    states = iter([
        {"metadata": {"uid": "app-uid", "resourceVersion": "7"}, "spec": {"source": {"targetRevision": revision}}, "status": {"sync": {"revision": "b" * 40, "status": "OutOfSync"}, "health": {"status": "Healthy"}}},
        {"metadata": {"uid": "app-uid", "resourceVersion": "8"}, "spec": {"source": {"targetRevision": revision}}, "status": {"sync": {"revision": revision, "status": "Synced"}, "health": {"status": "Healthy"}}},
    ])

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return {"returncode": 0, "output": "application.argoproj.io/api", "duration": 0.01}

    def fake_json(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return next(states)

    monkeypatch.setattr(main, "_run", fake_run)
    monkeypatch.setattr(main, "_run_json", fake_json)
    before = {"application": "api", "namespace": "apps", "uid": "app-uid", "resource_version": "7", "desired_revision": revision, "observed_revision": "b" * 40, "sync_status": "OutOfSync", "health_status": "Healthy"}
    preview = {"preconditions": {"gitops_state_hash": main.sha256_hex(before)}}
    typed = _typed_with_namespaces("cluster.gitops.sync", {"native_target_id": "tgt_test", "application": "api", "namespace": "apps", "revision": revision, "prune": True}, preview, ["apps"])
    result = main._execute_day2(_changeset(typed), {"executor": "kubernetes-broker"})
    patch_calls = [args for args in calls if args[:3] == ["kubectl", "patch", "applications.argoproj.io"]]
    assert len(patch_calls) == 1
    assert '"revision":"' + revision + '"' in patch_calls[0][patch_calls[0].index("-p") + 1]
    assert ["kubectl", "wait", "applications.argoproj.io", "api", "-n", "apps", "--for=jsonpath={.status.sync.status}=Synced", "--timeout=5m"] in calls
    checks = {item["id"]: item for item in result["verification"]["checks"]}
    assert checks["gitops-synced"]["status"] == "PASS"
    assert checks["gitops-healthy"]["status"] == "PASS"


def test_cilium_upgrade_is_pinned_and_actively_verifies_cilium_and_hubble(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})
    before = {"exists": True, "release": "cilium", "namespace": "kube-system", "revision": 4, "status": {"info": {"status": "deployed"}}}

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        if args[:2] == ["helm", "list"]:
            return {"returncode": 0, "output": '[{"revision":"4"}]', "duration": 0.01}
        if args[:2] == ["helm", "status"]:
            return {"returncode": 0, "output": '{"info":{"status":"deployed"}}', "duration": 0.01}
        return {"returncode": 0, "output": "ok", "duration": 0.01}

    json_states = iter([
        {"info": {"status": "deployed"}},
        {"items": [{"metadata": {"name": "cilium-abc"}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}}]},
    ])

    def fake_json(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return next(json_states)

    monkeypatch.setattr(main, "_run", fake_run)
    monkeypatch.setattr(main, "_run_json", fake_json)
    monkeypatch.setattr(main.hubble_provider, "collect", lambda **kwargs: {"summary": {"event_count": 3, "verdict_counts": {"FORWARDED": 3}}, "raw_flow_bodies_returned": False})
    preview = {"preconditions": {"release_snapshot_hash": main._helm_snapshot_hash(before)}}
    params = {"native_target_id": "tgt_test", "release": "cilium", "chart": "cilium/cilium", "namespace": "kube-system", "version": "1.19.4"}
    typed = _typed_with_namespaces("cluster.cilium.upgrade", params, preview, ["kube-system"])
    result = main._execute_day2(_changeset(typed), {"executor": "kubernetes-broker"})
    assert ["helm", "upgrade", "cilium", "cilium/cilium", "--install", "--namespace", "kube-system", "--create-namespace", "--version", "1.19.4", "--wait", "--timeout", "5m"] in calls
    checks = {item["id"]: item for item in result["verification"]["checks"]}
    assert checks["helm-release-ready"]["status"] == "PASS"
    assert checks["cilium-ready"]["status"] == "PASS"
    assert checks["hubble-ready"]["status"] == "PASS"


def test_gitops_and_cilium_reject_unpinned_or_wrong_targets():
    with pytest.raises(Exception) as exc:
        main._day2_argocd({"application": "api", "namespace": "apps", "revision": "HEAD"})
    assert "commit digest" in str(exc.value).lower()
    with pytest.raises(Exception) as exc:
        main._day2_preview({"kind": "kubernetes", "status": "configured", "connection_mode": "agent", "scope": {"namespace_allowlist": ["kube-system"], "cluster_read": True}}, "cluster.cilium.upgrade", {"release": "not-cilium", "chart": "cilium/cilium", "namespace": "kube-system", "version": "1.19.4"})
    assert "cilium upgrade" in str(exc.value).lower()


def test_velero_backup_uses_fixed_cr_manifest_and_active_completion_verification(monkeypatch):
    calls = []
    manifests = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})
    get_count = 0

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        nonlocal get_count
        calls.append(args)
        if args[:3] == ["kubectl", "get", "backups.velero.io"]:
            get_count += 1
            if get_count < 3:
                return {"returncode": 0, "output": "", "duration": 0.01}
            return {
                "returncode": 0,
                "output": '{"metadata":{"uid":"backup-uid","resourceVersion":"9"},"spec":{"includedNamespaces":["apps"],"snapshotVolumes":true,"ttl":"72h0m0s"},"status":{"phase":"Completed","warnings":0,"errors":0,"volumeSnapshotsAttempted":2,"volumeSnapshotsCompleted":2}}',
                "duration": 0.01,
            }
        if args[:4] == ["kubectl", "create", "-f", "-"]:
            manifests.append(stdin)
            return {"returncode": 0, "output": "backup.velero.io/hermes-test", "duration": 0.01}
        if args[:3] == ["kubectl", "wait", "backups.velero.io"]:
            return {"returncode": 0, "output": "backup.velero.io/hermes-test condition met", "duration": 0.01}
        return {"returncode": 0, "output": "ok", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    before = {"exists": False, "backup_name": "hermes-test", "namespace": "velero"}
    preview = {"preconditions": {"velero_backup_state_hash": main.sha256_hex(before)}}
    params = {
        "native_target_id": "tgt_test",
        "backup_name": "hermes-test",
        "namespace": "velero",
        "included_namespaces": ["apps"],
        "snapshot_volumes": True,
        "ttl_hours": 72,
    }
    typed = _typed_with_namespaces("cluster.backup.velero", params, preview, ["velero", "apps"])
    result = main._execute_day2(_changeset(typed), {"executor": "kubernetes-broker"})
    assert len(manifests) == 1
    manifest = manifests[0]
    assert '"apiVersion":"velero.io/v1"' in manifest
    assert '"kind":"Backup"' in manifest
    assert '"name":"hermes-test"' in manifest
    assert '"includedNamespaces":["apps"]' in manifest
    assert '"snapshotVolumes":true' in manifest
    assert '"ttl":"72h0m0s"' in manifest
    assert '"hooks"' not in manifest
    assert "credential" not in manifest.lower()
    assert ["kubectl", "wait", "backups.velero.io", "hermes-test", "-n", "velero", "--for=jsonpath={.status.phase}=Completed", "--timeout=10m"] in calls
    checks = {item["id"]: item for item in result["verification"]["checks"]}
    assert checks["velero-backup-completed"]["status"] == "PASS"
    assert checks["velero-backup-completed"]["evidence"]["volume_snapshots_completed"] == 2


def test_velero_backup_scope_rejects_all_namespaces_without_cluster_read():
    snapshot = {"scope": {"namespace_allowlist": ["velero", "apps"], "cluster_read": False}}
    with pytest.raises(Exception) as exc:
        main._enforce_velero_scope(snapshot, "velero", ["*"], [])
    assert "cluster_read" in str(exc.value)


def test_velero_existing_backup_must_match_approved_spec_and_not_be_failed():
    matching = {
        "exists": True,
        "backup_name": "hermes-test",
        "namespace": "velero",
        "included_namespaces": ["apps"],
        "excluded_namespaces": [],
        "snapshot_volumes": True,
        "ttl": "72h0m0s",
        "phase": "Completed",
    }
    main._assert_velero_reusable(matching, "hermes-test", ["apps"], [], True, 72)

    mismatched = dict(matching, ttl="24h0m0s")
    with pytest.raises(Exception) as exc:
        main._assert_velero_reusable(mismatched, "hermes-test", ["apps"], [], True, 72)
    assert "different approved specification" in str(exc.value)

    failed = dict(matching, phase="PartiallyFailed")
    with pytest.raises(Exception) as exc:
        main._assert_velero_reusable(failed, "hermes-test", ["apps"], [], True, 72)
    assert "terminal phase" in str(exc.value)


def test_velero_restore_uses_fixed_non_destructive_cr_and_active_completion_verification(monkeypatch):
    calls = []
    manifests = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})

    source = {
        "exists": True,
        "backup_name": "hermes-test",
        "namespace": "velero",
        "uid": "backup-uid",
        "resource_version": "9",
        "deletion_timestamp": None,
        "included_namespaces": ["apps"],
        "excluded_namespaces": [],
        "snapshot_volumes": True,
        "ttl": "72h0m0s",
        "phase": "Completed",
        "warnings": 0,
        "errors": 0,
        "volume_snapshots_attempted": 2,
        "volume_snapshots_completed": 2,
    }
    before = {"exists": False, "restore_name": "hermes-restore", "namespace": "velero"}
    restore_gets = 0

    def backup_json():
        return '{"metadata":{"uid":"backup-uid","resourceVersion":"9"},"spec":{"includedNamespaces":["apps"],"snapshotVolumes":true,"ttl":"72h0m0s"},"status":{"phase":"Completed","warnings":0,"errors":0,"volumeSnapshotsAttempted":2,"volumeSnapshotsCompleted":2}}'

    def restore_json():
        return '{"metadata":{"uid":"restore-uid","resourceVersion":"4"},"spec":{"backupName":"hermes-test","includedNamespaces":["apps"],"restorePVs":false,"includeClusterResources":false,"preserveNodePorts":false,"existingResourcePolicy":"none"},"status":{"phase":"Completed","warnings":0,"errors":0,"validationErrors":[],"restoreItemOperationsAttempted":3,"restoreItemOperationsCompleted":3,"restoreItemOperationsFailed":0}}'

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        nonlocal restore_gets
        calls.append(args)
        if args[:3] == ["kubectl", "get", "backups.velero.io"]:
            return {"returncode": 0, "output": backup_json(), "duration": 0.01}
        if args[:3] == ["kubectl", "get", "restores.velero.io"]:
            restore_gets += 1
            return {"returncode": 0, "output": "" if restore_gets < 3 else restore_json(), "duration": 0.01}
        if args[:4] == ["kubectl", "create", "-f", "-"]:
            manifests.append(stdin)
            return {"returncode": 0, "output": "restore.velero.io/hermes-restore", "duration": 0.01}
        if args[:3] == ["kubectl", "wait", "restores.velero.io"]:
            return {"returncode": 0, "output": "restore.velero.io/hermes-restore condition met", "duration": 0.01}
        return {"returncode": 0, "output": "ok", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    preview = {
        "preconditions": {
            "velero_restore_source_hash": main.sha256_hex(source),
            "velero_restore_state_hash": main.sha256_hex(before),
        }
    }
    params = {
        "native_target_id": "tgt_test",
        "restore_name": "hermes-restore",
        "backup_name": "hermes-test",
        "namespace": "velero",
        "included_namespaces": ["apps"],
        "restore_pvs": False,
    }
    typed = _typed_with_namespaces("cluster.restore", params, preview, ["velero", "apps"])
    result = main._execute_day2(_changeset(typed), {"executor": "kubernetes-broker"})

    assert len(manifests) == 1
    manifest = manifests[0]
    assert '"apiVersion":"velero.io/v1"' in manifest
    assert '"kind":"Restore"' in manifest
    assert '"name":"hermes-restore"' in manifest
    assert '"backupName":"hermes-test"' in manifest
    assert '"includedNamespaces":["apps"]' in manifest
    assert '"restorePVs":false' in manifest
    assert '"includeClusterResources":false' in manifest
    assert '"existingResourcePolicy":"none"' in manifest
    assert '"preserveNodePorts":false' in manifest
    for forbidden in ('"hooks"', '"resourceModifier"', '"namespaceMapping"', '"scheduleName"'):
        assert forbidden not in manifest
    assert "credential" not in manifest.lower()
    assert ["kubectl", "wait", "restores.velero.io", "hermes-restore", "-n", "velero", "--for=jsonpath={.status.phase}=Completed", "--timeout=30m"] in calls
    checks = {item["id"]: item for item in result["verification"]["checks"]}
    assert checks["velero-restore-source-bound"]["status"] == "PASS"
    assert checks["velero-restore-completed"]["status"] == "PASS"
    assert checks["velero-restore-completed"]["evidence"]["item_operations_failed"] == 0
    assert result["verification"]["evidence"]["arbitrary_shell"] is False
    assert result["verification"]["evidence"]["raw_credentials_returned"] is False


def test_velero_restore_requires_completed_source_explicit_scope_and_cluster_permission_for_pvs():
    source = {
        "exists": True,
        "backup_name": "hermes-test",
        "namespace": "velero",
        "included_namespaces": ["apps"],
        "excluded_namespaces": [],
        "phase": "PartiallyFailed",
        "errors": 1,
    }
    with pytest.raises(Exception) as exc:
        main._assert_velero_backup_restore_source(source, "hermes-test", ["apps"])
    assert "completed with zero errors" in str(exc.value).lower()

    with pytest.raises(Exception) as exc:
        main._day2_velero_restore({"restore_name": "hermes-restore", "backup_name": "hermes-test", "included_namespaces": ["*"]})
    assert "explicit" in str(exc.value).lower()

    snapshot = {"scope": {"namespace_allowlist": ["velero", "apps"], "cluster_read": True, "allow_cluster_scoped": False}}
    with pytest.raises(Exception) as exc:
        main._enforce_velero_restore_scope(snapshot, "velero", ["apps"], True)
    assert "allow_cluster_scoped" in str(exc.value)


def test_velero_restore_existing_object_must_match_exact_approved_non_destructive_spec():
    matching = {
        "exists": True,
        "restore_name": "hermes-restore",
        "namespace": "velero",
        "backup_name": "hermes-test",
        "included_namespaces": ["apps"],
        "restore_pvs": False,
        "include_cluster_resources": False,
        "preserve_node_ports": False,
        "existing_resource_policy": "none",
        "phase": "Completed",
    }
    main._assert_velero_restore_reusable(matching, "hermes-restore", "hermes-test", ["apps"], False)

    with pytest.raises(Exception) as exc:
        main._assert_velero_restore_reusable(dict(matching, existing_resource_policy="update"), "hermes-restore", "hermes-test", ["apps"], False)
    assert "different approved specification" in str(exc.value)

    with pytest.raises(Exception) as exc:
        main._assert_velero_restore_reusable(dict(matching, phase="PartiallyFailed"), "hermes-restore", "hermes-test", ["apps"], False)
    assert "partial-failure" in str(exc.value)


def test_velero_schedule_updates_fixed_cr_with_exact_state_binding_and_active_verification(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, refresh=False: {"binding_hash": "x"})

    before_raw = {
        "metadata": {"uid": "schedule-uid", "resourceVersion": "7"},
        "spec": {
            "schedule": "0 2 * * *",
            "template": {"includedNamespaces": ["apps"], "snapshotVolumes": True, "ttl": "72h0m0s"},
        },
        "status": {"phase": "Enabled", "validationErrors": []},
    }
    after_raw = {
        "metadata": {"uid": "schedule-uid", "resourceVersion": "8"},
        "spec": {
            "schedule": "30 3 * * *",
            "template": {"includedNamespaces": ["apps"], "snapshotVolumes": True, "ttl": "168h0m0s"},
        },
        "status": {"phase": "Enabled", "validationErrors": [], "lastBackup": "2026-08-20T18:00:00Z"},
    }
    get_states = iter([before_raw, before_raw, after_raw])

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append((args, stdin))
        if args[:3] == ["kubectl", "get", "schedules.velero.io"]:
            return {"returncode": 0, "output": __import__("json").dumps(next(get_states)), "duration": 0.01}
        return {"returncode": 0, "output": "schedule.velero.io/hermes-daily", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    before = {
        "exists": True,
        "schedule_name": "hermes-daily",
        "namespace": "velero",
        "uid": "schedule-uid",
        "resource_version": "7",
        "deletion_timestamp": None,
        "schedule": "0 2 * * *",
        "included_namespaces": ["apps"],
        "excluded_namespaces": [],
        "snapshot_volumes": True,
        "ttl": "72h0m0s",
        "phase": "Enabled",
        "validation_error_count": 0,
        "last_backup_present": False,
        "unsupported_spec_fields": [],
        "unsupported_template_fields": [],
    }
    preview = {"preconditions": {"velero_schedule_state_hash": main.sha256_hex(before)}}
    params = {
        "native_target_id": "tgt_test",
        "schedule_name": "hermes-daily",
        "namespace": "velero",
        "schedule": "30 3 * * *",
        "included_namespaces": ["apps"],
        "snapshot_volumes": True,
        "ttl_hours": 168,
    }
    typed = _typed_with_namespaces("cluster.backup.schedule", params, preview, ["velero", "apps"])
    result = main._execute_day2(_changeset(typed), {"executor": "kubernetes-broker"})

    patch_calls = [entry for entry in calls if entry[0][:3] == ["kubectl", "patch", "schedules.velero.io"]]
    assert len(patch_calls) == 1
    patch = patch_calls[0][0][patch_calls[0][0].index("-p") + 1]
    assert '"schedule":"30 3 * * *"' in patch
    assert '"ttl":"168h0m0s"' in patch
    assert "hooks" not in patch
    assert "storageLocation" not in patch
    assert result["result"]["action"] == "updated"
    check = {item["id"]: item for item in result["verification"]["checks"]}["velero-schedule-ready"]
    assert check["status"] == "PASS"
    assert check["evidence"]["last_backup_present"] is True
    assert result["verification"]["evidence"]["arbitrary_shell"] is False


def test_velero_schedule_rejects_frequent_cron_and_existing_unbounded_fields(monkeypatch):
    with pytest.raises(Exception) as exc:
        main._day2_velero_schedule({
            "schedule_name": "too-often",
            "schedule": "*/5 * * * *",
            "included_namespaces": ["apps"],
        })
    assert "no more frequently than hourly" in str(exc.value)

    monkeypatch.setattr(main, "_run", lambda *args, **kwargs: {
        "returncode": 0,
        "output": '{"metadata":{"uid":"x","resourceVersion":"1"},"spec":{"schedule":"0 2 * * *","template":{"includedNamespaces":["apps"],"snapshotVolumes":true,"ttl":"72h0m0s","hooks":{"resources":[]}}},"status":{"phase":"Enabled","validationErrors":[]}}',
        "duration": 0.01,
    })
    state = main._velero_schedule_state({"scope": {}}, "hermes-daily", "velero")
    assert state["unsupported_template_fields"] == ["hooks"]
    with pytest.raises(Exception) as exc:
        main._assert_velero_schedule_manageable(state, "hermes-daily")
    assert "outside the bounded Hermes schedule contract" in str(exc.value)
