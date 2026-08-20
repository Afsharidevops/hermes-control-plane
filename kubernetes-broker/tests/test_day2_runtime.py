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
