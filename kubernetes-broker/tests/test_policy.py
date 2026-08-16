import importlib
import json
import os

import pytest

os.environ.setdefault("HERMES_KUBERNETES_BROKER_TOKEN", "test-token")
os.environ.setdefault("HERMES_EXECUTION_HMAC_KEY", "x" * 64)
main = importlib.import_module("hermes_kubernetes_broker.main")


def test_manifest_denies_secret():
    with pytest.raises(Exception):
        main._manifest_docs("apiVersion: v1\nkind: Secret\nmetadata:\n  name: nope\n")


def test_manifest_allows_deployment():
    docs = main._manifest_docs("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n")
    assert docs[0]["kind"] == "Deployment"


def test_ticket_binds_plan(monkeypatch):
    monkeypatch.setattr(main, "EXECUTION_KEY", "key")
    plan = {"schema_version": 2, "operation": "kubernetes.manifest.apply", "adapter": "kubernetes", "target_id": "t", "parameters": {}, "policy_generation": 1, "target_snapshot": {"kind": "kubernetes"}}
    ticket = {"changeset_id": "c", "plan_hash": main.sha256_hex(plan), "plan": plan, "issued_at": 1, "expires_at": 9999999999}
    import hashlib, hmac
    sig = hmac.new(b"key", main.canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    verified_plan, preconditions = main._verify_ticket(ticket, sig)
    assert verified_plan == plan
    assert preconditions == {}


def test_namespace_allowlist_enforced():
    snapshot = {"kind": "kubernetes", "scope": {"namespace_allowlist": ["apps"]}}
    main._enforce_namespace(snapshot, "apps")
    with pytest.raises(Exception):
        main._enforce_namespace(snapshot, "default")


def test_namespace_resource_requires_cluster_scope():
    snapshot = {"kind": "kubernetes", "scope": {"namespace_allowlist": ["apps"]}}
    docs = main._manifest_docs("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: demo\n")
    with pytest.raises(Exception):
        main._enforce_manifest_scope(snapshot, docs, "apps")


def test_helm_chart_cannot_be_flag():
    with pytest.raises(Exception):
        main._validate_helm_chart("--post-renderer")


def test_manifest_execution_verifies_convergence(monkeypatch):
    calls = []

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append({
            "args": args,
            "stdin": stdin,
            "allowed_codes": allowed_codes,
        })
        return {"returncode": 0, "output": "", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)

    plan = {
        "schema_version": 2,
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": "test",
        "parameters": {
            "namespace": "default",
            "manifest": (
                "apiVersion: v1\n"
                "kind: ConfigMap\n"
                "metadata:\n"
                "  name: execution-test\n"
                "  namespace: default\n"
                "data:\n"
                "  value: test\n"
            ),
        },
        "policy_generation": 1,
        "target_snapshot": {
            "kind": "kubernetes",
            "connection_mode": "agent",
            "scope": {},
        },
    }

    result = main._execute_plan(plan)

    verbs = [call["args"][1] for call in calls]
    assert verbs[:3] == ["get", "apply", "diff"]
    diff_call = next(call for call in calls if call["args"][1] == "diff")
    assert diff_call["allowed_codes"] == {0}
    assert result["before_state"]["resources"][0]["exists"] is False
    assert result["verification"]["converged"] is True
    assert result["verification"]["method"] == "kubectl-diff"



def test_live_state_precondition_rejects_drift(monkeypatch):
    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        if args[1] == "get":
            return {
                "returncode": 0,
                "output": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: changed\n",
                "duration": 0.01,
            }
        return {"returncode": 0, "output": "", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    plan = {
        "schema_version": 2,
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": "test",
        "parameters": {
            "namespace": "default",
            "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\n",
        },
        "policy_generation": 1,
        "target_snapshot": {"kind": "kubernetes", "connection_mode": "agent", "scope": {}},
    }
    with pytest.raises(Exception) as exc:
        main._execute_plan(plan, {"live_state_hash": "0" * 64})
    assert "changed after preview" in str(exc.value)


def test_delete_execution_captures_before_state_and_verifies_absence(monkeypatch):
    calls = []
    gets = iter([
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: one\n",
        "",
    ])

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        if args[1] == "get":
            return {"returncode": 0, "output": next(gets), "duration": 0.01}
        return {"returncode": 0, "output": "configmap/demo\n", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    plan = {
        "schema_version": 2,
        "operation": "kubernetes.manifest.delete",
        "adapter": "kubernetes",
        "target_id": "test",
        "parameters": {
            "namespace": "default",
            "manifest": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\n",
        },
        "policy_generation": 1,
        "target_snapshot": {"kind": "kubernetes", "connection_mode": "agent", "scope": {}},
    }
    result = main._execute_plan(plan)
    assert result["before_state"]["resources"][0]["exists"] is True
    assert result["verification"]["deleted"] is True
    assert any(args[1] == "delete" for args in calls)


def test_rollback_apply_restores_previous_manifest(monkeypatch):
    calls = []

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append((args, stdin))
        if args[1] == "get":
            return {"returncode": 0, "output": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: two\n", "duration": 0.01}
        return {"returncode": 0, "output": "", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    old_manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n  namespace: default\ndata:\n  value: one\n"
    plan = {
        "schema_version": 2,
        "operation": "kubernetes.manifest.rollback",
        "adapter": "kubernetes",
        "target_id": "test",
        "parameters": {
            "namespace": "default",
            "source_changeset_id": "chg_source",
            "actions": [{"action": "apply", "resource": {"apiVersion": "v1", "kind": "ConfigMap", "name": "demo", "namespace": "default"}, "manifest": old_manifest}],
        },
        "policy_generation": 1,
        "target_snapshot": {"kind": "kubernetes", "connection_mode": "agent", "scope": {}},
    }
    result = main._execute_plan(plan)
    assert result["verification"]["rollback_completed"] is True
    assert any(args[1] == "apply" and stdin == old_manifest for args, stdin in calls)


def test_workload_apply_runs_rollout_status(monkeypatch):
    calls = []

    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        calls.append(args)
        return {"returncode": 0, "output": "", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    plan = {
        "schema_version": 2,
        "operation": "kubernetes.manifest.apply",
        "adapter": "kubernetes",
        "target_id": "test",
        "parameters": {
            "namespace": "default",
            "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: default\nspec:\n  selector:\n    matchLabels:\n      app: web\n  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n      containers:\n      - name: web\n        image: nginx\n",
        },
        "policy_generation": 1,
        "target_snapshot": {"kind": "kubernetes", "connection_mode": "agent", "scope": {}},
    }
    result = main._execute_plan(plan)
    assert any(args[1:3] == ["rollout", "status"] for args in calls)
    assert result["verification"]["rollouts"]


def test_helm_precondition_uses_release_revision(monkeypatch):
    def fake_run(args, snapshot, stdin=None, timeout=None, allowed_codes=None):
        if args[1] == "list":
            return {"returncode": 0, "output": '[{"name":"demo","revision":"2"}]', "duration": 0.01}
        if args[1] == "status":
            return {"returncode": 0, "output": '{"info":{"status":"deployed"}}', "duration": 0.01}
        if args[1] == "history":
            return {"returncode": 0, "output": '[]', "duration": 0.01}
        return {"returncode": 0, "output": "", "duration": 0.01}

    monkeypatch.setattr(main, "_run", fake_run)
    snapshot = {"kind": "kubernetes", "connection_mode": "agent", "scope": {}}
    current = main._helm_release_snapshot(snapshot, "demo", "default")
    good = main._helm_snapshot_hash(current)
    assert main._assert_helm_precondition(snapshot, "demo", "default", good)["revision"] == 2
    with pytest.raises(Exception):
        main._assert_helm_precondition(snapshot, "demo", "default", "0" * 64)


def test_run_json_parses_large_stdout_and_ignores_stderr_warning(monkeypatch):
    class Proc:
        returncode = 0
        stdout = json.dumps({"items": [{"metadata": {"name": "demo"}, "padding": "x" * 150_000}]})
        stderr = "Warning: client/server version skew notice\n"

    monkeypatch.setattr(main, "_env", lambda snapshot: {})
    monkeypatch.setattr(main.subprocess, "run", lambda *args, **kwargs: Proc())

    result = main._run_json(["kubectl", "get", "deployments", "-A", "-o", "json"], {"kind": "kubernetes"})

    assert result["items"][0]["metadata"]["name"] == "demo"
    assert len(result["items"][0]["padding"]) == 150_000


def test_run_json_rejects_oversized_structured_output(monkeypatch):
    class Proc:
        returncode = 0
        stdout = json.dumps({"padding": "x" * 256})
        stderr = ""

    monkeypatch.setattr(main, "STRUCTURED_OUTPUT_LIMIT", 64)
    monkeypatch.setattr(main, "_env", lambda snapshot: {})
    monkeypatch.setattr(main.subprocess, "run", lambda *args, **kwargs: Proc())

    with pytest.raises(Exception) as exc:
        main._run_json(["kubectl", "get", "deployments", "-A", "-o", "json"], {"kind": "kubernetes"})
    assert "structured Kubernetes command output exceeds" in str(exc.value)
