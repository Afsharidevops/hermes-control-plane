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


def test_dynamic_kubectl_selects_exact_server_minor(monkeypatch, tmp_path):
    root = tmp_path / "kubectl"
    for minor in (33, 34, 35, 36):
        binary = root / f"1.{minor}" / "kubectl"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(f"kubectl-{minor}".encode())
        binary.chmod(0o755)

    class Proc:
        returncode = 0
        stderr = ""
        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(args, **kwargs):
        exe = str(args[0])
        if args[1:] == ["version", "-o", "json"]:
            return Proc(json.dumps({"serverVersion": {"gitVersion": "v1.35.4"}, "clientVersion": {"gitVersion": "v1.34.10"}}))
        if args[1:] == ["version", "--client", "-o", "json"]:
            minor = exe.split("/")[-2]
            return Proc(json.dumps({"clientVersion": {"gitVersion": f"v{minor}.99"}}))
        raise AssertionError(args)

    monkeypatch.setattr(main, "KUBECTL_ROOT", root)
    monkeypatch.setattr(main, "KUBECTL_BOOTSTRAP", str(root / "1.34" / "kubectl"))
    monkeypatch.setattr(main, "DYNAMIC_KUBECTL_ENABLED", True)
    monkeypatch.setattr(main, "KUBECTL_SELECTION_MODE", "exact-preferred")
    monkeypatch.setattr(main, "_env", lambda snapshot: {})
    monkeypatch.setattr(main.subprocess, "run", fake_run)
    main._TOOLCHAIN_CACHE.clear()

    selected = main._kubectl_toolchain({"kind": "kubernetes", "snapshot_hash": "a" * 64})
    assert selected["client_minor"] == 35
    assert selected["server_minor"] == 35
    assert selected["path"].endswith("/1.35/kubectl")
    assert len(selected["binding_hash"]) == 64


def test_dynamic_kubectl_uses_compatible_fallback(monkeypatch, tmp_path):
    root = tmp_path / "kubectl"
    for minor in (34, 36):
        binary = root / f"1.{minor}" / "kubectl"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(f"kubectl-{minor}".encode())
        binary.chmod(0o755)

    class Proc:
        returncode = 0
        stderr = ""
        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(args, **kwargs):
        exe = str(args[0])
        if args[1:] == ["version", "-o", "json"]:
            return Proc(json.dumps({"serverVersion": {"gitVersion": "v1.35.4"}}))
        if args[1:] == ["version", "--client", "-o", "json"]:
            minor = exe.split("/")[-2]
            return Proc(json.dumps({"clientVersion": {"gitVersion": f"v{minor}.99"}}))
        raise AssertionError(args)

    monkeypatch.setattr(main, "KUBECTL_ROOT", root)
    monkeypatch.setattr(main, "KUBECTL_BOOTSTRAP", str(root / "1.34" / "kubectl"))
    monkeypatch.setattr(main, "DYNAMIC_KUBECTL_ENABLED", True)
    monkeypatch.setattr(main, "KUBECTL_SELECTION_MODE", "exact-preferred")
    monkeypatch.setattr(main, "_env", lambda snapshot: {})
    monkeypatch.setattr(main.subprocess, "run", fake_run)
    main._TOOLCHAIN_CACHE.clear()

    selected = main._kubectl_toolchain({"kind": "kubernetes", "snapshot_hash": "b" * 64})
    assert selected["server_minor"] == 35
    assert selected["client_minor"] == 34


def test_dynamic_kubectl_fails_closed_without_compatible_binary(monkeypatch, tmp_path):
    root = tmp_path / "kubectl"
    binary = root / "1.33" / "kubectl"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"kubectl-33")
    binary.chmod(0o755)

    class Proc:
        returncode = 0
        stderr = ""
        stdout = json.dumps({"serverVersion": {"gitVersion": "v1.36.2"}})

    monkeypatch.setattr(main, "KUBECTL_ROOT", root)
    monkeypatch.setattr(main, "KUBECTL_BOOTSTRAP", str(binary))
    monkeypatch.setattr(main, "DYNAMIC_KUBECTL_ENABLED", True)
    monkeypatch.setattr(main, "KUBECTL_SELECTION_MODE", "exact-preferred")
    monkeypatch.setattr(main, "_env", lambda snapshot: {})
    monkeypatch.setattr(main.subprocess, "run", lambda *args, **kwargs: Proc())
    main._TOOLCHAIN_CACHE.clear()

    with pytest.raises(Exception) as exc:
        main._kubectl_toolchain({"kind": "kubernetes", "snapshot_hash": "c" * 64})
    assert "no compatible kubectl" in str(exc.value)


def test_execution_rejects_toolchain_binding_drift(monkeypatch):
    monkeypatch.setattr(main, "TOKEN", "test-token")
    monkeypatch.setattr(main, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(main, "_verify_ticket", lambda ticket, signature: (
        {"operation": "kubernetes.manifest.apply", "target_snapshot": {"kind": "kubernetes"}},
        {"toolchain_binding_hash": "a" * 64},
    ))
    monkeypatch.setattr(main, "_kubectl_toolchain", lambda snapshot, **kwargs: {"binding_hash": "b" * 64})
    req = main.ExecuteRequest(ticket={}, signature="0" * 64)
    with pytest.raises(Exception) as exc:
        main.execute(req, authorization="Bearer test-token")
    assert "kubectl toolchain changed after preview" in str(exc.value)


def test_hubble_sanitizes_raw_l7_and_aggregates(monkeypatch):
    from hermes_kubernetes_broker import hubble

    class Proc:
        returncode = 0
        stderr = ""
        stdout = "\n".join([
            json.dumps({"flow": {
                "time": "2026-08-20T10:00:00Z",
                "verdict": "FORWARDED",
                "source": {"namespace": "apps", "pod_name": "api-1", "workloads": [{"kind": "Deployment", "name": "api"}]},
                "destination": {"namespace": "apps", "pod_name": "db-1", "workloads": [{"kind": "StatefulSet", "name": "db"}]},
                "l4": {"TCP": {"destination_port": 5432}},
                "l7": {"http": {"method": "POST", "code": 201, "url": "https://secret.internal/token", "headers": [{"key": "authorization", "value": "Bearer nope"}]}}
            }}),
            json.dumps({"flow": {
                "time": "2026-08-20T10:00:01Z",
                "verdict": "DROPPED",
                "drop_reason_desc": "POLICY_DENIED",
                "source": {"namespace": "other", "pod_name": "x"},
                "destination": {"namespace": "apps", "pod_name": "api-1"},
                "l4": {"TCP": {"destination_port": 443}}
            }}),
        ])

    seen = {}
    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["env"] = kwargs.get("env")
        return Proc()

    monkeypatch.setattr(hubble.subprocess, "run", fake_run)
    result = hubble.collect(
        snapshot={"kind": "kubernetes", "scope": {"namespace_allowlist": ["apps"]}},
        env={"KUBECONFIG": "/credentials/kubeconfigs/cred.yaml"},
        last=20,
        since_seconds=30,
    )
    assert seen["args"] == ["hubble", "observe", "--port-forward", "--output", "jsonpb", "--last", "20", "--since", "30s"]
    assert len(result["events"]) == 1
    encoded = json.dumps(result)
    assert "secret.internal" not in encoded
    assert "Bearer nope" not in encoded
    assert result["events"][0]["http"] == {"method": "POST", "status_class": "2xx"}
    assert result["summary"]["verdict_counts"] == {"FORWARDED": 1}
    assert result["raw_flow_bodies_returned"] is False


def test_hubble_rejects_unbounded_request():
    from hermes_kubernetes_broker import hubble
    with pytest.raises(hubble.HubbleError):
        hubble.collect(snapshot={"kind": "kubernetes", "scope": {}}, env={}, last=201)


def test_dev5_native_diagnostics_are_scoped_read_only_and_redacted(monkeypatch):
    calls = []

    pod = {
        "kind": "Pod",
        "metadata": {"namespace": "apps", "name": "api-1"},
        "spec": {
            "containers": [{
                "name": "api",
                "securityContext": {"privileged": True, "capabilities": {"add": ["NET_ADMIN"]}},
                "env": [{"name": "TOP_SECRET", "value": "TOPSECRET"}],
            }],
            "volumes": [{"name": "host", "hostPath": {"path": "/sensitive/host/path", "type": "Directory"}}],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [{"name": "api", "restartCount": 7, "lastState": {"terminated": {"reason": "OOMKilled"}}}],
        },
    }
    service = {"kind": "Service", "metadata": {"namespace": "apps", "name": "public"}, "spec": {"type": "LoadBalancer"}}
    event = {"kind": "Event", "metadata": {"namespace": "apps", "name": "warn"}, "type": "Warning", "reason": "BackOff", "count": 2, "message": "TOPSECRET", "involvedObject": {"kind": "Pod", "name": "api-1"}}

    def fake_run_json(args, snapshot, timeout=None):
        calls.append(list(args))
        joined = " ".join(args)
        if "--raw" in args:
            return {"items": []}
        if " pods " in f" {joined} ":
            return {"items": [pod]}
        if " services " in f" {joined} ":
            return {"items": [service]}
        if " events " in f" {joined} ":
            return {"items": [event]}
        return {"items": []}

    monkeypatch.setattr(main, "_run_json", fake_run_json)
    snapshot = {
        "kind": "kubernetes",
        "status": "configured",
        "connection_mode": "agent",
        "scope": {"namespace_allowlist": ["apps"], "cluster_read": False},
    }
    payload = main.DiagnosticsRunRequest(
        target_snapshot=snapshot,
        checks=[
            "pods.health", "pods.oom", "events.correlation", "security.privileged",
            "security.capabilities", "security.hostpath", "security.exposed-services",
        ],
    )
    result = main.run_diagnostics(payload, authorization="Bearer test-token")

    assert result["mutation_commands_executed"] is False
    assert result["secret_data_requested"] is False
    assert result["policy_scope"]["namespace_allowlist"] == ["apps"]
    encoded = json.dumps(result, sort_keys=True)
    assert "TOPSECRET" not in encoded
    assert "/sensitive/host/path" not in encoded
    assert any(x["id"] == "security.privileged" and x["status"] == "WARN" for x in result["checks"])
    assert any(x["id"] == "pods.oom" and x["status"] == "WARN" for x in result["checks"])
    assert all(call[1] == "get" for call in calls)
    assert all("-n" in call and "apps" in call or "--raw" in call for call in calls)
    flattened = "\n".join(" ".join(call) for call in calls)
    for forbidden in (" apply ", " delete ", " patch ", " create ", " exec ", " logs "):
        assert forbidden not in f" {flattened} "


def test_dev5_diagnostics_reject_unknown_check(monkeypatch):
    snapshot = {"kind": "kubernetes", "status": "configured", "connection_mode": "agent", "scope": {"namespace_allowlist": ["apps"]}}
    payload = main.DiagnosticsRunRequest(target_snapshot=snapshot, checks=["not.a.real.check"])
    with pytest.raises(Exception) as exc:
        main.run_diagnostics(payload, authorization="Bearer test-token")
    assert "unsupported diagnostic checks" in str(exc.value)


def test_dev5_diagnostics_degrade_collector_rbac_failure_to_skip(monkeypatch):
    def fake_run_json(args, snapshot, timeout=None):
        if "services" in args:
            raise main.HTTPException(422, {"message": "forbidden", "output": "sensitive server text"})
        if "--raw" in args:
            return {"items": []}
        return {"items": []}

    monkeypatch.setattr(main, "_run_json", fake_run_json)
    snapshot = {
        "kind": "kubernetes",
        "status": "configured",
        "connection_mode": "agent",
        "scope": {"namespace_allowlist": ["apps"], "cluster_read": False},
    }
    payload = main.DiagnosticsRunRequest(target_snapshot=snapshot, checks=["security.exposed-services"])
    result = main.run_diagnostics(payload, authorization="Bearer test-token")
    finding = result["checks"][0]
    assert finding["status"] == "SKIP"
    assert finding["evidence"]["collector_error"] == "collector HTTP 422"
    assert "sensitive server text" not in json.dumps(result)
