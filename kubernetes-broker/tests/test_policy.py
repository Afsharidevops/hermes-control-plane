import importlib
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
    assert main._verify_ticket(ticket, sig) == plan


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

    assert calls[0]["args"][1] == "apply"
    assert calls[1]["args"][1] == "diff"
    assert calls[1]["allowed_codes"] == {0}
    assert result["verification"]["converged"] is True
    assert result["verification"]["method"] == "kubectl-diff"
