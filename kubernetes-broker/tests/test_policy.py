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
