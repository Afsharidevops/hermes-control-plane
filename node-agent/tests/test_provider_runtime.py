from __future__ import annotations

import hashlib
import hmac
import io
import json
import tarfile
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from hermes_node_agent import provider_runtime as runtime


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signed_ticket(typed: dict, key: str, *, provider_job_id: str = "job_0123456789abcdef"):
    changeset_plan = {"parameters": {"typed_plan": typed}}
    ticket = {
        "changeset_id": "chg_0123456789abcdef",
        "plan_hash": runtime.sha256_hex(changeset_plan),
        "plan": changeset_plan,
        "preconditions": {
            "provider_job_id": provider_job_id,
            "executor": "cluster-provider-worker",
            "typed_plan_hash": typed["plan_hash"],
            "policy_generation": 1,
            "artifact_manifest_hash": typed["artifact_supply"]["manifest_hash"],
        },
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
    }
    sig = hmac.new(key.encode(), _canonical(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, sig


def _k3s_bundle(path: Path) -> str:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload, mode in [
            ("install.sh", b"#!/bin/sh\nexit 0\n", 0o755),
            ("k3s", b"binary", 0o755),
            ("k3s-airgap-images-amd64.tar.zst", b"images", 0o600),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = mode
            archive.addfile(info, io.BytesIO(payload))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile(root: Path, cred: str, host: str, user: str, fingerprint: str):
    directory = root / cred
    directory.mkdir(parents=True)
    (directory / "identity").write_text("fake-private-key")
    (directory / "known_hosts").write_text(f"{host} ssh-ed25519 AAAATEST\n")
    (directory / "profile.json").write_text(json.dumps({"host": host, "port": 22, "user": user, "fingerprint": fingerprint}))


def _typed_plan(bundle: Path, digest: str) -> dict:
    typed = {
        "schema_version": 5,
        "kind": "ClusterProvisioningPlan",
        "cluster_id": "clu_0123456789abcdef",
        "provider": "k3s",
        "kubernetes_version": "1.35.6",
        "nodes": [
            {
                "server_id": "srv_0123456789abcdef",
                "hostname": "node1",
                "management_ip": "10.0.0.10",
                "ssh_port": 22,
                "ssh_user": "ubuntu",
                "credential_ref": "cred_0123456789abcdef",
                "status": "configured",
                "role": "control-plane-worker",
                "preflight_status": "PASS",
                "host_fingerprint": "SHA256:" + "A" * 43,
                "snapshot_hash": "a" * 64,
            }
        ],
        "artifact_supply": {
            "mode": "offline-manifest-bound",
            "manifest_hash": "b" * 64,
            "dependency_order": [
                {
                    "artifact_id": "art_0123456789abcdef",
                    "component": "provider",
                    "name": "k3s-provider-bundle",
                    "kind": "package",
                    "version": "v1.35.6+k3s1",
                    "digest": "sha256:" + digest,
                    "offline_reference": f"file://{bundle}",
                    "depends_on": [],
                },
                {
                    "artifact_id": "art_1111111111111111",
                    "component": "addon",
                    "name": "cilium-image",
                    "kind": "oci-image",
                    "version": "1.18.2",
                    "digest": "sha256:" + "1" * 64,
                    "offline_reference": "oci://registry.offline.local/cilium/cilium",
                    "depends_on": [],
                },
            ],
            "offline_reference_selection": "verified-destination-only",
            "credential_material_in_plan": False,
            "provisioner_rewrite_applied": True,
        },
        "provider_payload": {"kind": "K3sExecutionSpec", "provisioner_rewrite_applied": True},
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    return typed


def test_preview_rejects_unrewritten_offline_plan():
    typed = {
        "kind": "ClusterProvisioningPlan",
        "cluster_id": "clu_x",
        "provider": "k3s",
        "nodes": [],
        "artifact_supply": {
            "mode": "offline-manifest-bound",
            "manifest_hash": "b" * 64,
            "dependency_order": [{}],
            "credential_material_in_plan": False,
            "provisioner_rewrite_applied": False,
        },
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 409
    assert "rewriting" in str(exc.value.detail)


def test_execution_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", False)
    with pytest.raises(HTTPException) as exc:
        runtime.execute({}, "0" * 64)
    assert exc.value.status_code == 503


def test_signed_k3s_execution_uses_fixed_ansible_and_suppresses_output(tmp_path: Path, monkeypatch):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    bundle = mirror / "provider.tar.gz"
    digest = _k3s_bundle(bundle)
    profiles = tmp_path / "profiles"
    _profile(profiles, "cred_0123456789abcdef", "10.0.0.10", "ubuntu", "SHA256:" + "A" * 43)
    work = tmp_path / "work"
    key = "execution-key-0123456789abcdef0123456789abcdef"

    monkeypatch.setattr(runtime, "EXECUTION_ENABLED", True)
    monkeypatch.setattr(runtime, "EXECUTION_KEY", key)
    monkeypatch.setattr(runtime, "MIRROR_ROOT", mirror)
    monkeypatch.setattr(runtime, "SSH_PROFILE_ROOT", profiles)
    monkeypatch.setattr(runtime, "WORK_ROOT", work)
    monkeypatch.setattr(runtime, "PLAYBOOK_ROOT", Path(__file__).parents[1] / "playbooks")
    runtime._USED_TICKETS.clear()

    seen: list[list[str]] = []
    monkeypatch.setattr(runtime, "_run", lambda args, **kwargs: seen.append(list(args)))

    typed = _typed_plan(bundle, digest)
    ticket, signature = _signed_ticket(typed, key)
    result = runtime.execute(ticket, signature)

    assert result["state"] == "SUCCEEDED"
    assert result["verification"]["evidence"]["arbitrary_shell"] is False
    assert result["verification"]["evidence"]["arbitrary_ssh_command"] is False
    assert result["verification"]["evidence"]["stdout_returned"] is False
    assert result["verification"]["evidence"]["stderr_returned"] is False
    assert len(seen) == 2
    assert all(command[0] == "ansible-playbook" for command in seen)
    assert all("--extra-vars" in command for command in seen)
    assert not (work / typed["plan_hash"]).exists()

    with pytest.raises(HTTPException) as replay:
        runtime.execute(ticket, signature)
    assert replay.value.status_code == 409
    assert "already been used" in str(replay.value.detail)


def test_file_artifact_digest_drift_is_rejected(tmp_path: Path, monkeypatch):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    bundle = mirror / "provider.tar.gz"
    _k3s_bundle(bundle)
    typed = _typed_plan(bundle, "0" * 64)
    monkeypatch.setattr(runtime, "MIRROR_ROOT", mirror)
    with pytest.raises(HTTPException) as exc:
        runtime._artifact_context(typed, tmp_path / "work")
    assert exc.value.status_code == 409
    assert "digest drift" in str(exc.value.detail)


def test_kubespray_direct_etcd_restore_fails_closed_before_execution():
    typed = {
        "schema_version": 5,
        "kind": "Day2OperationPlan",
        "operation": "cluster.etcd.restore",
        "provider": "kubespray",
        "parameters": {"snapshot_reference": "before-upgrade"},
        "targets": [{
            "entity_type": "cluster", "kind": "kubernetes-cluster", "id": "clu_0123456789abcdef",
            "provider": "kubespray", "server_snapshots": [{
                "entity_type": "server", "id": "srv_0123456789abcdef", "hostname": "node1",
                "management_ip": "10.0.0.10", "ssh_port": 22, "ssh_user": "ubuntu",
                "credential_ref": "cred_0123456789abcdef", "status": "configured",
                "preflight_status": "PASS", "host_fingerprint": "SHA256:" + "A" * 43, "snapshot_hash": "a" * 64,
            }],
            "node_roles": [{"role": "control-plane-worker", "server_ids": ["srv_0123456789abcdef"]}],
        }],
    }
    typed["plan_hash"] = runtime.sha256_hex(typed)
    with pytest.raises(HTTPException) as exc:
        runtime.preview({"parameters": {"typed_plan": typed}})
    assert exc.value.status_code == 422
    assert "fails closed" in str(exc.value.detail)


def test_provider_playbooks_are_role_aware_and_shell_free():
    root = Path(__file__).parents[1] / "playbooks"
    operation = (root / "provider-operation.yml").read_text(encoding="utf-8")
    verification = (root / "provider-verify.yml").read_text(encoding="utf-8")
    assert "K3S_URL" in operation
    assert "K3S_TOKEN" in operation
    assert "INSTALL_K3S_SKIP_DOWNLOAD" in operation
    assert "INSTALL_RKE2_ARTIFACT_PATH" in operation
    assert "hermes_primary_supervisor_url" in operation
    assert "token:" in operation
    assert "Delete old K3s peer DB before rejoin" in operation
    assert "Delete old RKE2 peer DB before rejoin" in operation
    assert "--cluster-reset-restore-path=/var/lib/hermes/provider/snapshots/" in operation
    assert "--etcd-s3=false" in operation
    assert "k3s, kubectl, delete, node" in operation
    assert "rke2/bin/kubectl" in operation
    assert "--raw=/readyz" in verification
    lowered = (operation + "\n" + verification).lower()
    assert "ansible.builtin.shell" not in lowered
    assert "ansible.builtin.raw" not in lowered
    assert "kubectl exec" not in lowered
    assert "kubectl cp" not in lowered


def test_maintenance_action_is_provider_specific():
    params = {"action": "restart-kubelet", "server_id": "srv_0123456789abcdef"}
    typed = {
        "kind": "Day2OperationPlan", "operation": "cluster.node.maintenance", "provider": "k3s",
        "parameters": params, "targets": [{
            "entity_type": "cluster", "id": "clu_0123456789abcdef", "provider": "k3s",
            "server_snapshots": [], "node_roles": []
        }],
    }
    with pytest.raises(HTTPException) as exc:
        runtime._validate_provider_parameters(typed, "k3s", "cluster.node.maintenance", params)
    assert exc.value.status_code == 422
    assert "Kubespray" in str(exc.value.detail)


def test_disaster_recovery_does_not_require_artifact_reinstall():
    assert runtime._operation_requires_artifacts("k3s", "cluster.disaster-recovery") is False
    assert runtime._operation_requires_artifacts("rke2", "cluster.disaster-recovery") is False


def test_cluster_decommission_stays_fail_closed_until_provider_capacity_runtime_exists():
    with pytest.raises(HTTPException) as exc:
        runtime._require_provider_operation("k3s", "cluster.decommission")
    assert exc.value.status_code == 422
    assert "not supported" in str(exc.value.detail)


def test_kubespray_runtime_release_pin_matches_bundled_ansible_contract():
    assert runtime.KUBESPRAY_SUPPORTED_RELEASES == {"2.28.1", "v2.28.1"}
