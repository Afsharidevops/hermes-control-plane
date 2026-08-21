from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import yaml
from fastapi import HTTPException

TOKEN = os.getenv("HERMES_PROVIDER_WORKER_TOKEN", "")
EXECUTION_KEY = os.getenv("HERMES_EXECUTION_HMAC_KEY", "")
EXECUTION_ENABLED = os.getenv("HERMES_PROVIDER_EXECUTION_ENABLED", "false").lower() == "true"
COMMAND_TIMEOUT = int(os.getenv("HERMES_PROVIDER_COMMAND_TIMEOUT", "1800"))
WORK_ROOT = Path(os.getenv("HERMES_PROVIDER_WORK_ROOT", "/var/lib/hermes-provider"))
SSH_PROFILE_ROOT = Path(os.getenv("HERMES_PROVIDER_SSH_PROFILE_ROOT", "/credentials/ssh"))
MIRROR_ROOT = Path(os.getenv("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror"))
PLAYBOOK_ROOT = Path(os.getenv("HERMES_PROVIDER_PLAYBOOK_ROOT", "/app/playbooks"))
FILES_REPO_URL = os.getenv("HERMES_PROVIDER_FILES_REPO_URL", "").rstrip("/")
APT_REPO_URL = os.getenv("HERMES_PROVIDER_APT_REPO_URL", "").rstrip("/")
RPM_REPO_URL = os.getenv("HERMES_PROVIDER_RPM_REPO_URL", "").rstrip("/")
PYPI_URL = os.getenv("HERMES_PROVIDER_PYPI_URL", "").rstrip("/")

_USED_TICKETS: set[str] = set()
_USED_LOCK = threading.Lock()
CRED_RE = re.compile(r"^cred_[0-9a-f]{16}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
SUPPORTED_PROVIDERS = {"kubespray", "k3s", "rke2"}
KUBESPRAY_SUPPORTED_RELEASES = {"2.28.1", "v2.28.1"}
SUPPORTED_OPERATIONS = {
    "cluster.worker.add",
    "cluster.worker.remove",
    "cluster.worker.replace",
    "cluster.kubernetes.upgrade",
    "cluster.etcd.snapshot",
    "cluster.etcd.restore",
    "cluster.certificate.rotate",
    "cluster.node.maintenance",
    "cluster.decommission",
    "cluster.disaster-recovery",
}

PROVIDER_OPERATION_MATRIX = {
    "kubespray": {
        "cluster.provision.apply", "cluster.worker.add", "cluster.worker.remove", "cluster.worker.replace",
        "cluster.kubernetes.upgrade", "cluster.certificate.rotate", "cluster.node.maintenance",
    },
    "k3s": (set(SUPPORTED_OPERATIONS) - {"cluster.decommission"}) | {"cluster.provision.apply"},
    "rke2": (set(SUPPORTED_OPERATIONS) - {"cluster.decommission"}) | {"cluster.provision.apply"},
}
INSTALL_OPERATIONS = {
    "cluster.provision.apply", "cluster.worker.add", "cluster.worker.replace",
    "cluster.kubernetes.upgrade",
}
KUBESPRAY_ARTIFACT_OPERATIONS = {
    "cluster.provision.apply", "cluster.worker.add", "cluster.worker.remove",
    "cluster.worker.replace", "cluster.kubernetes.upgrade",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def require_token(authorization: str | None) -> None:
    if not TOKEN:
        raise HTTPException(503, "provider worker token not configured")
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "invalid provider worker token")


def _verify_ticket(ticket: dict[str, Any], signature: str, *, consume: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    if not EXECUTION_KEY:
        raise HTTPException(503, "execution signing key not configured")
    expected = hmac.new(EXECUTION_KEY.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "invalid execution ticket signature")
    now = int(time.time())
    if int(ticket.get("expires_at") or 0) < now:
        raise HTTPException(409, "execution ticket expired")
    if int(ticket.get("issued_at") or 0) > now + 30:
        raise HTTPException(409, "execution ticket issued_at is in the future")
    plan = ticket.get("plan")
    if not isinstance(plan, dict) or sha256_hex(plan) != str(ticket.get("plan_hash") or ""):
        raise HTTPException(409, "execution ticket plan hash mismatch")
    preconditions = ticket.get("preconditions") or {}
    if not isinstance(preconditions, dict) or preconditions.get("executor") != "cluster-provider-worker":
        raise HTTPException(422, "execution ticket is not bound to cluster-provider-worker")
    if consume:
        with _USED_LOCK:
            if signature in _USED_TICKETS:
                raise HTTPException(409, "execution ticket has already been used")
            _USED_TICKETS.add(signature)
    return plan, preconditions


def _typed_plan(changeset_plan: dict[str, Any]) -> dict[str, Any]:
    params = changeset_plan.get("parameters") or {}
    typed = params.get("typed_plan")
    if not isinstance(typed, dict):
        raise HTTPException(422, "ChangeSet does not contain a typed provider plan")
    embedded = str(typed.get("plan_hash") or "")
    unsigned = dict(typed)
    unsigned.pop("plan_hash", None)
    if not embedded or sha256_hex(unsigned) != embedded:
        raise HTTPException(409, "typed provider plan hash mismatch")
    return typed


def _cluster_target(typed: dict[str, Any]) -> dict[str, Any]:
    for target in typed.get("targets") or []:
        if target.get("entity_type") == "cluster" or target.get("kind") == "kubernetes-cluster":
            return target
    if typed.get("kind") == "ClusterProvisioningPlan":
        return {
            "entity_type": "cluster",
            "id": typed.get("cluster_id"),
            "provider": typed.get("provider"),
            "kubernetes_version": typed.get("kubernetes_version"),
            "server_snapshots": typed.get("nodes") or [],
        }
    raise HTTPException(422, "typed provider plan has no cluster target")


def _provider(typed: dict[str, Any]) -> str:
    provider = str(typed.get("provider") or (_cluster_target(typed).get("provider") or ""))
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(422, f"unsupported cluster provider {provider!r}")
    return provider


def _artifact_supply(typed: dict[str, Any], *, required: bool = True) -> dict[str, Any] | None:
    supply = typed.get("artifact_supply")
    if not isinstance(supply, dict):
        target = _cluster_target(typed)
        supply = target.get("artifact_supply") or target.get("blueprint_artifact_supply")
    if not isinstance(supply, dict):
        if required:
            raise HTTPException(409, "provider runtime requires exact offline artifact supply")
        return None
    if supply.get("mode") != "offline-manifest-bound" or supply.get("credential_material_in_plan") is not False:
        raise HTTPException(409, "provider artifact supply is not an approved credential-free offline manifest")
    if supply.get("provisioner_rewrite_applied") is not True:
        raise HTTPException(409, "provider plan has not applied deterministic offline reference rewriting")
    manifest_hash = str(supply.get("manifest_hash") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
        raise HTTPException(409, "provider artifact supply has no exact manifest hash")
    items = supply.get("dependency_order") or []
    if not isinstance(items, list) or not items:
        raise HTTPException(409, "provider artifact supply contains no dependencies")
    return supply


def _safe_file_reference(item: dict[str, Any]) -> Path | None:
    reference = str(item.get("offline_reference") or "")
    parsed = urlparse(reference)
    if parsed.scheme != "file":
        return None
    if parsed.netloc or not parsed.path.startswith("/") or parsed.query or parsed.fragment:
        raise HTTPException(422, "unsafe offline file reference")
    path = Path(parsed.path)
    try:
        resolved = path.resolve(strict=True)
        root = MIRROR_ROOT.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(409, f"mirrored artifact {item.get('artifact_id')} is unavailable to provider worker") from exc
    if root != resolved and root not in resolved.parents:
        raise HTTPException(422, "offline file reference escapes provider mirror root")
    expected = str(item.get("digest") or "")
    if not expected.startswith("sha256:"):
        raise HTTPException(422, "offline file artifact lacks exact SHA-256 digest")
    actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, expected[7:]):
        raise HTTPException(409, f"mirrored artifact {item.get('artifact_id')} digest drift detected")
    return resolved


def _safe_extract_tar(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > 20000:
            raise HTTPException(422, "provider release archive contains too many entries")
        total = 0
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise HTTPException(422, "provider release archive contains unsafe entries")
            total += max(0, int(member.size or 0))
            if total > 2 * 1024 * 1024 * 1024:
                raise HTTPException(422, "provider release archive exceeds expanded-size limit")
        archive.extractall(destination, members=members, filter="data")


def _load_ssh_profile(snapshot: dict[str, Any]) -> dict[str, Any]:
    credential_ref = str(snapshot.get("credential_ref") or "")
    if not CRED_RE.fullmatch(credential_ref):
        raise HTTPException(422, "server has no valid SSH credential reference")
    credential = snapshot.get("credential_snapshot") or {}
    if credential and (credential.get("kind") != "ssh-key" or credential.get("status") != "configured"):
        raise HTTPException(409, "provider worker currently requires configured ssh-key credentials")
    directory = SSH_PROFILE_ROOT / credential_ref
    if directory.exists() and directory.is_dir() and not directory.is_symlink():
        meta_path = directory / "profile.json"
        identity = directory / "identity"
        known_hosts = directory / "known_hosts"
    else:
        # Kubernetes Secret/CSI mounts often expose a flat file set rather than
        # one directory per credential reference. Support the same immutable
        # profile contract in that layout without changing what the plan sees.
        meta_path = SSH_PROFILE_ROOT / f"{credential_ref}.profile.json"
        identity = SSH_PROFILE_ROOT / f"{credential_ref}.identity"
        known_hosts = SSH_PROFILE_ROOT / f"{credential_ref}.known_hosts"
    for path in (meta_path, identity, known_hosts):
        if path.is_symlink() or not path.is_file():
            raise HTTPException(409, f"SSH profile {credential_ref} is incomplete")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(409, f"SSH profile {credential_ref} metadata is invalid") from exc
    host = str(snapshot.get("management_ip") or snapshot.get("hostname") or "")
    port = int(snapshot.get("ssh_port") or 22)
    user = str(snapshot.get("ssh_user") or "")
    if str(meta.get("host") or "") != host or int(meta.get("port") or 0) != port or str(meta.get("user") or "") != user:
        raise HTTPException(409, f"SSH profile {credential_ref} no longer matches approved server snapshot")
    fingerprint = str(snapshot.get("host_fingerprint") or "")
    if fingerprint and str(meta.get("fingerprint") or "") != fingerprint:
        raise HTTPException(409, f"SSH host fingerprint drift detected for {snapshot.get('id')}")
    return {"identity": str(identity), "known_hosts": str(known_hosts)}


def _server_snapshots(typed: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots: dict[str, dict[str, Any]] = {}
    cluster = _cluster_target(typed)
    for item in cluster.get("server_snapshots") or []:
        if isinstance(item, dict) and str(item.get("id") or "").startswith("srv_"):
            snapshots[str(item["id"])] = item
    for item in typed.get("targets") or []:
        if isinstance(item, dict) and item.get("entity_type") == "server" and str(item.get("id") or "").startswith("srv_"):
            snapshots[str(item["id"])] = item
    if typed.get("kind") == "ClusterProvisioningPlan":
        for item in typed.get("nodes") or []:
            server_id = str(item.get("server_id") or "")
            if server_id:
                snapshots[server_id] = {
                    "entity_type": "server",
                    "id": server_id,
                    "hostname": item.get("hostname"),
                    "management_ip": item.get("management_ip"),
                    "ssh_port": item.get("ssh_port", 22),
                    "ssh_user": item.get("ssh_user"),
                    "host_fingerprint": item.get("host_fingerprint"),
                    "credential_ref": item.get("credential_ref"),
                    "status": item.get("status", "configured"),
                    "preflight_status": item.get("preflight_status"),
                    "snapshot_hash": item.get("snapshot_hash", ""),
                }
    if not snapshots:
        raise HTTPException(422, "provider runtime has no exact server snapshots")
    return [snapshots[key] for key in sorted(snapshots)]


def _inventory(typed: dict[str, Any], work: Path) -> tuple[Path, list[str]]:
    role_by_server: dict[str, str] = {}
    cluster = _cluster_target(typed)
    for role in cluster.get("node_roles") or []:
        for server_id in role.get("server_ids") or []:
            role_by_server[str(server_id)] = str(role.get("role") or "worker")
    for node in typed.get("nodes") or []:
        role_by_server[str(node.get("server_id") or "")] = str(node.get("role") or "worker")

    hosts: dict[str, Any] = {}
    cp: list[str] = []
    workers: list[str] = []
    for snapshot in _server_snapshots(typed):
        if snapshot.get("preflight_status") != "PASS" or snapshot.get("status") != "configured":
            raise HTTPException(409, f"server {snapshot.get('id')} is not preflight PASS/configured")
        profile = _load_ssh_profile(snapshot)
        hostname = str(snapshot.get("hostname") or "")
        if not hostname or not SAFE_NAME_RE.fullmatch(hostname):
            raise HTTPException(422, "server hostname is invalid for provider inventory")
        local_ssh = work / "ssh" / str(snapshot["credential_ref"])
        local_ssh.mkdir(parents=True, mode=0o700, exist_ok=True)
        local_identity = local_ssh / "identity"
        local_known_hosts = local_ssh / "known_hosts"
        try:
            shutil.copyfile(profile["identity"], local_identity)
            shutil.copyfile(profile["known_hosts"], local_known_hosts)
        except OSError as exc:
            raise HTTPException(409, f"SSH profile {snapshot['credential_ref']} cannot be staged for trusted execution") from exc
        os.chmod(local_identity, 0o600)
        os.chmod(local_known_hosts, 0o600)
        hosts[hostname] = {
            "ansible_host": str(snapshot.get("management_ip") or hostname),
            "ansible_port": int(snapshot.get("ssh_port") or 22),
            "ansible_user": str(snapshot.get("ssh_user") or ""),
            "ansible_ssh_private_key_file": str(local_identity),
            "ansible_ssh_common_args": f"-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={local_known_hosts}",
            "hermes_server_id": snapshot["id"],
            "hermes_management_ip": str(snapshot.get("management_ip") or hostname),
        }
        role = role_by_server.get(str(snapshot["id"]), "worker")
        hosts[hostname]["hermes_role"] = role
        if role in {"control-plane", "control-plane-worker"}:
            cp.append(hostname)
        if role in {"worker", "control-plane-worker"}:
            workers.append(hostname)
    if not cp:
        raise HTTPException(422, "provider inventory requires at least one control-plane node")
    data = {
        "all": {
            "hosts": hosts,
            "children": {
                "kube_control_plane": {"hosts": {name: {} for name in sorted(cp)}},
                "etcd": {"hosts": {name: {} for name in sorted(cp)}},
                "kube_node": {"hosts": {name: {} for name in sorted(set(cp + workers))}},
            },
        }
    }
    path = work / "inventory.yml"
    path.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)
    return path, sorted(hosts)


def _artifact_context(typed: dict[str, Any], work: Path) -> dict[str, Any]:
    supply = _artifact_supply(typed)
    artifacts = []
    provider_files: list[Path] = []
    oci_refs: list[str] = []
    for item in supply.get("dependency_order") or []:
        reference = str(item.get("offline_reference") or "")
        parsed = urlparse(reference)
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise HTTPException(422, "provider artifact reference contains forbidden credential/query material")
        local = _safe_file_reference(item)
        if local is not None and str(item.get("component") or "") == "provider":
            provider_files.append(local)
        if parsed.scheme == "oci":
            oci_refs.append(reference)
        artifacts.append({
            "artifact_id": str(item.get("artifact_id") or ""),
            "component": str(item.get("component") or ""),
            "name": str(item.get("name") or ""),
            "kind": str(item.get("kind") or ""),
            "version": str(item.get("version") or ""),
            "digest": str(item.get("digest") or ""),
            "offline_reference": reference,
        })
    if not provider_files:
        raise HTTPException(409, "provider runtime requires at least one local mirrored provider artifact")
    return {
        "manifest_hash": supply["manifest_hash"],
        "artifacts": artifacts,
        "provider_files": provider_files,
        "oci_registry": _common_registry(oci_refs),
    }


def _common_registry(refs: list[str]) -> str:
    registries = sorted({urlparse(ref).netloc for ref in refs if urlparse(ref).scheme == "oci"})
    if len(registries) > 1:
        raise HTTPException(422, "provider plan references multiple offline OCI registries")
    return registries[0] if registries else ""


def _run(args: list[str], *, cwd: Path, timeout: int | None = None) -> None:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=timeout or COMMAND_TIMEOUT,
            check=False,
            env={**os.environ, "ANSIBLE_HOST_KEY_CHECKING": "True", "ANSIBLE_NOCOLOR": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(502, f"provider worker fixed command failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise HTTPException(502, f"provider worker fixed command exited with status {completed.returncode}")


def _provider_bundle(provider: str, context: dict[str, Any], work: Path) -> dict[str, str]:
    bundle = work / "provider-bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for index, source in enumerate(context["provider_files"]):
        target = bundle / f"artifact-{index:02d}-{source.name}"
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        copied.append(target)
        if tarfile.is_tarfile(source):
            _safe_extract_tar(source, bundle / f"archive-{index:02d}")
    files = [p for p in bundle.rglob("*") if p.is_file()]
    result = {"bundle_root": str(bundle)}
    if provider == "k3s":
        binary = next((p for p in files if p.name == "k3s"), None)
        install = next((p for p in files if p.name == "install.sh"), None)
        image = next((p for p in files if p.name.startswith("k3s-airgap-images") and p.is_file()), None)
        if not binary or not install or not image:
            raise HTTPException(409, "K3s provider artifacts must contain k3s, install.sh and k3s-airgap-images archive")
        result.update(binary=str(binary), install_script=str(install), images=str(image))
    elif provider == "rke2":
        install = next((p for p in files if p.name == "install.sh"), None)
        images = next((p for p in files if p.name.startswith("rke2-images") and p.is_file()), None)
        artifact = next((p for p in files if p.name.startswith("rke2.linux-") or p.name.startswith("rke2.linux")), None)
        checksum = next((p for p in files if p.name.startswith("sha256sum-")), None)
        if not install or not images or not artifact or not checksum:
            raise HTTPException(409, "RKE2 provider artifacts must contain install.sh, binary archive, checksum and image archive")
        normalized = bundle / "rke2-offline"
        normalized.mkdir(mode=0o700, exist_ok=True)
        for source in (install, images, artifact, checksum):
            target = normalized / source.name
            shutil.copyfile(source, target)
            os.chmod(target, 0o700 if source == install else 0o600)
        result.update(
            bundle_root=str(normalized),
            install_script=str(normalized / install.name),
            images=str(normalized / images.name),
            binary_archive=str(normalized / artifact.name),
            checksum=str(normalized / checksum.name),
        )
    elif provider == "kubespray":
        provider_versions = {
            str(item.get("version") or "")
            for item in context.get("artifacts") or []
            if str(item.get("component") or "") == "provider"
        }
        if len(provider_versions) != 1 or next(iter(provider_versions)) not in KUBESPRAY_SUPPORTED_RELEASES:
            raise HTTPException(409, "trusted Kubespray runtime is pinned to provider release v2.28.1")
        cluster_yml = next((p for p in files if p.name == "cluster.yml"), None)
        if not cluster_yml:
            raise HTTPException(409, "Kubespray provider release must contain cluster.yml")
        result.update(kubespray_root=str(cluster_yml.parent), cluster_playbook=str(cluster_yml))
    return result


def _operation(typed: dict[str, Any]) -> str:
    if typed.get("kind") == "ClusterProvisioningPlan":
        return "cluster.provision.apply"
    op = str(typed.get("operation") or "")
    if op not in SUPPORTED_OPERATIONS:
        raise HTTPException(422, f"unsupported trusted provider operation {op!r}")
    return op


def _require_provider_operation(provider: str, operation: str) -> None:
    if operation not in PROVIDER_OPERATION_MATRIX.get(provider, set()):
        if provider == "kubespray" and operation in {"cluster.etcd.snapshot", "cluster.etcd.restore", "cluster.disaster-recovery"}:
            raise HTTPException(422, "direct etcd snapshot/restore and DR are currently bounded to K3s/RKE2 embedded-etcd runtimes; Kubespray fails closed")
        raise HTTPException(422, f"operation {operation!r} is not supported by trusted {provider} runtime")


def _role_by_server(typed: dict[str, Any]) -> dict[str, str]:
    roles: dict[str, str] = {}
    cluster = _cluster_target(typed)
    for item in cluster.get("node_roles") or []:
        for server_id in item.get("server_ids") or []:
            roles[str(server_id)] = str(item.get("role") or "worker")
    for node in typed.get("nodes") or []:
        roles[str(node.get("server_id") or "")] = str(node.get("role") or "worker")
    return roles


def _operation_requires_artifacts(provider: str, operation: str) -> bool:
    if provider == "kubespray":
        return operation in KUBESPRAY_ARTIFACT_OPERATIONS
    return operation in INSTALL_OPERATIONS


def _require_offline_runtime_endpoints(provider: str, operation: str, context: dict[str, Any]) -> None:
    if not _operation_requires_artifacts(provider, operation):
        return
    if not context.get("oci_registry"):
        raise HTTPException(409, f"{provider} offline execution requires an exact offline OCI registry reference")
    if provider == "kubespray":
        missing = [name for name, value in {
            "HERMES_PROVIDER_FILES_REPO_URL": FILES_REPO_URL,
            "HERMES_PROVIDER_APT_REPO_URL": APT_REPO_URL,
            "HERMES_PROVIDER_RPM_REPO_URL": RPM_REPO_URL,
            "HERMES_PROVIDER_PYPI_URL": PYPI_URL,
        }.items() if not value]
        if missing:
            raise HTTPException(409, "Kubespray offline execution requires internal file/package/PyPI endpoints: " + ", ".join(missing))


def _validated_parameters(typed: dict[str, Any], operation: str) -> dict[str, Any]:
    p = dict(typed.get("parameters") or {})
    if operation in {"cluster.etcd.snapshot", "cluster.etcd.restore", "cluster.disaster-recovery"}:
        name = str(p.get("snapshot_name") or p.get("snapshot_reference") or "")
        if not SNAPSHOT_RE.fullmatch(name):
            raise HTTPException(422, "snapshot_name/snapshot_reference is invalid")
    if operation == "cluster.node.maintenance" and p.get("action") not in {"reboot", "restart-kubelet", "restart-provider-service"}:
        raise HTTPException(422, "maintenance action must be reboot, restart-kubelet or restart-provider-service")
    if operation == "cluster.kubernetes.upgrade":
        version = str(p.get("target_version") or "")
        if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise HTTPException(422, "target_version is invalid")
    return p


def _validate_provider_parameters(typed: dict[str, Any], provider: str, operation: str, params: dict[str, Any]) -> None:
    roles = _role_by_server(typed)
    if operation == "cluster.worker.add":
        server_id = str(params.get("server_id") or "")
        if roles.get(server_id, "worker") != "worker":
            raise HTTPException(422, "worker add target must have worker role")
    elif operation == "cluster.worker.remove":
        server_id = str(params.get("server_id") or "")
        if roles.get(server_id) != "worker":
            raise HTTPException(422, "worker remove target must be an existing worker")
    elif operation == "cluster.worker.replace":
        old_id = str(params.get("old_server_id") or "")
        new_id = str(params.get("new_server_id") or "")
        if roles.get(old_id) != "worker" or roles.get(new_id, "worker") != "worker":
            raise HTTPException(422, "worker replacement is bounded to worker-role nodes")
    elif operation == "cluster.node.maintenance":
        action = str(params.get("action") or "")
        if action == "restart-kubelet" and provider != "kubespray":
            raise HTTPException(422, "restart-kubelet is only valid for Kubespray/kubeadm nodes")
        if action == "restart-provider-service" and provider == "kubespray":
            raise HTTPException(422, "Kubespray maintenance uses restart-kubelet rather than restart-provider-service")


def _vars(typed: dict[str, Any], provider: str, operation: str, context: dict[str, Any], bundle: dict[str, str], work: Path) -> Path:
    params = _validated_parameters(typed, operation)
    cluster = _cluster_target(typed)
    snapshots = _server_snapshots(typed)
    roles = _role_by_server(typed)
    cp = [item for item in snapshots if roles.get(str(item.get("id"))) in {"control-plane", "control-plane-worker"}]
    cp.sort(key=lambda item: (str(item.get("hostname") or ""), str(item.get("id") or "")))
    if not cp:
        raise HTTPException(422, "provider runtime requires a control-plane host")
    primary = cp[0]
    values: dict[str, Any] = {
        "hermes_operation": operation,
        "hermes_provider": provider,
        "hermes_cluster_id": str(typed.get("cluster_id") or cluster.get("id") or ""),
        "hermes_kubernetes_version": str(typed.get("kubernetes_version") or cluster.get("kubernetes_version") or params.get("target_version") or ""),
        "hermes_target_version": str(params.get("target_version") or ""),
        "hermes_snapshot_name": str(params.get("snapshot_name") or params.get("snapshot_reference") or ""),
        "hermes_maintenance_action": str(params.get("action") or ""),
        "hermes_server_id": str(params.get("server_id") or ""),
        "hermes_old_server_id": str(params.get("old_server_id") or ""),
        "hermes_new_server_id": str(params.get("new_server_id") or ""),
        "hermes_offline_manifest_hash": context["manifest_hash"],
        "hermes_offline_registry": context["oci_registry"],
        "hermes_files_repo": FILES_REPO_URL,
        "hermes_apt_repo": APT_REPO_URL,
        "hermes_rpm_repo": RPM_REPO_URL,
        "hermes_pypi_repo": PYPI_URL,
        "hermes_primary_hostname": str(primary.get("hostname") or ""),
        "hermes_primary_api_url": f"https://{primary.get('management_ip')}:6443",
        "hermes_primary_supervisor_url": f"https://{primary.get('management_ip')}:9345",
        **{f"hermes_{k}": v for k, v in bundle.items()},
    }
    if provider == "kubespray" and _operation_requires_artifacts(provider, operation):
        registry = context["oci_registry"]
        kube_version = str(values["hermes_target_version"] or values["hermes_kubernetes_version"])
        if kube_version and not kube_version.startswith("v"):
            kube_version = "v" + kube_version
        values.update({
            "kube_version": kube_version,
            "kube_network_plugin": "cilium",
            "kube_image_repo": registry,
            "gcr_image_repo": registry,
            "docker_image_repo": registry,
            "quay_image_repo": registry,
            "github_image_repo": registry,
            "registry_host": registry,
            "registry_addr": registry,
            "files_repo": FILES_REPO_URL,
            "github_url": f"{FILES_REPO_URL}/github.com",
            "dl_k8s_io_url": f"{FILES_REPO_URL}/dl.k8s.io",
            "storage_googleapis_url": f"{FILES_REPO_URL}/storage.googleapis.com",
            "get_helm_url": f"{FILES_REPO_URL}/get.helm.sh",
            "debian_repo": APT_REPO_URL,
            "ubuntu_repo": APT_REPO_URL,
            "yum_repo": RPM_REPO_URL,
            "docker_debian_repo_base_url": APT_REPO_URL,
            "docker_ubuntu_repo_base_url": APT_REPO_URL,
            "docker_rh_repo_base_url": RPM_REPO_URL,
            "docker_fedora_repo_base_url": RPM_REPO_URL,
            "download_run_once": True,
            "unsafe_show_logs": False,
        })
    path = work / "vars.yml"
    path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def preview(changeset_plan: dict[str, Any]) -> dict[str, Any]:
    typed = _typed_plan(changeset_plan)
    provider = _provider(typed)
    operation = _operation(typed)
    _require_provider_operation(provider, operation)
    supply = _artifact_supply(typed, required=_operation_requires_artifacts(provider, operation))
    servers = _server_snapshots(typed)
    params = _validated_parameters(typed, operation)
    _validate_provider_parameters(typed, provider, operation, params)
    return {
        "kind": "ProviderRuntimePreview",
        "operation": operation,
        "provider": provider,
        "summary": f"Trusted {provider} provider runtime preview for {operation}",
        "preconditions": {
            "typed_plan_hash": typed["plan_hash"],
            "artifact_manifest_hash": str((supply or {}).get("manifest_hash") or ""),
            "server_snapshot_hashes": {str(s["id"]): str(s.get("snapshot_hash") or "") for s in servers},
        },
        "parameters": {k: v for k, v in params.items() if "credential" not in str(k).lower()},
        "arbitrary_shell": False,
        "arbitrary_ssh_command": False,
        "credential_material_returned": False,
        "secret_output_suppressed": True,
    }


def execute(ticket: dict[str, Any], signature: str) -> dict[str, Any]:
    if not EXECUTION_ENABLED:
        raise HTTPException(503, "provider execution is disabled")
    changeset_plan, preconditions = _verify_ticket(ticket, signature, consume=True)
    typed = _typed_plan(changeset_plan)
    if str(preconditions.get("typed_plan_hash") or "") != str(typed.get("plan_hash") or ""):
        raise HTTPException(409, "execution ticket typed plan hash mismatch")
    provider = _provider(typed)
    operation = _operation(typed)
    _require_provider_operation(provider, operation)
    supply = _artifact_supply(typed, required=_operation_requires_artifacts(provider, operation))
    if preconditions.get("artifact_manifest_hash") and str(preconditions["artifact_manifest_hash"]) != str((supply or {}).get("manifest_hash") or ""):
        raise HTTPException(409, "execution ticket artifact manifest precondition mismatch")
    _validate_provider_parameters(typed, provider, operation, _validated_parameters(typed, operation))

    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    work = WORK_ROOT / str(typed["plan_hash"])
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    try:
        inventory, hostnames = _inventory(typed, work)
        if _operation_requires_artifacts(provider, operation):
            context = _artifact_context(typed, work)
            _require_offline_runtime_endpoints(provider, operation, context)
            bundle = _provider_bundle(provider, context, work)
        else:
            context = {"manifest_hash": "", "artifacts": [], "provider_files": [], "oci_registry": ""}
            bundle = {"bundle_root": str(work / "provider-bundle")}
        vars_path = _vars(typed, provider, operation, context, bundle, work)

        if operation in KUBESPRAY_ARTIFACT_OPERATIONS and provider == "kubespray":
            kubespray_root = Path(bundle["kubespray_root"])
            def fixed_playbook(name: str) -> Path:
                selected = kubespray_root / name
                if not selected.is_file():
                    raise HTTPException(409, f"Kubespray release does not contain required fixed playbook {name}")
                return selected
            params = _validated_parameters(typed, operation)
            snapshots = {str(item.get("id") or ""): item for item in _server_snapshots(typed)}
            if operation == "cluster.kubernetes.upgrade":
                commands = [["ansible-playbook", "-i", str(inventory), str(fixed_playbook("upgrade-cluster.yml")), "-b", "--extra-vars", f"@{vars_path}"]]
            elif operation == "cluster.worker.remove":
                server = snapshots.get(str(params.get("server_id") or ""))
                if not server:
                    raise HTTPException(409, "approved worker-remove server snapshot is missing")
                commands = [["ansible-playbook", "-i", str(inventory), str(fixed_playbook("remove-node.yml")), "-b", "--extra-vars", f"@{vars_path}", "--extra-vars", f"node={server['hostname']}"]]
            elif operation == "cluster.worker.replace":
                old_server = snapshots.get(str(params.get("old_server_id") or ""))
                if not old_server:
                    raise HTTPException(409, "approved old worker snapshot is missing")
                commands = [
                    ["ansible-playbook", "-i", str(inventory), str(fixed_playbook("cluster.yml")), "-b", "--extra-vars", f"@{vars_path}"],
                    ["ansible-playbook", "-i", str(inventory), str(fixed_playbook("remove-node.yml")), "-b", "--extra-vars", f"@{vars_path}", "--extra-vars", f"node={old_server['hostname']}"],
                ]
            else:
                commands = [["ansible-playbook", "-i", str(inventory), str(fixed_playbook("cluster.yml")), "-b", "--extra-vars", f"@{vars_path}"]]
            for args in commands:
                _run(args, cwd=work)
        else:
            playbook = PLAYBOOK_ROOT / "provider-operation.yml"
            if not playbook.is_file():
                raise HTTPException(503, "provider operation playbook is unavailable")
            args = ["ansible-playbook", "-i", str(inventory), str(playbook), "-b", "--extra-vars", f"@{vars_path}"]
            _run(args, cwd=work)

        verify_playbook = PLAYBOOK_ROOT / "provider-verify.yml"
        if not verify_playbook.is_file():
            raise HTTPException(503, "provider verification playbook is unavailable")
        _run(["ansible-playbook", "-i", str(inventory), str(verify_playbook), "-b", "--extra-vars", f"@{vars_path}"], cwd=work, timeout=min(COMMAND_TIMEOUT, 600))

        observed_at = int(time.time())
        return {
            "state": "SUCCEEDED",
            "provider": provider,
            "operation": operation,
            "typed_plan_hash": typed["plan_hash"],
            "artifact_manifest_hash": str((supply or {}).get("manifest_hash") or ""),
            "verification": {
                "checks": [
                    {"id": "provider-fixed-command", "status": "PASS", "summary": "Fixed provider execution completed without shell/caller CLI injection", "evidence": {"provider": provider, "operation": operation}},
                    {"id": "provider-active-verify", "status": "PASS", "summary": "Static active verification playbook completed on approved hosts", "evidence": {"host_count": len(hostnames)}},
                    {"id": "offline-artifact-binding", "status": "PASS" if supply else "SKIP", "summary": "Execution consumed exact verified offline artifact manifest" if supply else "Operation did not require artifact changes", "evidence": {"manifest_hash": str((supply or {}).get("manifest_hash") or "")}},
                ],
                "evidence": {
                    "provider": provider,
                    "operation": operation,
                    "host_count": len(hostnames),
                    "arbitrary_shell": False,
                    "arbitrary_ssh_command": False,
                    "raw_credentials_returned": False,
                    "stdout_returned": False,
                    "stderr_returned": False,
                },
                "observed_at": observed_at,
            },
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)
