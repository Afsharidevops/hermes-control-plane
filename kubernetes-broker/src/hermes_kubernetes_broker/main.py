from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import shutil
import time
import threading
from pathlib import Path
from typing import Any, Literal

from . import hubble as hubble_provider
from . import diagnostics as diagnostics_provider

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

VERSION = "0.5.11-dev.5"
CREDENTIAL_ROOT = Path(os.getenv("HERMES_KUBECONFIG_ROOT", "/credentials/kubeconfigs"))
TOKEN = os.getenv("HERMES_KUBERNETES_BROKER_TOKEN", "")
EXECUTION_KEY = os.getenv("HERMES_EXECUTION_HMAC_KEY", "")
EXECUTION_ENABLED = os.getenv("HERMES_KUBERNETES_EXECUTION_ENABLED", "false").lower() == "true"
COMMAND_TIMEOUT = int(os.getenv("HERMES_KUBERNETES_COMMAND_TIMEOUT", "60"))
STRUCTURED_OUTPUT_LIMIT = int(os.getenv("HERMES_KUBERNETES_STRUCTURED_OUTPUT_LIMIT_BYTES", str(8 * 1024 * 1024)))
KUBECTL_ROOT = Path(os.getenv("HERMES_KUBECTL_ROOT", "/opt/hermes/kubectl"))
KUBECTL_BOOTSTRAP = os.getenv("HERMES_KUBECTL_BOOTSTRAP", "/usr/local/bin/kubectl")
KUBECTL_SELECTION_MODE = os.getenv("HERMES_KUBECTL_SELECTION_MODE", "exact-preferred").strip().lower()
DYNAMIC_KUBECTL_ENABLED = os.getenv("HERMES_DYNAMIC_KUBECTL_ENABLED", "true").lower() == "true" and KUBECTL_ROOT.is_dir()
KUBECTL_CACHE_TTL = int(os.getenv("HERMES_KUBECTL_CACHE_TTL_SECONDS", "10"))
_TOOLCHAIN_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_TOOLCHAIN_LOCK = threading.Lock()
_USED_TICKETS: set[str] = set()
_USED_LOCK = threading.Lock()

SAFE_MANIFEST_KINDS = {
    "ConfigMap", "CronJob", "DaemonSet", "Deployment", "HorizontalPodAutoscaler",
    "Ingress", "Job", "Namespace", "PersistentVolumeClaim", "Service", "ServiceAccount",
    "StatefulSet",
}
DENIED_KINDS = {
    "Secret", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "CertificateSigningRequest", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "CustomResourceDefinition",
}
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
CRED_FILE_RE = re.compile(r"^cred_[0-9a-f]{16}\.ya?ml$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BrokerPlanRequest(StrictModel):
    plan: dict[str, Any]


class DiscoveryRequest(StrictModel):
    target_snapshot: dict[str, Any]


class ExecuteRequest(StrictModel):
    ticket: dict[str, Any]
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class Day2PreviewRequest(StrictModel):
    target_snapshot: dict[str, Any]
    operation: str = Field(min_length=1, max_length=160)
    parameters: dict[str, Any]


class HubbleCollectRequest(StrictModel):
    target_snapshot: dict[str, Any]
    last: int = Field(default=50, ge=1, le=200)
    since_seconds: int | None = Field(default=None, ge=1, le=3600)


class DiagnosticsRunRequest(StrictModel):
    target_snapshot: dict[str, Any]
    checks: list[str] = Field(default_factory=list, max_length=32)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _require_token(authorization: str | None) -> None:
    if not TOKEN:
        raise HTTPException(503, "broker token not configured")
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "invalid broker token")


def _target(plan_or_snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot = plan_or_snapshot.get("target_snapshot", plan_or_snapshot)
    if snapshot.get("kind") != "kubernetes":
        raise HTTPException(422, "target snapshot is not kubernetes")
    return snapshot


def _kubeconfig_for(snapshot: dict[str, Any]) -> Path | None:
    mode = snapshot.get("connection_mode", "direct")
    if mode == "agent" or snapshot.get("scope", {}).get("in_cluster") is True:
        return None
    cred = snapshot.get("credential_snapshot") or {}
    if cred.get("kind") != "kubeconfig":
        raise HTTPException(422, "direct Kubernetes targets require a kubeconfig credential reference")
    metadata = cred.get("metadata") or {}
    filename = str(metadata.get("file") or "")
    if not CRED_FILE_RE.fullmatch(filename):
        raise HTTPException(422, "credential metadata does not contain a valid local kubeconfig file")
    path = CREDENTIAL_ROOT / filename
    try:
        resolved = path.resolve(strict=True)
        root = CREDENTIAL_ROOT.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(409, "kubeconfig material is not available to Kubernetes Broker") from exc
    if root not in resolved.parents:
        raise HTTPException(422, "invalid kubeconfig path")
    expected = str(metadata.get("sha256") or "")
    try:
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except PermissionError as exc:
        raise HTTPException(
            409,
            "kubeconfig material is not readable by Kubernetes Broker"
        ) from exc
    except OSError as exc:
        raise HTTPException(
            409,
            f"kubeconfig material could not be read: {type(exc).__name__}"
        ) from exc
    if not expected or not hmac.compare_digest(expected, actual):
        raise HTTPException(409, "kubeconfig fingerprint does not match approved target snapshot")
    return resolved


def _env(snapshot: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    kubeconfig = _kubeconfig_for(snapshot)
    if kubeconfig is not None:
        env["KUBECONFIG"] = str(kubeconfig)
    else:
        env.pop("KUBECONFIG", None)
    return env


def _minor_from_version(value: str) -> int:
    match = re.match(r"^v?1\.(\d+)(?:\.|$)", str(value or ""))
    if not match:
        raise HTTPException(502, f"could not parse Kubernetes version {value!r}")
    return int(match.group(1))


def _kubectl_inventory() -> dict[int, Path]:
    inventory: dict[int, Path] = {}
    if not KUBECTL_ROOT.is_dir():
        return inventory
    for child in KUBECTL_ROOT.iterdir():
        if not child.is_dir() or not re.fullmatch(r"1\.\d+", child.name):
            continue
        binary = child / "kubectl"
        if binary.is_file() and os.access(binary, os.X_OK):
            inventory[int(child.name.split(".", 1)[1])] = binary
    return inventory


def _probe_server_version(snapshot: dict[str, Any]) -> str:
    bootstrap = Path(KUBECTL_BOOTSTRAP)
    if not bootstrap.is_file():
        fallback = shutil.which("kubectl")
        if not fallback:
            raise HTTPException(503, "no kubectl bootstrap binary is available")
        bootstrap = Path(fallback)
    try:
        proc = subprocess.run(
            [str(bootstrap), "version", "-o", "json"],
            text=True,
            capture_output=True,
            env=_env(snapshot),
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, f"kubectl version probe timed out after {COMMAND_TIMEOUT}s") from exc
    if proc.returncode != 0:
        output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        raise HTTPException(422, {"message": "Kubernetes version probe failed", "returncode": proc.returncode, "output": output[-100_000:]})
    try:
        data = json.loads(proc.stdout or "")
        return str((data.get("serverVersion") or {}).get("gitVersion") or "")
    except json.JSONDecodeError as exc:
        raise HTTPException(502, "kubectl version probe returned invalid JSON") from exc


def _kubectl_toolchain(snapshot: dict[str, Any], *, refresh: bool = False) -> dict[str, Any] | None:
    if not DYNAMIC_KUBECTL_ENABLED:
        return None
    cache_key = str(snapshot.get("snapshot_hash") or sha256_hex(snapshot))
    now = time.monotonic()
    with _TOOLCHAIN_LOCK:
        cached = _TOOLCHAIN_CACHE.get(cache_key)
        if cached and not refresh and now - cached[0] <= KUBECTL_CACHE_TTL:
            return dict(cached[1])

    inventory = _kubectl_inventory()
    if not inventory:
        raise HTTPException(503, "dynamic kubectl is enabled but no versioned kubectl binaries are installed")
    server_version = _probe_server_version(snapshot)
    server_minor = _minor_from_version(server_version)
    compatible = sorted((minor for minor in inventory if abs(minor - server_minor) <= 1), key=lambda m: (m != server_minor, abs(m - server_minor), m > server_minor, m))
    if KUBECTL_SELECTION_MODE == "exact" and server_minor not in inventory:
        raise HTTPException(409, f"no exact kubectl 1.{server_minor} binary is installed for Kubernetes {server_version}")
    if not compatible:
        available = ", ".join(f"1.{x}" for x in sorted(inventory)) or "none"
        raise HTTPException(409, f"no compatible kubectl is installed for Kubernetes {server_version}; installed minors: {available}")
    chosen_minor = server_minor if server_minor in inventory else compatible[0]
    binary = inventory[chosen_minor]
    try:
        proc = subprocess.run([str(binary), "version", "--client", "-o", "json"], text=True, capture_output=True, timeout=COMMAND_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "selected kubectl client version probe timed out") from exc
    if proc.returncode != 0:
        raise HTTPException(503, f"selected kubectl 1.{chosen_minor} is not runnable")
    try:
        client_version = str((json.loads(proc.stdout or "").get("clientVersion") or {}).get("gitVersion") or "")
    except json.JSONDecodeError as exc:
        raise HTTPException(503, "selected kubectl returned invalid client version JSON") from exc
    client_minor = _minor_from_version(client_version)
    if abs(client_minor - server_minor) > 1:
        raise HTTPException(409, f"selected kubectl {client_version} is outside supported skew for Kubernetes {server_version}")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    result = {
        "kind": "kubectl",
        "path": str(binary),
        "client_version": client_version,
        "client_minor": client_minor,
        "server_version": server_version,
        "server_minor": server_minor,
        "binary_sha256": digest,
        "selection_mode": KUBECTL_SELECTION_MODE,
    }
    result["binding_hash"] = sha256_hex({k: v for k, v in result.items() if k not in {"path", "binding_hash"}})
    with _TOOLCHAIN_LOCK:
        _TOOLCHAIN_CACHE[cache_key] = (time.monotonic(), dict(result))
    return result


def _resolve_command(args: list[str], snapshot: dict[str, Any]) -> list[str]:
    if args and args[0] == "kubectl":
        toolchain = _kubectl_toolchain(snapshot)
        if toolchain:
            return [str(toolchain["path"]), *args[1:]]
    return args


def _run(args: list[str], snapshot: dict[str, Any], stdin: str | None = None, timeout: int | None = None, allowed_codes: set[int] | None = None) -> dict[str, Any]:
    allowed = allowed_codes or {0}
    started = time.monotonic()
    try:
        proc = subprocess.run(
            _resolve_command(args, snapshot),
            input=stdin,
            text=True,
            capture_output=True,
            env=_env(snapshot),
            timeout=timeout or COMMAND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, f"command timed out after {timeout or COMMAND_TIMEOUT}s") from exc
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    output = output[-100_000:]
    result = {"returncode": proc.returncode, "output": output, "duration": round(time.monotonic() - started, 3)}
    if proc.returncode not in allowed:
        raise HTTPException(422, {"message": "Kubernetes command failed", **result})
    return result


def _run_json(args: list[str], snapshot: dict[str, Any], timeout: int | None = None) -> Any:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            _resolve_command(args, snapshot),
            text=True,
            capture_output=True,
            env=_env(snapshot),
            timeout=timeout or COMMAND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, f"command timed out after {timeout or COMMAND_TIMEOUT}s") from exc

    if proc.returncode != 0:
        output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        result = {
            "returncode": proc.returncode,
            "output": output[-100_000:],
            "duration": round(time.monotonic() - started, 3),
        }
        raise HTTPException(422, {"message": "Kubernetes command failed", **result})

    stdout = proc.stdout or ""
    stdout_bytes = len(stdout.encode("utf-8", errors="replace"))
    if stdout_bytes > STRUCTURED_OUTPUT_LIMIT:
        raise HTTPException(502, f"structured Kubernetes command output exceeds {STRUCTURED_OUTPUT_LIMIT} bytes")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        stderr_tail = (proc.stderr or "")[-4_000:]
        detail = "Kubernetes command returned invalid JSON on stdout"
        if stderr_tail:
            detail += f"; stderr: {stderr_tail}"
        raise HTTPException(502, detail) from exc


def _namespace(value: Any) -> str:
    ns = str(value or "default").lower()
    if not NAME_RE.fullmatch(ns):
        raise HTTPException(422, "invalid Kubernetes namespace")
    return ns


def _release(value: Any) -> str:
    release = str(value or "")
    if not NAME_RE.fullmatch(release):
        raise HTTPException(422, "invalid Helm release name")
    return release


def _scope(snapshot: dict[str, Any]) -> dict[str, Any]:
    value = snapshot.get("scope") or {}
    if not isinstance(value, dict):
        raise HTTPException(422, "target scope must be an object")
    return value


def _enforce_namespace(snapshot: dict[str, Any], namespace: str) -> None:
    scope = _scope(snapshot)
    deny = {str(x).lower() for x in (scope.get("namespace_denylist") or [])}
    allow = {str(x).lower() for x in (scope.get("namespace_allowlist") or [])}
    if namespace in deny or "*" in deny:
        raise HTTPException(403, f"namespace {namespace} is denied by target policy")
    if allow and "*" not in allow and namespace not in allow:
        raise HTTPException(403, f"namespace {namespace} is outside the target allowlist")


def _enforce_manifest_scope(snapshot: dict[str, Any], docs: list[dict[str, Any]], default_namespace: str) -> None:
    scope = _scope(snapshot)
    allow_kinds = {str(x) for x in (scope.get("kind_allowlist") or [])}
    deny_kinds = {str(x) for x in (scope.get("kind_denylist") or [])}
    cluster_scoped_allowed = bool(scope.get("allow_cluster_scoped", False))
    for doc in docs:
        kind = str(doc.get("kind") or "")
        if kind in deny_kinds or "*" in deny_kinds:
            raise HTTPException(403, f"{kind} is denied by target resource policy")
        if allow_kinds and "*" not in allow_kinds and kind not in allow_kinds:
            raise HTTPException(403, f"{kind} is outside the target resource allowlist")
        if kind == "Namespace" and not cluster_scoped_allowed:
            raise HTTPException(403, "Namespace changes require scope.allow_cluster_scoped=true")
        metadata = doc.get("metadata") or {}
        ns = str(metadata.get("namespace") or default_namespace).lower()
        if kind != "Namespace":
            _enforce_namespace(snapshot, _namespace(ns))


def _validate_helm_chart(value: Any) -> str:
    chart = str(value or "").strip()
    if not chart or len(chart) > 500 or "\x00" in chart or chart.startswith("-"):
        raise HTTPException(422, "invalid Helm chart reference")
    return chart


def _validate_helm_version(value: Any) -> str:
    version = str(value or "").strip()
    if version.startswith("-") or "\x00" in version or len(version) > 128:
        raise HTTPException(422, "invalid Helm chart version")
    return version


def _manifest_docs(manifest: str) -> list[dict[str, Any]]:
    if len(manifest.encode()) > 512_000:
        raise HTTPException(413, "manifest exceeds 512 KiB beta limit")
    try:
        docs = [doc for doc in yaml.safe_load_all(manifest) if doc]
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"invalid YAML: {exc}") from exc
    if not docs:
        raise HTTPException(422, "manifest is empty")
    for doc in docs:
        if not isinstance(doc, dict):
            raise HTTPException(422, "each YAML document must be an object")
        kind = str(doc.get("kind") or "")
        if kind in DENIED_KINDS:
            raise HTTPException(403, f"{kind} is denied by the beta.1 safety floor")
        if kind not in SAFE_MANIFEST_KINDS:
            raise HTTPException(403, f"{kind or 'unknown kind'} is not in the beta.1 manifest allowlist")
    return docs


def _resource_ref(doc: dict[str, Any], default_namespace: str) -> dict[str, Any]:
    metadata = doc.get("metadata") or {}
    name = str(metadata.get("name") or "")
    kind = str(doc.get("kind") or "")
    api_version = str(doc.get("apiVersion") or "")
    if not name or not NAME_RE.fullmatch(name.lower()):
        raise HTTPException(422, f"invalid resource name for {kind or 'resource'}")
    namespace = None if kind == "Namespace" else _namespace(metadata.get("namespace") or default_namespace)
    return {"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}


def _normalized_live_manifest(raw: str) -> dict[str, Any] | None:
    if not raw.strip():
        return None
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise HTTPException(502, f"could not normalize live Kubernetes object: {exc}") from exc
    if not isinstance(doc, dict):
        return None
    doc.pop("status", None)
    metadata = doc.get("metadata") or {}
    for key in ("managedFields", "resourceVersion", "uid", "creationTimestamp", "generation", "selfLink"):
        metadata.pop(key, None)
    doc["metadata"] = metadata
    return doc


def _get_live_resource(snapshot: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    args = ["kubectl", "get", str(ref["kind"]), str(ref["name"])]
    if ref.get("namespace"):
        args += ["-n", str(ref["namespace"])]
    args += ["--ignore-not-found", "-o", "yaml"]
    result = _run(args, snapshot)
    raw = result["output"].strip()
    normalized = _normalized_live_manifest(raw)
    rollback_manifest = yaml.safe_dump(normalized, sort_keys=False).strip() if normalized else None
    return {
        "resource": ref,
        "exists": bool(raw),
        "manifest": rollback_manifest,
        "normalized": normalized,
    }


def _capture_live_state(snapshot: dict[str, Any], refs: list[dict[str, Any]]) -> dict[str, Any]:
    resources = [_get_live_resource(snapshot, ref) for ref in refs]
    normalized = [
        {"resource": x["resource"], "exists": x["exists"], "manifest": x["normalized"]}
        for x in resources
    ]
    return {"resources": resources, "hash": sha256_hex(normalized)}


def _manifest_refs(docs: list[dict[str, Any]], namespace: str) -> list[dict[str, Any]]:
    return [_resource_ref(doc, namespace) for doc in docs]


def _assert_live_precondition(snapshot: dict[str, Any], refs: list[dict[str, Any]], expected: str | None) -> dict[str, Any]:
    state = _capture_live_state(snapshot, refs)
    if expected and not hmac.compare_digest(state["hash"], expected):
        raise HTTPException(409, "live Kubernetes state changed after preview; create and approve a new ChangeSet")
    return state


def _delete_dry_run(snapshot: dict[str, Any], refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for ref in refs:
        args = ["kubectl", "delete", str(ref["kind"]), str(ref["name"]), "--dry-run=server"]
        if ref.get("namespace"):
            args += ["-n", str(ref["namespace"])]
        results.append({"resource": ref, "result": _run(args, snapshot)})
    return results


def _manifest_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    manifest = str(params.get("manifest") or "")
    docs = _manifest_docs(manifest)
    namespace = _namespace(params.get("namespace"))
    _enforce_namespace(snapshot, namespace)
    _enforce_manifest_scope(snapshot, docs, namespace)
    refs = _manifest_refs(docs, namespace)
    before = _capture_live_state(snapshot, refs)
    dry = _run([
        "kubectl", "apply", "--server-side", "--dry-run=server", "--field-manager=hermes-control-plane",
        "-n", namespace, "-f", "-", "-o", "yaml"
    ], snapshot, manifest)
    diff = _run([
        "kubectl", "diff", "--server-side", "--field-manager=hermes-control-plane", "-n", namespace, "-f", "-"
    ], snapshot, manifest, allowed_codes={0, 1})
    return {
        "kind": "kubernetes-manifest",
        "summary": f"Server-side dry-run passed for {len(refs)} resource(s) in namespace {namespace}",
        "resources": refs,
        "before_state": before,
        "live_state_hash": before["hash"],
        "dry_run": dry,
        "diff": diff,
        "secret_output_suppressed": True,
    }


def _manifest_delete_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    manifest = str(params.get("manifest") or "")
    docs = _manifest_docs(manifest)
    namespace = _namespace(params.get("namespace"))
    _enforce_namespace(snapshot, namespace)
    _enforce_manifest_scope(snapshot, docs, namespace)
    refs = _manifest_refs(docs, namespace)
    before = _capture_live_state(snapshot, refs)
    missing = [x["resource"] for x in before["resources"] if not x["exists"]]
    if missing:
        raise HTTPException(409, {"message": "delete target does not exist", "resources": missing})
    dry = _delete_dry_run(snapshot, refs)
    return {
        "kind": "kubernetes-delete",
        "summary": f"Server-side delete dry-run passed for {len(refs)} resource(s)",
        "resources": refs,
        "before_state": before,
        "live_state_hash": before["hash"],
        "dry_run": dry,
        "secret_output_suppressed": True,
    }


def _rollback_actions(plan: dict[str, Any]) -> tuple[dict[str, Any], str, list[dict[str, Any]], list[dict[str, Any]]]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    namespace = _namespace(params.get("namespace"))
    _enforce_namespace(snapshot, namespace)
    actions = params.get("actions") or []
    if not isinstance(actions, list) or not actions:
        raise HTTPException(422, "rollback actions are missing")
    validated = []
    refs = []
    for action in actions:
        if not isinstance(action, dict) or action.get("action") not in {"apply", "delete"}:
            raise HTTPException(422, "invalid rollback action")
        if action["action"] == "apply":
            manifest = str(action.get("manifest") or "")
            docs = _manifest_docs(manifest)
            _enforce_manifest_scope(snapshot, docs, namespace)
            if len(docs) != 1:
                raise HTTPException(422, "each rollback apply action must contain exactly one resource")
            ref = _resource_ref(docs[0], namespace)
            validated.append({"action": "apply", "resource": ref, "manifest": manifest})
            refs.append(ref)
        else:
            ref = action.get("resource") or {}
            kind = str(ref.get("kind") or "")
            name = str(ref.get("name") or "")
            if kind in DENIED_KINDS or kind not in SAFE_MANIFEST_KINDS:
                raise HTTPException(403, f"{kind or 'unknown kind'} is not eligible for rollback delete")
            fake = {"apiVersion": ref.get("apiVersion") or "v1", "kind": kind, "metadata": {"name": name}}
            if ref.get("namespace"):
                fake["metadata"]["namespace"] = ref["namespace"]
            _enforce_manifest_scope(snapshot, [fake], namespace)
            safe_ref = _resource_ref(fake, namespace)
            validated.append({"action": "delete", "resource": safe_ref})
            refs.append(safe_ref)
    return snapshot, namespace, validated, refs


def _manifest_rollback_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot, namespace, actions, refs = _rollback_actions(plan)
    current = _capture_live_state(snapshot, refs)
    previews = []
    for action in actions:
        if action["action"] == "apply":
            manifest = action["manifest"]
            dry = _run([
                "kubectl", "apply", "--server-side", "--dry-run=server", "--field-manager=hermes-control-plane",
                "-n", namespace, "-f", "-", "-o", "yaml"
            ], snapshot, manifest)
            diff = _run([
                "kubectl", "diff", "--server-side", "--field-manager=hermes-control-plane", "-n", namespace, "-f", "-"
            ], snapshot, manifest, allowed_codes={0, 1})
            previews.append({"action": "apply", "resource": action["resource"], "dry_run": dry, "diff": diff})
        else:
            previews.extend({"action": "delete", **x} for x in _delete_dry_run(snapshot, [action["resource"]]))
    return {
        "kind": "kubernetes-rollback",
        "summary": f"Rollback preview passed for {len(actions)} resource action(s)",
        "actions": previews,
        "live_state": current,
        "live_state_hash": current["hash"],
        "secret_output_suppressed": True,
    }



def _helm_values_file(values_yaml: str):
    handle = tempfile.NamedTemporaryFile("w", prefix="hermes-values-", suffix=".yaml", delete=False)
    try:
        handle.write(values_yaml)
        handle.flush()
        os.chmod(handle.name, 0o600)
    finally:
        handle.close()
    return Path(handle.name)


def _helm_base(params: dict[str, Any]) -> tuple[str, str, str, list[str]]:
    release = _release(params.get("release"))
    chart = _validate_helm_chart(params.get("chart"))
    namespace = _namespace(params.get("namespace"))
    args = ["helm", "upgrade", "--install", release, chart, "--namespace", namespace]
    version = _validate_helm_version(params.get("version"))
    if version:
        args += ["--version", version]
    if params.get("create_namespace", True):
        args.append("--create-namespace")
    return release, chart, namespace, args


def _parsed_json(result: dict[str, Any], fallback: Any) -> Any:
    try:
        return json.loads(result.get("output") or "")
    except (json.JSONDecodeError, TypeError):
        return fallback


def _helm_release_snapshot(snapshot: dict[str, Any], release: str, namespace: str) -> dict[str, Any]:
    listed = _run(["helm", "list", "--namespace", namespace, "--filter", f"^{re.escape(release)}$", "-o", "json"], snapshot)
    items = _parsed_json(listed, [])
    if not isinstance(items, list) or not items:
        return {"exists": False, "release": release, "namespace": namespace, "revision": None}
    status_result = _run(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
    status = _parsed_json(status_result, {"raw": status_result.get("output", "")})
    revision = None
    try:
        revision = int((items[0] or {}).get("revision") or 0) or None
    except (TypeError, ValueError):
        pass
    return {"exists": True, "release": release, "namespace": namespace, "revision": revision, "status": status}


def _helm_snapshot_hash(value: dict[str, Any]) -> str:
    # Status may contain timestamps. Bind approval to stable release identity/revision/status.
    stable = {
        "exists": value.get("exists"),
        "release": value.get("release"),
        "namespace": value.get("namespace"),
        "revision": value.get("revision"),
        "status": ((value.get("status") or {}).get("info") or {}).get("status") if isinstance(value.get("status"), dict) else None,
    }
    return sha256_hex(stable)


def _assert_helm_precondition(snapshot: dict[str, Any], release: str, namespace: str, expected: str | None) -> dict[str, Any]:
    current = _helm_release_snapshot(snapshot, release, namespace)
    if expected and not hmac.compare_digest(_helm_snapshot_hash(current), expected):
        raise HTTPException(409, "Helm release changed after preview; create and approve a new ChangeSet")
    return current


def _helm_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    release, chart, namespace, args = _helm_base(params)
    _enforce_namespace(snapshot, namespace)
    before = _helm_release_snapshot(snapshot, release, namespace)
    values_path = None
    try:
        values_yaml = str(params.get("values_yaml") or "")
        if values_yaml:
            if len(values_yaml.encode()) > 256_000:
                raise HTTPException(413, "Helm values exceed 256 KiB beta limit")
            values_path = _helm_values_file(values_yaml)
            args += ["-f", str(values_path)]
        result = _run(args + ["--dry-run=server", "--hide-secret"], snapshot, timeout=max(COMMAND_TIMEOUT, 120))
        return {
            "kind": "helm",
            "summary": f"Helm server dry-run passed for release {release} in namespace {namespace}",
            "release": release,
            "chart": chart,
            "namespace": namespace,
            "release_snapshot": before,
            "release_snapshot_hash": _helm_snapshot_hash(before),
            "dry_run": result,
            "secret_output_suppressed": True,
        }
    finally:
        if values_path:
            values_path.unlink(missing_ok=True)


def _helm_rollback_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    p = plan.get("parameters") or {}
    release = _release(p.get("release"))
    namespace = _namespace(p.get("namespace"))
    revision = int(p.get("revision") or 0)
    _enforce_namespace(snapshot, namespace)
    if revision < 1:
        raise HTTPException(422, "rollback revision must be >= 1")
    before = _helm_release_snapshot(snapshot, release, namespace)
    if not before.get("exists"):
        raise HTTPException(409, "Helm release does not exist")
    history_result = _run(["helm", "history", release, "--namespace", namespace, "-o", "json"], snapshot)
    history = _parsed_json(history_result, [])
    revisions = {int(x.get("revision") or 0) for x in history if isinstance(x, dict)} if isinstance(history, list) else set()
    if revision not in revisions:
        raise HTTPException(409, f"Helm revision {revision} does not exist for release {release}")
    return {
        "kind": "helm-rollback",
        "summary": f"Rollback plan for {release} to revision {revision}",
        "history": history,
        "release_snapshot": before,
        "release_snapshot_hash": _helm_snapshot_hash(before),
        "secret_output_suppressed": True,
    }


def _helm_uninstall_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    p = plan.get("parameters") or {}
    release = _release(p.get("release"))
    namespace = _namespace(p.get("namespace"))
    _enforce_namespace(snapshot, namespace)
    before = _helm_release_snapshot(snapshot, release, namespace)
    if not before.get("exists"):
        raise HTTPException(409, "Helm release does not exist")
    return {
        "kind": "helm-uninstall",
        "summary": f"Helm uninstall plan for release {release} in namespace {namespace}",
        "release_snapshot": before,
        "release_snapshot_hash": _helm_snapshot_hash(before),
        "secret_output_suppressed": True,
    }



def preview(plan: dict[str, Any]) -> dict[str, Any]:
    operation = str(plan.get("operation") or "")
    if sha256_hex(plan) != str(plan.get("plan_hash", sha256_hex(plan))):
        raise HTTPException(409, "embedded plan hash mismatch")
    if operation == "kubernetes.manifest.apply":
        return _manifest_preview(plan)
    if operation == "kubernetes.manifest.delete":
        return _manifest_delete_preview(plan)
    if operation == "kubernetes.manifest.rollback":
        return _manifest_rollback_preview(plan)
    if operation in {"helm.install", "helm.upgrade"}:
        return _helm_preview(plan)
    if operation == "helm.rollback":
        return _helm_rollback_preview(plan)
    if operation == "helm.uninstall":
        return _helm_uninstall_preview(plan)
    raise HTTPException(422, f"unsupported beta.1 operation: {operation}")



def _verify_ticket(ticket: dict[str, Any], signature: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not EXECUTION_KEY:
        raise HTTPException(503, "execution signing key not configured")
    expected = hmac.new(EXECUTION_KEY.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "invalid execution ticket signature")
    if int(ticket.get("expires_at") or 0) < int(time.time()):
        raise HTTPException(409, "execution ticket expired")
    with _USED_LOCK:
        if signature in _USED_TICKETS:
            raise HTTPException(409, "execution ticket has already been used")
        _USED_TICKETS.add(signature)
    plan = ticket.get("plan")
    if not isinstance(plan, dict):
        raise HTTPException(422, "execution ticket has no plan")
    if sha256_hex(plan) != ticket.get("plan_hash"):
        raise HTTPException(409, "execution ticket plan hash mismatch")
    preconditions = ticket.get("preconditions") or {}
    if not isinstance(preconditions, dict):
        raise HTTPException(422, "execution ticket preconditions are invalid")
    return plan, preconditions


def _verify_workload_rollouts(snapshot: dict[str, Any], refs: list[dict[str, Any]], timeout: str) -> list[dict[str, Any]]:
    checks = []
    for ref in refs:
        kind = str(ref.get("kind") or "")
        name = str(ref.get("name") or "")
        namespace = ref.get("namespace")
        if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
            args = ["kubectl", "rollout", "status", f"{kind.lower()}/{name}", f"--timeout={timeout}"]
            if namespace:
                args += ["-n", str(namespace)]
            checks.append({"resource": ref, "result": _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))})
        elif kind == "Job":
            args = ["kubectl", "wait", "--for=condition=complete", f"job/{name}", f"--timeout={timeout}"]
            if namespace:
                args += ["-n", str(namespace)]
            checks.append({"resource": ref, "result": _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))})
    return checks


def _apply_manifest(snapshot: dict[str, Any], manifest: str, namespace: str, docs: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    result = _run(
        ["kubectl", "apply", "--server-side", "--field-manager=hermes-control-plane", "-n", namespace, "-f", "-", "-o", "name"],
        snapshot,
        manifest,
        timeout=max(COMMAND_TIMEOUT, 120),
    )
    convergence = _run(
        ["kubectl", "diff", "--server-side", "--field-manager=hermes-control-plane", "-n", namespace, "-f", "-"],
        snapshot,
        manifest,
        timeout=max(COMMAND_TIMEOUT, 120),
        allowed_codes={0},
    )
    refs = _manifest_refs(docs, namespace)
    rollout_timeout = "5m"
    rollouts = _verify_workload_rollouts(snapshot, refs, rollout_timeout)
    return result, {
        "converged": True,
        "method": "kubectl-diff",
        "diff": convergence,
        "resources": refs,
        "rollouts": rollouts,
    }


def _execute_plan(plan: dict[str, Any], preconditions: dict[str, Any] | None = None) -> dict[str, Any]:
    preconditions = preconditions or {}
    snapshot = _target(plan)
    operation = str(plan.get("operation") or "")
    params = plan.get("parameters") or {}
    if operation == "kubernetes.manifest.apply":
        manifest = str(params.get("manifest") or "")
        docs = _manifest_docs(manifest)
        ns = _namespace(params.get("namespace"))
        _enforce_namespace(snapshot, ns)
        _enforce_manifest_scope(snapshot, docs, ns)
        refs = _manifest_refs(docs, ns)
        before = _assert_live_precondition(snapshot, refs, preconditions.get("live_state_hash"))
        result, verification = _apply_manifest(snapshot, manifest, ns, docs)
        return {"operation": operation, "before_state": before, "result": result, "verification": verification}

    if operation == "kubernetes.manifest.delete":
        manifest = str(params.get("manifest") or "")
        docs = _manifest_docs(manifest)
        ns = _namespace(params.get("namespace"))
        _enforce_namespace(snapshot, ns)
        _enforce_manifest_scope(snapshot, docs, ns)
        refs = _manifest_refs(docs, ns)
        before = _assert_live_precondition(snapshot, refs, preconditions.get("live_state_hash"))
        if any(not x["exists"] for x in before["resources"]):
            raise HTTPException(409, "one or more delete targets disappeared after preview")
        results = []
        for ref in refs:
            args = ["kubectl", "delete", str(ref["kind"]), str(ref["name"]), "--wait=true", "--timeout=2m"]
            if ref.get("namespace"):
                args += ["-n", str(ref["namespace"])]
            results.append({"resource": ref, "result": _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 180))})
        after = _capture_live_state(snapshot, refs)
        if any(x["exists"] for x in after["resources"]):
            raise HTTPException(502, "delete verification failed; one or more resources still exist")
        return {"operation": operation, "before_state": before, "result": results, "verification": {"deleted": True, "resources": refs}}

    if operation == "kubernetes.manifest.rollback":
        snapshot, ns, actions, refs = _rollback_actions(plan)
        before = _assert_live_precondition(snapshot, refs, preconditions.get("live_state_hash"))
        results = []
        for action in actions:
            if action["action"] == "apply":
                manifest = action["manifest"]
                docs = _manifest_docs(manifest)
                result, verification = _apply_manifest(snapshot, manifest, ns, docs)
                results.append({"action": "apply", "resource": action["resource"], "result": result, "verification": verification})
            else:
                ref = action["resource"]
                live = _get_live_resource(snapshot, ref)
                if live["exists"]:
                    args = ["kubectl", "delete", str(ref["kind"]), str(ref["name"]), "--wait=true", "--timeout=2m"]
                    if ref.get("namespace"):
                        args += ["-n", str(ref["namespace"])]
                    result = _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 180))
                else:
                    result = {"returncode": 0, "output": "already absent", "duration": 0.0}
                results.append({"action": "delete", "resource": ref, "result": result})
        return {"operation": operation, "before_state": before, "result": results, "verification": {"rollback_completed": True, "resources": refs}}

    if operation in {"helm.install", "helm.upgrade"}:
        release, chart, namespace, args = _helm_base(params)
        _enforce_namespace(snapshot, namespace)
        before = _assert_helm_precondition(snapshot, release, namespace, preconditions.get("release_snapshot_hash"))
        values_path = None
        try:
            values_yaml = str(params.get("values_yaml") or "")
            if values_yaml:
                values_path = _helm_values_file(values_yaml)
                args += ["-f", str(values_path)]
            args += ["--wait", "--timeout", str(params.get("timeout", "5m"))]
            result = _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))
            status_result = _run(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
            status = _parsed_json(status_result, {"raw": status_result.get("output", "")})
            state = str(((status.get("info") or {}).get("status") if isinstance(status, dict) else "") or "").lower()
            if state and state != "deployed":
                raise HTTPException(502, f"Helm release verification returned status {state}")
            history_result = _run(["helm", "history", release, "--namespace", namespace, "-o", "json"], snapshot)
            return {
                "operation": operation,
                "before_release": before,
                "result": result,
                "verification": {"status": status, "history": _parsed_json(history_result, [])},
            }
        finally:
            if values_path:
                values_path.unlink(missing_ok=True)

    if operation == "helm.rollback":
        release = _release(params.get("release"))
        namespace = _namespace(params.get("namespace"))
        revision = int(params.get("revision") or 0)
        _enforce_namespace(snapshot, namespace)
        if revision < 1:
            raise HTTPException(422, "rollback revision must be >= 1")
        before = _assert_helm_precondition(snapshot, release, namespace, preconditions.get("release_snapshot_hash"))
        result = _run(["helm", "rollback", release, str(revision), "--namespace", namespace, "--wait"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        status_result = _run(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
        return {"operation": operation, "before_release": before, "result": result, "verification": {"status": _parsed_json(status_result, {})}}

    if operation == "helm.uninstall":
        release = _release(params.get("release"))
        namespace = _namespace(params.get("namespace"))
        _enforce_namespace(snapshot, namespace)
        before = _assert_helm_precondition(snapshot, release, namespace, preconditions.get("release_snapshot_hash"))
        if not before.get("exists"):
            raise HTTPException(409, "Helm release disappeared after preview")
        result = _run(["helm", "uninstall", release, "--namespace", namespace, "--wait", "--timeout", "5m"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        after = _helm_release_snapshot(snapshot, release, namespace)
        if after.get("exists"):
            raise HTTPException(502, "Helm uninstall verification failed; release still exists")
        return {"operation": operation, "before_release": before, "result": result, "verification": {"uninstalled": True}}

    raise HTTPException(422, f"unsupported beta.1 operation: {operation}")


app = FastAPI(title="Hermes Kubernetes Broker", version=VERSION)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-kubernetes-broker",
        "version": VERSION,
        "execution_enabled": EXECUTION_ENABLED,
        "kubectl": bool(_kubectl_inventory()) if DYNAMIC_KUBECTL_ENABLED else subprocess.run(["kubectl", "version", "--client", "-o", "json"], capture_output=True, text=True).returncode == 0,
        "dynamic_kubectl": DYNAMIC_KUBECTL_ENABLED,
        "kubectl_minors": [f"1.{x}" for x in sorted(_kubectl_inventory())] if DYNAMIC_KUBECTL_ENABLED else [],
        "helm": subprocess.run(["helm", "version", "--short"], capture_output=True, text=True).returncode == 0,
        "hubble": shutil.which("hubble") is not None,
    }


@app.post("/v1/discover")
def discover(payload: DiscoveryRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    snapshot = _target(payload.target_snapshot)
    version = _run_json(["kubectl", "version", "-o", "json"], snapshot)
    scope = _scope(snapshot)
    allow = [str(x).lower() for x in (scope.get("namespace_allowlist") or []) if str(x).strip()]
    deny = {str(x).lower() for x in (scope.get("namespace_denylist") or [])}

    if allow and "*" not in allow:
        namespace_items = []
        workload_items = []
        for ns in allow:
            _enforce_namespace(snapshot, _namespace(ns))
            namespace_items.append(_run_json(["kubectl", "get", "namespace", ns, "-o", "json"], snapshot))
            workloads_result = _run_json(["kubectl", "get", "deployments,statefulsets,daemonsets", "-n", ns, "-o", "json"], snapshot)
            workload_items.extend(workloads_result.get("items", []))
        namespaces = {"items": namespace_items, "policy_scoped": True}
        workloads = {"items": workload_items, "policy_scoped": True}
    else:
        namespaces = _run_json(["kubectl", "get", "namespaces", "-o", "json"], snapshot)
        if deny:
            namespaces["items"] = [x for x in namespaces.get("items", []) if str((x.get("metadata") or {}).get("name", "")).lower() not in deny]
        workloads = _run_json(["kubectl", "get", "deployments,statefulsets,daemonsets", "-A", "-o", "json"], snapshot)
        if deny:
            workloads["items"] = [x for x in workloads.get("items", []) if str((x.get("metadata") or {}).get("namespace", "")).lower() not in deny]

    nodes = None
    if bool(scope.get("cluster_read", False)):
        nodes = _run_json(["kubectl", "get", "nodes", "-o", "json"], snapshot)
    toolchain = _kubectl_toolchain(snapshot)
    return {"version": version, "namespaces": namespaces, "nodes": nodes, "workloads": workloads, "policy_scope": scope, "secret_data_requested": False, "toolchain": toolchain}



def _diagnostic_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return f"collector HTTP {exc.status_code}"
    return f"collector {type(exc).__name__}"


def _diagnostic_scoped_list(snapshot: dict[str, Any], resource: str, *, cluster_scoped: bool = False, optional: bool = False) -> dict[str, Any]:
    scope = _scope(snapshot)
    if cluster_scoped:
        if not bool(scope.get("cluster_read", False)):
            return {"items": [], "error": "cluster_read target scope required"}
        try:
            data = _run_json(["kubectl", "get", resource, "-o", "json"], snapshot)
            return {"items": list((data or {}).get("items") or [])}
        except HTTPException as exc:
            if optional:
                return {"items": [], "error": _diagnostic_error(exc)}
            raise

    allow = sorted({str(x).lower() for x in (scope.get("namespace_allowlist") or []) if str(x).strip()})
    deny = {str(x).lower() for x in (scope.get("namespace_denylist") or []) if str(x).strip()}
    try:
        if allow and "*" not in allow:
            items: list[dict[str, Any]] = []
            for namespace in allow:
                _enforce_namespace(snapshot, _namespace(namespace))
                data = _run_json(["kubectl", "get", resource, "-n", namespace, "-o", "json"], snapshot)
                items.extend(x for x in ((data or {}).get("items") or []) if isinstance(x, dict))
            return {"items": items}
        data = _run_json(["kubectl", "get", resource, "-A", "-o", "json"], snapshot)
        items = [x for x in ((data or {}).get("items") or []) if isinstance(x, dict)]
        if deny:
            items = [x for x in items if str(((x.get("metadata") or {}).get("namespace") or "")).lower() not in deny]
        return {"items": items}
    except HTTPException as exc:
        return {"items": [], "error": _diagnostic_error(exc)}


def _diagnostic_metrics(snapshot: dict[str, Any], *, nodes: bool = False) -> dict[str, Any]:
    scope = _scope(snapshot)
    try:
        if nodes:
            if not bool(scope.get("cluster_read", False)):
                return {"items": [], "error": "cluster_read target scope required"}
            data = _run_json(["kubectl", "get", "--raw", "/apis/metrics.k8s.io/v1beta1/nodes"], snapshot)
            return {"items": list((data or {}).get("items") or [])}

        allow = sorted({str(x).lower() for x in (scope.get("namespace_allowlist") or []) if str(x).strip()})
        deny = {str(x).lower() for x in (scope.get("namespace_denylist") or []) if str(x).strip()}
        if allow and "*" not in allow:
            items: list[dict[str, Any]] = []
            for namespace in allow:
                _enforce_namespace(snapshot, _namespace(namespace))
                path = f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods"
                data = _run_json(["kubectl", "get", "--raw", path], snapshot)
                items.extend(x for x in ((data or {}).get("items") or []) if isinstance(x, dict))
            return {"items": items}
        data = _run_json(["kubectl", "get", "--raw", "/apis/metrics.k8s.io/v1beta1/pods"], snapshot)
        items = [x for x in ((data or {}).get("items") or []) if isinstance(x, dict)]
        if deny:
            items = [x for x in items if str(((x.get("metadata") or {}).get("namespace") or "")).lower() not in deny]
        return {"items": items}
    except HTTPException as exc:
        return {"items": [], "error": _diagnostic_error(exc)}


def _diagnostic_bundle(snapshot: dict[str, Any], checks: list[str]) -> dict[str, Any]:
    requested = set(checks or diagnostics_provider.DEFAULT_CHECK_IDS)
    unknown = sorted(requested - set(diagnostics_provider.CHECK_IDS))
    if unknown:
        raise HTTPException(422, f"unsupported diagnostic checks: {', '.join(unknown)}")

    bundle: dict[str, Any] = {}
    bundle["nodes"] = _diagnostic_scoped_list(snapshot, "nodes", cluster_scoped=True, optional=True)
    bundle["pods"] = _diagnostic_scoped_list(snapshot, "pods")
    bundle["workloads"] = _diagnostic_scoped_list(snapshot, "deployments,statefulsets,daemonsets")
    bundle["services"] = _diagnostic_scoped_list(snapshot, "services")
    bundle["ingresses"] = _diagnostic_scoped_list(snapshot, "ingresses.networking.k8s.io", optional=True)
    bundle["networkpolicies"] = _diagnostic_scoped_list(snapshot, "networkpolicies.networking.k8s.io", optional=True)
    bundle["events"] = _diagnostic_scoped_list(snapshot, "events")
    bundle["pvcs"] = _diagnostic_scoped_list(snapshot, "persistentvolumeclaims")
    bundle["roles"] = _diagnostic_scoped_list(snapshot, "roles.rbac.authorization.k8s.io", optional=True)
    bundle["clusterroles"] = _diagnostic_scoped_list(snapshot, "clusterroles.rbac.authorization.k8s.io", cluster_scoped=True, optional=True)
    validating = _diagnostic_scoped_list(snapshot, "validatingwebhookconfigurations.admissionregistration.k8s.io", cluster_scoped=True, optional=True)
    mutating = _diagnostic_scoped_list(snapshot, "mutatingwebhookconfigurations.admissionregistration.k8s.io", cluster_scoped=True, optional=True)
    bundle["webhooks"] = {
        "items": [*(validating.get("items") or []), *(mutating.get("items") or [])],
        "error": validating.get("error") or mutating.get("error"),
    }
    bundle["argocd_applications"] = _diagnostic_scoped_list(snapshot, "applications.argoproj.io", optional=True)
    bundle["certificates"] = _diagnostic_scoped_list(snapshot, "certificates.cert-manager.io", optional=True)
    bundle["velero_backups"] = _diagnostic_scoped_list(snapshot, "backups.velero.io", optional=True)
    bundle["metrics_pods"] = _diagnostic_metrics(snapshot)
    bundle["metrics_nodes"] = _diagnostic_metrics(snapshot, nodes=True)

    if requested & {"network.hubble", "network.policy-drops"}:
        try:
            bundle["hubble"] = hubble_provider.collect(snapshot=snapshot, env=_env(snapshot), last=20, since_seconds=60)
        except hubble_provider.HubbleError as exc:
            bundle["hubble"] = {"error": f"HubbleError: {str(exc)[:400]}", "raw_flow_bodies_returned": False}
    else:
        bundle["hubble"] = {"summary": {}, "raw_flow_bodies_returned": False}
    return bundle


@app.post("/v1/diagnostics/run")
def run_diagnostics(payload: DiagnosticsRunRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    snapshot = _target(payload.target_snapshot)
    if snapshot.get("status") not in {None, "configured"}:
        raise HTTPException(409, "Kubernetes target is disabled")
    observed_at = int(time.time())
    bundle = _diagnostic_bundle(snapshot, payload.checks)
    try:
        result = diagnostics_provider.evaluate(bundle=bundle, requested_checks=payload.checks, observed_at=observed_at)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    result["policy_scope"] = {
        "namespace_allowlist": list((_scope(snapshot).get("namespace_allowlist") or [])),
        "namespace_denylist": list((_scope(snapshot).get("namespace_denylist") or [])),
        "cluster_read": bool(_scope(snapshot).get("cluster_read", False)),
    }
    return result


@app.post("/v1/hubble/collect")
def collect_hubble(payload: HubbleCollectRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    snapshot = _target(payload.target_snapshot)
    if snapshot.get("status") not in {None, "configured"}:
        raise HTTPException(409, "Kubernetes target is disabled")
    try:
        return hubble_provider.collect(
            snapshot=snapshot,
            env=_env(snapshot),
            last=payload.last,
            since_seconds=payload.since_seconds,
        )
    except hubble_provider.HubbleError as exc:
        raise HTTPException(502, str(exc)) from exc


KUBERNETES_DAY2_OPERATIONS = {
    "cluster.node.cordon",
    "cluster.node.uncordon",
    "cluster.node.drain",
    "cluster.workload.restart",
    "cluster.workload.scale",
    "cluster.addon.install",
    "cluster.addon.upgrade",
    "cluster.helm.apply",
    "cluster.gitops.sync",
    "cluster.cilium.upgrade",
}


def _day2_typed_plan(changeset_plan: dict[str, Any]) -> dict[str, Any]:
    params = changeset_plan.get("parameters") or {}
    typed = params.get("typed_plan") if isinstance(params, dict) else None
    if not isinstance(typed, dict):
        raise HTTPException(422, "execution ticket does not contain a typed day-2 plan")
    typed_hash = str(typed.get("plan_hash") or "")
    unhashed = dict(typed)
    unhashed.pop("plan_hash", None)
    if not typed_hash or sha256_hex(unhashed) != typed_hash:
        raise HTTPException(409, "typed day-2 plan hash verification failed")
    operation = str(typed.get("operation") or "")
    if operation not in KUBERNETES_DAY2_OPERATIONS:
        raise HTTPException(422, f"unsupported trusted Kubernetes day-2 operation: {operation}")
    if typed.get("arbitrary_shell") is not False or typed.get("mutation_gate") != "changeset-exact-hash-approval":
        raise HTTPException(409, "typed day-2 plan does not preserve Hermes mutation invariants")
    return typed


def _day2_target(typed: dict[str, Any]) -> dict[str, Any]:
    matches = [item for item in (typed.get("targets") or []) if isinstance(item, dict) and item.get("kind") == "kubernetes"]
    if len(matches) != 1:
        raise HTTPException(422, "typed day-2 plan must contain exactly one Kubernetes target snapshot")
    snapshot = matches[0]
    if snapshot.get("status") not in {None, "configured"}:
        raise HTTPException(409, "Kubernetes target is disabled")
    return snapshot


def _day2_parameters(typed: dict[str, Any]) -> dict[str, Any]:
    parameters = typed.get("parameters") or {}
    if not isinstance(parameters, dict):
        raise HTTPException(422, "typed day-2 parameters are invalid")
    return parameters


def _day2_node_name(parameters: dict[str, Any]) -> str:
    node = str(parameters.get("node") or "")
    if not NAME_RE.fullmatch(node):
        raise HTTPException(422, "invalid node name")
    return node


def _day2_workload(parameters: dict[str, Any], *, scaling: bool = False) -> tuple[str, str, str]:
    kind = str(parameters.get("kind") or "").lower()
    allowed = {"deployment", "statefulset"} if scaling else {"deployment", "statefulset", "daemonset"}
    if kind not in allowed:
        raise HTTPException(422, "unsupported workload kind for this day-2 operation")
    name = str(parameters.get("name") or "")
    if not NAME_RE.fullmatch(name):
        raise HTTPException(422, "invalid workload name")
    namespace = _namespace(str(parameters.get("namespace") or "default"))
    return kind, name, namespace


def _day2_helm(parameters: dict[str, Any]) -> tuple[str, str, str, str, str | None]:
    release = str(parameters.get("release") or "")
    chart = str(parameters.get("chart") or "")
    namespace = _namespace(str(parameters.get("namespace") or "default"))
    version = str(parameters.get("version") or "")
    values_yaml = parameters.get("values_yaml")
    if not NAME_RE.fullmatch(release):
        raise HTTPException(422, "invalid Helm release name")
    if not chart or len(chart) > 500 or any(ch.isspace() for ch in chart):
        raise HTTPException(422, "invalid Helm chart reference")
    if not version or version in {"latest", "*"} or len(version) > 160:
        raise HTTPException(422, "Helm day-2 execution requires a pinned chart version")
    if values_yaml is not None and not isinstance(values_yaml, str):
        raise HTTPException(422, "values_yaml must be a string")
    return release, chart, namespace, version, values_yaml


def _day2_argocd(parameters: dict[str, Any]) -> tuple[str, str, str, bool]:
    application = str(parameters.get("application") or "")
    namespace = _namespace(str(parameters.get("namespace") or "default"))
    revision = str(parameters.get("revision") or "")
    prune = parameters.get("prune", False)
    if not NAME_RE.fullmatch(application):
        raise HTTPException(422, "invalid Argo CD Application name")
    if len(revision) not in {40, 64} or any(ch not in "0123456789abcdefABCDEF" for ch in revision):
        raise HTTPException(422, "GitOps sync requires a full 40- or 64-character commit digest")
    if not isinstance(prune, bool):
        raise HTTPException(422, "prune must be boolean")
    return application, namespace, revision, prune


def _day2_argocd_state(snapshot: dict[str, Any], application: str, namespace: str) -> dict[str, Any]:
    data = _run_json(["kubectl", "get", "applications.argoproj.io", application, "-n", namespace, "-o", "json"], snapshot)
    metadata = data.get("metadata") or {}
    spec = data.get("spec") or {}
    source = spec.get("source") if isinstance(spec.get("source"), dict) else {}
    status = data.get("status") or {}
    sync = status.get("sync") if isinstance(status.get("sync"), dict) else {}
    health = status.get("health") if isinstance(status.get("health"), dict) else {}
    return {
        "application": application,
        "namespace": namespace,
        "uid": metadata.get("uid"),
        "resource_version": metadata.get("resourceVersion"),
        "desired_revision": source.get("targetRevision"),
        "observed_revision": sync.get("revision"),
        "sync_status": sync.get("status"),
        "health_status": health.get("status"),
    }


def _argocd_sync_patch(revision: str, prune: bool) -> str:
    return json.dumps({"operation": {"sync": {"revision": revision, "prune": prune}}}, sort_keys=True, separators=(",", ":"))


def _cilium_ready(snapshot: dict[str, Any], namespace: str) -> tuple[bool, dict[str, Any]]:
    data = _run_json(["kubectl", "get", "pods", "-n", namespace, "-l", "k8s-app=cilium", "-o", "json"], snapshot)
    items = data.get("items") if isinstance(data.get("items"), list) else []
    unhealthy: list[str] = []
    for pod in items:
        metadata = pod.get("metadata") or {}
        status = pod.get("status") or {}
        conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
        ready = any(str(c.get("type")) == "Ready" and str(c.get("status")) == "True" for c in conditions if isinstance(c, dict))
        if str(status.get("phase") or "") != "Running" or not ready:
            unhealthy.append(str(metadata.get("name") or "unknown"))
    return bool(items) and not unhealthy, {"visible_cilium_pods": len(items), "unhealthy_cilium_pods": unhealthy[:20]}


def _node_unschedulable(snapshot: dict[str, Any], node: str) -> bool:
    data = _run_json(["kubectl", "get", "node", node, "-o", "json"], snapshot)
    return bool((data.get("spec") or {}).get("unschedulable", False))


def _verification_check(check_id: str, passed: bool, summary: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": check_id, "status": "PASS" if passed else "FAIL", "summary": summary, "evidence": evidence or {}}


def _day2_node_state(snapshot: dict[str, Any], node: str) -> dict[str, Any]:
    data = _run_json(["kubectl", "get", "node", node, "-o", "json"], snapshot)
    metadata = data.get("metadata") or {}
    spec = data.get("spec") or {}
    return {
        "node": node,
        "uid": metadata.get("uid"),
        "unschedulable": bool(spec.get("unschedulable", False)),
    }


def _day2_workload_state(snapshot: dict[str, Any], kind: str, name: str, namespace: str) -> dict[str, Any]:
    data = _run_json(["kubectl", "get", f"{kind}/{name}", "-n", namespace, "-o", "json"], snapshot)
    metadata = data.get("metadata") or {}
    spec = data.get("spec") or {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    template_meta = template.get("metadata") if isinstance(template.get("metadata"), dict) else {}
    annotations = template_meta.get("annotations") if isinstance(template_meta.get("annotations"), dict) else {}
    return {
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "uid": metadata.get("uid"),
        "generation": metadata.get("generation"),
        "replicas": spec.get("replicas"),
        "restart_annotation": annotations.get("kubectl.kubernetes.io/restartedAt"),
    }


def _day2_preview(snapshot: dict[str, Any], operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if operation not in KUBERNETES_DAY2_OPERATIONS:
        raise HTTPException(422, f"unsupported trusted Kubernetes day-2 operation: {operation}")
    _kubectl_toolchain(snapshot, refresh=True)
    if operation.startswith("cluster.node."):
        node = _day2_node_name(parameters)
        before = _day2_node_state(snapshot, node)
        desired = dict(before)
        desired["unschedulable"] = operation != "cluster.node.uncordon"
        return {
            "kind": "kubernetes-day2-node-preview",
            "operation": operation,
            "before": before,
            "desired": desired,
            "preconditions": {"node_state_hash": sha256_hex(before)},
            "secret_output_suppressed": True,
        }
    if operation in {"cluster.workload.restart", "cluster.workload.scale"}:
        kind, name, namespace = _day2_workload(parameters, scaling=operation == "cluster.workload.scale")
        _enforce_namespace(snapshot, namespace)
        before = _day2_workload_state(snapshot, kind, name, namespace)
        desired = {"kind": kind, "name": name, "namespace": namespace}
        if operation == "cluster.workload.scale":
            replicas = parameters.get("replicas")
            if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 0 or replicas > 10000:
                raise HTTPException(422, "replicas must be an integer between 0 and 10000")
            desired["replicas"] = replicas
        else:
            desired["restart"] = True
        return {
            "kind": "kubernetes-day2-workload-preview",
            "operation": operation,
            "before": before,
            "desired": desired,
            "preconditions": {"workload_state_hash": sha256_hex(before)},
            "secret_output_suppressed": True,
        }
    if operation == "cluster.gitops.sync":
        application, namespace, revision, prune = _day2_argocd(parameters)
        _enforce_namespace(snapshot, namespace)
        before = _day2_argocd_state(snapshot, application, namespace)
        patch = _argocd_sync_patch(revision, prune)
        dry_run = _run(["kubectl", "patch", "applications.argoproj.io", application, "-n", namespace, "--type=merge", "-p", patch, "--dry-run=server", "-o", "name"], snapshot)
        return {
            "kind": "kubernetes-day2-gitops-preview",
            "operation": operation,
            "before": before,
            "desired": {"application": application, "namespace": namespace, "revision": revision, "prune": prune},
            "preconditions": {"gitops_state_hash": sha256_hex(before)},
            "dry_run": dry_run,
            "secret_output_suppressed": True,
        }
    release, chart, namespace, version, values_yaml = _day2_helm(parameters)
    if operation == "cluster.cilium.upgrade":
        if release != "cilium" or namespace != "kube-system" or "cilium" not in chart.lower():
            raise HTTPException(422, "Cilium upgrade must target release cilium in kube-system with a Cilium chart")
    _enforce_namespace(snapshot, namespace)
    before = _helm_release_snapshot(snapshot, release, namespace)
    args = ["helm", "upgrade", release, chart, "--install", "--namespace", namespace, "--create-namespace", "--version", version, "--wait", "--timeout", "5m"]
    values_path: Path | None = None
    try:
        if values_yaml:
            if len(values_yaml.encode()) > 256_000:
                raise HTTPException(413, "Helm values exceed 256 KiB limit")
            values_path = _helm_values_file(values_yaml)
            args += ["-f", str(values_path)]
        dry_run = _run(args + ["--dry-run=server", "--hide-secret"], snapshot, timeout=max(COMMAND_TIMEOUT, 120))
    finally:
        if values_path is not None:
            values_path.unlink(missing_ok=True)
    return {
        "kind": "kubernetes-day2-helm-preview",
        "operation": operation,
        "before": {
            "exists": before.get("exists"),
            "release": release,
            "namespace": namespace,
            "revision": before.get("revision"),
            "status": ((before.get("status") or {}).get("info") or {}).get("status") if isinstance(before.get("status"), dict) else None,
        },
        "desired": {"release": release, "chart": chart, "namespace": namespace, "version": version},
        "preconditions": {"release_snapshot_hash": _helm_snapshot_hash(before)},
        "dry_run": dry_run,
        "secret_output_suppressed": True,
    }


def _assert_day2_runtime_preconditions(snapshot: dict[str, Any], typed: dict[str, Any], parameters: dict[str, Any]) -> None:
    preview = typed.get("runtime_preview") or {}
    preconditions = preview.get("preconditions") if isinstance(preview, dict) else None
    if not isinstance(preconditions, dict) or not preconditions:
        raise HTTPException(409, "typed day-2 plan has no exact runtime preview preconditions")
    operation = str(typed.get("operation") or "")
    if operation.startswith("cluster.node."):
        node = _day2_node_name(parameters)
        current = _day2_node_state(snapshot, node)
        expected = str(preconditions.get("node_state_hash") or "")
        if not expected or not hmac.compare_digest(sha256_hex(current), expected):
            raise HTTPException(409, "node state changed after preview; create and approve a new ChangeSet")
        return
    if operation in {"cluster.workload.restart", "cluster.workload.scale"}:
        kind, name, namespace = _day2_workload(parameters, scaling=operation == "cluster.workload.scale")
        _enforce_namespace(snapshot, namespace)
        current = _day2_workload_state(snapshot, kind, name, namespace)
        expected = str(preconditions.get("workload_state_hash") or "")
        if not expected or not hmac.compare_digest(sha256_hex(current), expected):
            raise HTTPException(409, "workload state changed after preview; create and approve a new ChangeSet")
        return
    if operation == "cluster.gitops.sync":
        application, namespace, _, _ = _day2_argocd(parameters)
        _enforce_namespace(snapshot, namespace)
        current = _day2_argocd_state(snapshot, application, namespace)
        expected = str(preconditions.get("gitops_state_hash") or "")
        if not expected or not hmac.compare_digest(sha256_hex(current), expected):
            raise HTTPException(409, "Argo CD Application state changed after preview; create and approve a new ChangeSet")
        return
    release, _, namespace, _, _ = _day2_helm(parameters)
    _enforce_namespace(snapshot, namespace)
    current = _helm_release_snapshot(snapshot, release, namespace)
    expected = str(preconditions.get("release_snapshot_hash") or "")
    if not expected or not hmac.compare_digest(_helm_snapshot_hash(current), expected):
        raise HTTPException(409, "Helm release changed after preview; create and approve a new ChangeSet")


def _execute_day2(changeset_plan: dict[str, Any], preconditions: dict[str, Any]) -> dict[str, Any]:
    typed = _day2_typed_plan(changeset_plan)
    snapshot = _day2_target(typed)
    parameters = _day2_parameters(typed)
    operation = str(typed["operation"])
    _kubectl_toolchain(snapshot, refresh=True)
    _assert_day2_runtime_preconditions(snapshot, typed, parameters)
    checks: list[dict[str, Any]] = []
    result: dict[str, Any] = {"operation": operation}

    if operation == "cluster.node.cordon":
        node = _day2_node_name(parameters)
        result["command"] = _run(["kubectl", "cordon", node], snapshot)
        passed = _node_unschedulable(snapshot, node)
        checks.append(_verification_check("node-unschedulable", passed, f"node {node} is cordoned", {"node": node, "unschedulable": passed}))
    elif operation == "cluster.node.uncordon":
        node = _day2_node_name(parameters)
        result["command"] = _run(["kubectl", "uncordon", node], snapshot)
        unschedulable = _node_unschedulable(snapshot, node)
        checks.append(_verification_check("node-schedulable", not unschedulable, f"node {node} is schedulable", {"node": node, "unschedulable": unschedulable}))
    elif operation == "cluster.node.drain":
        node = _day2_node_name(parameters)
        _run(["kubectl", "cordon", node], snapshot)
        args = ["kubectl", "drain", node, "--ignore-daemonsets", "--timeout=5m"]
        if bool(parameters.get("delete_emptydir_data", False)):
            args.append("--delete-emptydir-data")
        if bool(parameters.get("force", False)):
            args.append("--force")
        result["command"] = _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        unschedulable = _node_unschedulable(snapshot, node)
        checks.append(_verification_check("node-unschedulable", unschedulable, f"node {node} remains cordoned after drain", {"node": node, "unschedulable": unschedulable}))
        checks.append(_verification_check("drain-complete", True, f"kubectl drain completed for {node}", {"node": node}))
    elif operation == "cluster.workload.restart":
        kind, name, namespace = _day2_workload(parameters)
        _enforce_namespace(snapshot, namespace)
        result["command"] = _run(["kubectl", "rollout", "restart", f"{kind}/{name}", "-n", namespace], snapshot)
        rollout = _run(["kubectl", "rollout", "status", f"{kind}/{name}", "-n", namespace, "--timeout=5m"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        result["rollout"] = rollout
        checks.append(_verification_check("rollout-complete", True, f"{kind}/{name} rollout completed", {"kind": kind, "name": name, "namespace": namespace}))
    elif operation == "cluster.workload.scale":
        kind, name, namespace = _day2_workload(parameters, scaling=True)
        _enforce_namespace(snapshot, namespace)
        replicas = parameters.get("replicas")
        if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 0 or replicas > 10000:
            raise HTTPException(422, "replicas must be an integer between 0 and 10000")
        result["command"] = _run(["kubectl", "scale", f"{kind}/{name}", f"--replicas={replicas}", "-n", namespace], snapshot)
        rollout = _run(["kubectl", "rollout", "status", f"{kind}/{name}", "-n", namespace, "--timeout=5m"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        live = _run_json(["kubectl", "get", f"{kind}/{name}", "-n", namespace, "-o", "json"], snapshot)
        desired = int((live.get("spec") or {}).get("replicas") or 0)
        ready = int((live.get("status") or {}).get("readyReplicas") or 0)
        result["rollout"] = rollout
        checks.append(_verification_check("replicas-converged", desired == replicas and ready == replicas, f"{kind}/{name} replicas converged", {"desired": desired, "ready": ready, "requested": replicas}))
        checks.append(_verification_check("rollout-complete", True, f"{kind}/{name} rollout completed", {"kind": kind, "name": name, "namespace": namespace}))
    elif operation == "cluster.gitops.sync":
        application, namespace, revision, prune = _day2_argocd(parameters)
        _enforce_namespace(snapshot, namespace)
        patch = _argocd_sync_patch(revision, prune)
        result["command"] = _run(["kubectl", "patch", "applications.argoproj.io", application, "-n", namespace, "--type=merge", "-p", patch, "-o", "name"], snapshot)
        result["sync_wait"] = _run(["kubectl", "wait", "applications.argoproj.io", application, "-n", namespace, "--for=jsonpath={.status.sync.status}=Synced", "--timeout=5m"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        live = _day2_argocd_state(snapshot, application, namespace)
        synced = str(live.get("sync_status") or "") == "Synced" and str(live.get("observed_revision") or "") == revision
        healthy = str(live.get("health_status") or "") in {"Healthy", "Progressing"}
        checks.append(_verification_check("gitops-synced", synced, f"Argo CD Application {application} is synced to the approved revision", {"application": application, "namespace": namespace, "revision": revision, "sync_status": live.get("sync_status")}))
        checks.append(_verification_check("gitops-healthy", healthy, f"Argo CD Application {application} health is {live.get('health_status') or 'Unknown'}", {"application": application, "namespace": namespace, "health_status": live.get("health_status")}))
        result["application"] = live
    else:
        release, chart, namespace, version, values_yaml = _day2_helm(parameters)
        _enforce_namespace(snapshot, namespace)
        if operation == "cluster.cilium.upgrade" and (release != "cilium" or namespace != "kube-system" or "cilium" not in chart.lower()):
            raise HTTPException(422, "Cilium upgrade must target release cilium in kube-system with a Cilium chart")
        args = ["helm", "upgrade", release, chart, "--install", "--namespace", namespace, "--create-namespace", "--version", version, "--wait", "--timeout", "5m"]
        values_path: Path | None = None
        try:
            if values_yaml:
                values_path = _helm_values_file(values_yaml)
                args += ["-f", str(values_path)]
            result["command"] = _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))
            status = _run_json(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
        finally:
            if values_path is not None:
                values_path.unlink(missing_ok=True)
        info = status.get("info") or {}
        status_name = str(info.get("status") or status.get("status") or "").lower()
        ready = status_name in {"deployed", "superseded"}
        checks.append(_verification_check("helm-release-ready", ready, f"Helm release {release} status is {status_name or 'unknown'}", {"release": release, "namespace": namespace, "version": version, "status": status_name}))
        result["release"] = {"release": release, "namespace": namespace, "chart": chart, "version": version, "status": status_name}
        if operation == "cluster.cilium.upgrade":
            cilium_ok, cilium_evidence = _cilium_ready(snapshot, namespace)
            checks.append(_verification_check("cilium-ready", cilium_ok, "Cilium agent pods are Ready after the approved Helm upgrade", cilium_evidence))
            try:
                hubble = hubble_provider.collect(snapshot=snapshot, env=_env(snapshot), last=20, since_seconds=60)
                hubble_summary = hubble.get("summary") if isinstance(hubble.get("summary"), dict) else {}
                hubble_ok = hubble.get("raw_flow_bodies_returned") is False
                hubble_evidence = {"event_count": int(hubble_summary.get("event_count") or 0), "verdict_counts": dict(hubble_summary.get("verdict_counts") or {}), "raw_flow_bodies_returned": False}
            except hubble_provider.HubbleError as exc:
                hubble_ok = False
                hubble_evidence = {"collector_error": str(exc)[:400], "raw_flow_bodies_returned": False}
            checks.append(_verification_check("hubble-ready", hubble_ok, "Hubble Relay is reachable through the trusted broker after the Cilium upgrade", hubble_evidence))

    observed_at = int(time.time())
    return {
        "schema_version": 1,
        "operation": operation,
        "typed_plan_hash": typed["plan_hash"],
        "target_snapshot_hash": snapshot.get("snapshot_hash"),
        "result": result,
        "verification": {
            "observed_at": observed_at,
            "checks": checks,
            "evidence": {
                "source": "kubernetes-broker-active-verification",
                "mutation_commands_generated": False,
                "arbitrary_shell": False,
                "raw_credentials_returned": False,
            },
        },
    }


@app.post("/v1/day2/preview")
def preview_day2(payload: Day2PreviewRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    snapshot = _target(payload.target_snapshot)
    if snapshot.get("status") not in {None, "configured"}:
        raise HTTPException(409, "Kubernetes target is disabled")
    return _day2_preview(snapshot, payload.operation, payload.parameters)


@app.post("/v1/day2/execute")
def execute_day2(payload: ExecuteRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    if not EXECUTION_ENABLED:
        raise HTTPException(403, "Kubernetes execution is disabled; enable HERMES_KUBERNETES_EXECUTION_ENABLED only after policy review")
    plan, preconditions = _verify_ticket(payload.ticket, payload.signature)
    if str(preconditions.get("executor") or "") != "kubernetes-broker":
        raise HTTPException(409, "execution ticket is not bound to Kubernetes Broker")
    if not str(preconditions.get("operation_job_id") or "").startswith("opj_"):
        raise HTTPException(409, "execution ticket has no operation-job binding")
    return _execute_day2(plan, preconditions)


@app.post("/v1/preview")
def preview_endpoint(payload: BrokerPlanRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    result = preview(payload.plan)
    toolchain = _kubectl_toolchain(_target(payload.plan))
    if toolchain:
        result["toolchain"] = {k: v for k, v in toolchain.items() if k != "path"}
        result["toolchain_binding_hash"] = toolchain["binding_hash"]
    return result


@app.post("/v1/execute")
def execute(payload: ExecuteRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    if not EXECUTION_ENABLED:
        raise HTTPException(403, "Kubernetes execution is disabled; enable HERMES_KUBERNETES_EXECUTION_ENABLED only after policy review")
    plan, preconditions = _verify_ticket(payload.ticket, payload.signature)
    expected_toolchain = str((preconditions or {}).get("toolchain_binding_hash") or "")
    if expected_toolchain:
        current = _kubectl_toolchain(_target(plan), refresh=True)
        if not current or not hmac.compare_digest(expected_toolchain, str(current.get("binding_hash") or "")):
            raise HTTPException(409, "kubectl toolchain changed after preview; create and approve a new ChangeSet")
    return _execute_plan(plan, preconditions)
