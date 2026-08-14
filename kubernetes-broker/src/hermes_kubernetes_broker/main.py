from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
import threading
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

VERSION = "0.5.10-beta.1-dev.1"
CREDENTIAL_ROOT = Path(os.getenv("HERMES_KUBECONFIG_ROOT", "/credentials/kubeconfigs"))
TOKEN = os.getenv("HERMES_KUBERNETES_BROKER_TOKEN", "")
EXECUTION_KEY = os.getenv("HERMES_EXECUTION_HMAC_KEY", "")
EXECUTION_ENABLED = os.getenv("HERMES_KUBERNETES_EXECUTION_ENABLED", "false").lower() == "true"
COMMAND_TIMEOUT = int(os.getenv("HERMES_KUBERNETES_COMMAND_TIMEOUT", "60"))
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


def _run(args: list[str], snapshot: dict[str, Any], stdin: str | None = None, timeout: int | None = None, allowed_codes: set[int] | None = None) -> dict[str, Any]:
    allowed = allowed_codes or {0}
    started = time.monotonic()
    try:
        proc = subprocess.run(
            args,
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


def _manifest_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    manifest = str(params.get("manifest") or "")
    docs = _manifest_docs(manifest)
    namespace = _namespace(params.get("namespace"))
    _enforce_namespace(snapshot, namespace)
    _enforce_manifest_scope(snapshot, docs, namespace)
    dry = _run([
        "kubectl", "apply", "--server-side", "--dry-run=server", "--field-manager=hermes-control-plane",
        "-n", namespace, "-f", "-", "-o", "yaml"
    ], snapshot, manifest)
    diff = _run([
        "kubectl", "diff", "--server-side", "--field-manager=hermes-control-plane", "-n", namespace, "-f", "-"
    ], snapshot, manifest, allowed_codes={0, 1})
    resources = [{"apiVersion": d.get("apiVersion"), "kind": d.get("kind"), "name": (d.get("metadata") or {}).get("name"), "namespace": (d.get("metadata") or {}).get("namespace", namespace)} for d in docs]
    return {
        "kind": "kubernetes-manifest",
        "summary": f"Server-side dry-run passed for {len(resources)} resource(s) in namespace {namespace}",
        "resources": resources,
        "dry_run": dry,
        "diff": diff,
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


def _helm_preview(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    params = plan.get("parameters") or {}
    release, chart, namespace, args = _helm_base(params)
    _enforce_namespace(snapshot, namespace)
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
            "dry_run": result,
            "secret_output_suppressed": True,
        }
    finally:
        if values_path:
            values_path.unlink(missing_ok=True)


def preview(plan: dict[str, Any]) -> dict[str, Any]:
    operation = str(plan.get("operation") or "")
    if sha256_hex(plan) != str(plan.get("plan_hash", sha256_hex(plan))):
        # plan_hash is normally external; this branch only guards callers that embed one.
        raise HTTPException(409, "embedded plan hash mismatch")
    if operation == "kubernetes.manifest.apply":
        return _manifest_preview(plan)
    if operation in {"helm.install", "helm.upgrade"}:
        return _helm_preview(plan)
    if operation == "helm.rollback":
        snapshot = _target(plan)
        p = plan.get("parameters") or {}
        release = _release(p.get("release")); namespace = _namespace(p.get("namespace")); revision = int(p.get("revision") or 0)
        _enforce_namespace(snapshot, namespace)
        if revision < 1:
            raise HTTPException(422, "rollback revision must be >= 1")
        history = _run(["helm", "history", release, "--namespace", namespace, "-o", "json"], snapshot)
        return {"kind": "helm-rollback", "summary": f"Rollback plan for {release} to revision {revision}", "history": history, "secret_output_suppressed": True}
    raise HTTPException(422, f"unsupported beta.1 operation: {operation}")


def _verify_ticket(ticket: dict[str, Any], signature: str) -> dict[str, Any]:
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
    return plan


def _execute_plan(plan: dict[str, Any]) -> dict[str, Any]:
    snapshot = _target(plan)
    operation = str(plan.get("operation") or "")
    params = plan.get("parameters") or {}
    if operation == "kubernetes.manifest.apply":
        manifest = str(params.get("manifest") or "")
        docs = _manifest_docs(manifest)
        ns = _namespace(params.get("namespace"))
        _enforce_namespace(snapshot, ns)
        _enforce_manifest_scope(snapshot, docs, ns)
        result = _run(["kubectl", "apply", "--server-side", "--field-manager=hermes-control-plane", "-n", ns, "-f", "-", "-o", "name"], snapshot, manifest, timeout=max(COMMAND_TIMEOUT, 120))
        return {"operation": operation, "result": result}
    if operation in {"helm.install", "helm.upgrade"}:
        release, chart, namespace, args = _helm_base(params)
        _enforce_namespace(snapshot, namespace)
        values_path = None
        try:
            values_yaml = str(params.get("values_yaml") or "")
            if values_yaml:
                values_path = _helm_values_file(values_yaml); args += ["-f", str(values_path)]
            args += ["--wait", "--timeout", str(params.get("timeout", "5m"))]
            result = _run(args, snapshot, timeout=max(COMMAND_TIMEOUT, 360))
            status = _run(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
            return {"operation": operation, "result": result, "verification": status}
        finally:
            if values_path: values_path.unlink(missing_ok=True)
    if operation == "helm.rollback":
        release = _release(params.get("release")); namespace = _namespace(params.get("namespace")); revision = int(params.get("revision") or 0)
        _enforce_namespace(snapshot, namespace)
        if revision < 1: raise HTTPException(422, "rollback revision must be >= 1")
        result = _run(["helm", "rollback", release, str(revision), "--namespace", namespace, "--wait"], snapshot, timeout=max(COMMAND_TIMEOUT, 360))
        status = _run(["helm", "status", release, "--namespace", namespace, "-o", "json"], snapshot)
        return {"operation": operation, "result": result, "verification": status}
    raise HTTPException(422, f"unsupported beta.1 operation: {operation}")


app = FastAPI(title="Hermes Kubernetes Broker", version=VERSION)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-kubernetes-broker",
        "version": VERSION,
        "execution_enabled": EXECUTION_ENABLED,
        "kubectl": subprocess.run(["kubectl", "version", "--client", "-o", "json"], capture_output=True, text=True).returncode == 0,
        "helm": subprocess.run(["helm", "version", "--short"], capture_output=True, text=True).returncode == 0,
    }


@app.post("/v1/discover")
def discover(payload: DiscoveryRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    snapshot = _target(payload.target_snapshot)
    version = _run(["kubectl", "version", "-o", "json"], snapshot)
    scope = _scope(snapshot)
    allow = [str(x).lower() for x in (scope.get("namespace_allowlist") or []) if str(x).strip()]
    deny = {str(x).lower() for x in (scope.get("namespace_denylist") or [])}

    def parsed(result):
        try:
            return json.loads(result["output"])
        except json.JSONDecodeError:
            return {"raw": result["output"]}

    if allow and "*" not in allow:
        namespace_items = []
        workload_items = []
        for ns in allow:
            _enforce_namespace(snapshot, _namespace(ns))
            ns_result = _run(["kubectl", "get", "namespace", ns, "-o", "json"], snapshot)
            namespace_items.append(parsed(ns_result))
            workloads_result = _run(["kubectl", "get", "deployments,statefulsets,daemonsets", "-n", ns, "-o", "json"], snapshot)
            workload_items.extend(parsed(workloads_result).get("items", []))
        namespaces = {"items": namespace_items, "policy_scoped": True}
        workloads = {"items": workload_items, "policy_scoped": True}
    else:
        namespaces = parsed(_run(["kubectl", "get", "namespaces", "-o", "json"], snapshot))
        if deny:
            namespaces["items"] = [x for x in namespaces.get("items", []) if str((x.get("metadata") or {}).get("name", "")).lower() not in deny]
        workloads = parsed(_run(["kubectl", "get", "deployments,statefulsets,daemonsets", "-A", "-o", "json"], snapshot))
        if deny:
            workloads["items"] = [x for x in workloads.get("items", []) if str((x.get("metadata") or {}).get("namespace", "")).lower() not in deny]

    nodes = None
    if bool(scope.get("cluster_read", False)):
        nodes = parsed(_run(["kubectl", "get", "nodes", "-o", "json"], snapshot))
    return {"version": parsed(version), "namespaces": namespaces, "nodes": nodes, "workloads": workloads, "policy_scope": scope, "secret_data_requested": False}


@app.post("/v1/preview")
def preview_endpoint(payload: BrokerPlanRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    return preview(payload.plan)


@app.post("/v1/execute")
def execute(payload: ExecuteRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_token(authorization)
    if not EXECUTION_ENABLED:
        raise HTTPException(403, "Kubernetes execution is disabled; enable HERMES_KUBERNETES_EXECUTION_ENABLED only after policy review")
    plan = _verify_ticket(payload.ticket, payload.signature)
    return _execute_plan(plan)
