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

VERSION = "0.5.10-rc.1"
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
    plan, preconditions = _verify_ticket(payload.ticket, payload.signature)
    return _execute_plan(plan, preconditions)
