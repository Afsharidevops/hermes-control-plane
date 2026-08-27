from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import tarfile
import shutil
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse
import re

from .repository_snapshot import (
    REPOSITORY_KINDS,
    RepositorySnapshotError,
    extract_snapshot_archive,
    validate_repository_tree,
)


class ArtifactMirrorError(RuntimeError):
    pass




_OCI_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_OCI_REPOSITORY_RE = re.compile(r"^[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*)*$")
_HELM_VERSION_TAG_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:_[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
_HELM_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_HELM_CONFIG_MEDIA_TYPE = "application/vnd.cncf.helm.config.v1+json"
_HELM_CHART_LAYER_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
_HELM_PROVENANCE_LAYER_MEDIA_TYPE = "application/vnd.cncf.helm.chart.provenance.v1.prov"
_GIT_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_GIT_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$")
_ANSIBLE_COLLECTION_PART_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ANSIBLE_COLLECTION_VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
_ANSIBLE_COLLECTION_METADATA_LIMIT = 2 * 1024 * 1024
_ANSIBLE_COLLECTION_MEMBER_LIMIT = 20000


def _oci_registry_allowlisted(host: str, *, destination: bool) -> bool:
    env = "HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST" if destination else "HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST"
    allowed = {item.strip().lower().rstrip(".") for item in os.getenv(env, "").split(",") if item.strip()}
    return bool(allowed) and host.lower().rstrip(".") in allowed


def _oci_reference(uri: str, *, destination: bool) -> tuple[str, str]:
    parsed = urlparse(uri)
    purpose = "artifact OCI destination" if destination else "artifact OCI source"
    if parsed.scheme != "oci" or not parsed.hostname:
        raise ArtifactMirrorError(f"{purpose} must use oci://registry/repository")
    if parsed.username is not None or parsed.password is not None:
        raise ArtifactMirrorError(f"embedded credentials are forbidden in {purpose}")
    if parsed.params or parsed.query or parsed.fragment:
        raise ArtifactMirrorError(f"{purpose} must not contain params, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ArtifactMirrorError(f"invalid {purpose} registry port") from exc
    if port is not None and port < 1:
        raise ArtifactMirrorError(f"invalid {purpose} registry port")
    host = parsed.hostname.lower().rstrip(".")
    netloc = host if port is None else f"{host}:{port}"
    if not _oci_registry_allowlisted(netloc, destination=destination):
        side = "destination" if destination else "source"
        raise ArtifactMirrorError(f"artifact OCI {side} registry is not allowlisted")
    repository = parsed.path.lstrip("/").rstrip("/")
    if not repository or not _OCI_REPOSITORY_RE.fullmatch(repository):
        raise ArtifactMirrorError(f"{purpose} repository is invalid")
    if "@" in repository or ":" in repository:
        raise ArtifactMirrorError(f"{purpose} repository must not include a tag or digest")
    return netloc, repository


def _authfile_path(*, destination: bool) -> str | None:
    env = "HERMES_ARTIFACT_OCI_DESTINATION_AUTHFILE" if destination else "HERMES_ARTIFACT_OCI_SOURCE_AUTHFILE"
    raw = os.getenv(env, "").strip()
    if not raw:
        return None
    auth_root = Path(os.getenv("HERMES_ARTIFACT_AUTH_ROOT", "/run/secrets/hermes-artifact-auth")).expanduser().resolve(strict=False)
    if not auth_root.is_dir() or auth_root.is_symlink():
        raise ArtifactMirrorError("HERMES_ARTIFACT_AUTH_ROOT must be an existing non-symlink directory")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ArtifactMirrorError(f"{env} must be an absolute path")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(auth_root)
    except ValueError as exc:
        raise ArtifactMirrorError(f"{env} escapes HERMES_ARTIFACT_AUTH_ROOT") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ArtifactMirrorError(f"{env} must reference a regular non-symlink file")
    return str(resolved)



def _trusted_secret_file(env: str, *, purpose: str, required: bool = False) -> Path | None:
    raw = os.getenv(env, "").strip()
    if not raw:
        if required:
            raise ArtifactMirrorError(f"{env} is required for {purpose}")
        return None
    auth_root = Path(os.getenv("HERMES_ARTIFACT_AUTH_ROOT", "/run/secrets/hermes-artifact-auth")).expanduser().resolve(strict=False)
    if not auth_root.is_dir() or auth_root.is_symlink():
        raise ArtifactMirrorError("HERMES_ARTIFACT_AUTH_ROOT must be an existing non-symlink directory")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ArtifactMirrorError(f"{env} must be an absolute path")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(auth_root)
    except ValueError as exc:
        raise ArtifactMirrorError(f"{env} escapes HERMES_ARTIFACT_AUTH_ROOT") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ArtifactMirrorError(f"{env} must reference a regular non-symlink file")
    return resolved


def _https_authorization_header(uri: str) -> str | None:
    path = _trusted_secret_file("HERMES_ARTIFACT_HTTPS_AUTHFILE", purpose="authenticated HTTPS artifact access")
    if path is None:
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactMirrorError("HERMES_ARTIFACT_HTTPS_AUTHFILE must contain valid JSON") from exc
    if not isinstance(doc, dict):
        raise ArtifactMirrorError("HERMES_ARTIFACT_HTTPS_AUTHFILE must contain a host-to-authorization object")
    parsed = urlparse(uri)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ArtifactMirrorError("artifact HTTPS source contains an invalid port") from exc
    host_key = hostname if port is None else f"{hostname}:{port}"
    value = doc.get(host_key, doc.get(hostname))
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("authorization")
    if not isinstance(value, str) or not value or len(value) > 8192 or "\r" in value or "\n" in value:
        raise ArtifactMirrorError("artifact HTTPS authorization entry is invalid")
    return value


def _repository_keyring() -> Path:
    path = _trusted_secret_file(
        "HERMES_ARTIFACT_REPOSITORY_KEYRING",
        purpose="signed repository metadata verification",
        required=True,
    )
    assert path is not None
    return path


def _gpgv_binary() -> str:
    binary = os.getenv("HERMES_GPGV_BINARY", "gpgv").strip()
    if not binary or "/" in binary or binary != "gpgv":
        raise ArtifactMirrorError("HERMES_GPGV_BINARY must be the pinned command name gpgv")
    return binary


def _verify_repository_signature(data_path: Path, signature_path: Path) -> None:
    command = [_gpgv_binary(), "--keyring", str(_repository_keyring()), str(signature_path), str(data_path)]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_timeout_seconds(),
            check=False,
            env={**os.environ, "LC_ALL": "C", "GNUPGHOME": "/nonexistent"},
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactMirrorError("repository signature verification timed out") from exc
    except OSError as exc:
        raise ArtifactMirrorError(f"repository signature verifier failed to start: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise ArtifactMirrorError(f"repository signature verification failed with exit code {completed.returncode}")


def _repository_max_expanded_bytes() -> int:
    raw = os.getenv("HERMES_ARTIFACT_REPOSITORY_MAX_EXPANDED_BYTES", str(4 * 1024 * 1024 * 1024))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ArtifactMirrorError("HERMES_ARTIFACT_REPOSITORY_MAX_EXPANDED_BYTES must be an integer") from exc
    if value < 1 or value > 64 * 1024 * 1024 * 1024:
        raise ArtifactMirrorError("repository snapshot expanded-byte limit must be between 1 and 68719476736")
    return value


def _repository_metadata_limit() -> int:
    raw = os.getenv("HERMES_ARTIFACT_REPOSITORY_METADATA_MAX_BYTES", str(256 * 1024 * 1024))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ArtifactMirrorError("HERMES_ARTIFACT_REPOSITORY_METADATA_MAX_BYTES must be an integer") from exc
    if value < 1024 or value > 1024 * 1024 * 1024:
        raise ArtifactMirrorError("repository metadata byte limit must be between 1024 and 1073741824")
    return value


def _skopeo_binary() -> str:
    binary = os.getenv("HERMES_SKOPEO_BINARY", "skopeo").strip()
    if not binary or "/" in binary or binary not in {"skopeo"}:
        raise ArtifactMirrorError("HERMES_SKOPEO_BINARY must be the pinned command name skopeo")
    return binary


def _run_skopeo(args: list[str], *, timeout: int | None = None, allow_not_found: bool = False) -> subprocess.CompletedProcess[bytes] | None:
    command = [_skopeo_binary(), *args]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout or _timeout_seconds(),
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactMirrorError("OCI registry operation timed out") from exc
    except OSError as exc:
        raise ArtifactMirrorError(f"OCI registry runtime failed to start: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        if allow_not_found:
            stderr = completed.stderr.decode("utf-8", errors="replace").lower()
            if any(marker in stderr for marker in ("manifest unknown", "name unknown", "not found")):
                return None
        raise ArtifactMirrorError(f"OCI registry operation failed with exit code {completed.returncode}")
    return completed


def _raw_manifest(reference: str, *, auth_args: list[str], allow_not_found: bool = False) -> bytes | None:
    completed = _run_skopeo(["inspect", *auth_args, "--raw", reference], allow_not_found=allow_not_found)
    return None if completed is None else completed.stdout


def _raw_manifest_digest(reference: str, *, auth_args: list[str], allow_not_found: bool = False) -> str | None:
    manifest = _raw_manifest(reference, auth_args=auth_args, allow_not_found=allow_not_found)
    if manifest is None:
        return None
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def _validate_helm_manifest(raw_manifest: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactMirrorError("Helm OCI source manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ArtifactMirrorError("Helm OCI source manifest must be schemaVersion 2")
    media_type = str(manifest.get("mediaType") or "")
    if media_type != _HELM_MANIFEST_MEDIA_TYPE:
        raise ArtifactMirrorError("Helm OCI source manifest has an unsupported OCI manifest media type")
    config = manifest.get("config")
    if not isinstance(config, dict) or config.get("mediaType") != _HELM_CONFIG_MEDIA_TYPE:
        raise ArtifactMirrorError("Helm OCI source manifest is missing the Helm config media type")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise ArtifactMirrorError("Helm OCI source manifest must contain chart content")
    media_types = [str(layer.get("mediaType") or "") for layer in layers if isinstance(layer, dict)]
    if media_types.count(_HELM_CHART_LAYER_MEDIA_TYPE) != 1:
        raise ArtifactMirrorError("Helm OCI source manifest must contain exactly one Helm chart content layer")
    unsupported = sorted(set(media_types) - {_HELM_CHART_LAYER_MEDIA_TYPE, _HELM_PROVENANCE_LAYER_MEDIA_TYPE})
    if unsupported:
        raise ArtifactMirrorError("Helm OCI source manifest contains unsupported layer media types")
    if media_types.count(_HELM_PROVENANCE_LAYER_MEDIA_TYPE) > 1:
        raise ArtifactMirrorError("Helm OCI source manifest contains more than one provenance layer")
    return {
        "manifest_media_type": media_type,
        "config_media_type": _HELM_CONFIG_MEDIA_TYPE,
        "chart_layer_media_type": _HELM_CHART_LAYER_MEDIA_TYPE,
        "provenance_layer_present": _HELM_PROVENANCE_LAYER_MEDIA_TYPE in media_types,
    }


def _git_binary() -> str:
    binary = os.getenv("HERMES_GIT_BINARY", "git").strip()
    if not binary or "/" in binary or binary != "git":
        raise ArtifactMirrorError("HERMES_GIT_BINARY must be the pinned command name git")
    return binary


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }


def _run_git(args: list[str], *, timeout: int | None = None, allowed_returncodes: set[int] | None = None) -> subprocess.CompletedProcess[bytes]:
    command = [
        _git_binary(),
        "-c", "credential.helper=",
        "-c", "http.followRedirects=false",
        "-c", "http.sslVerify=true",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ssh.allow=never",
        "-c", "protocol.git.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.http.allow=never",
        "-c", "protocol.https.allow=always",
        *args,
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout or _timeout_seconds(),
            check=False,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactMirrorError("Git release mirror operation timed out") from exc
    except OSError as exc:
        raise ArtifactMirrorError(f"Git release runtime failed to start: {type(exc).__name__}") from exc
    allowed = {0} if allowed_returncodes is None else allowed_returncodes
    if completed.returncode not in allowed:
        raise ArtifactMirrorError(f"Git release operation failed with exit code {completed.returncode}")
    return completed


def _run_git_network(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    last_error: ArtifactMirrorError | None = None
    for attempt in range(1, 3):
        try:
            return _run_git(args, timeout=timeout)
        except ArtifactMirrorError as exc:
            last_error = exc
            if attempt == 2:
                raise
    raise last_error or ArtifactMirrorError("Git release network operation failed")


def _git_release_binding(artifact: dict[str, Any]) -> tuple[str, str]:
    labels = artifact.get("labels") if isinstance(artifact.get("labels"), dict) else {}
    unknown = sorted(set(labels) - {"git_ref", "git_commit"})
    if unknown:
        raise ArtifactMirrorError(f"git-release labels contain unsupported keys: {', '.join(unknown)}")
    git_ref = str(labels.get("git_ref") or "")
    git_commit = str(labels.get("git_commit") or "").lower()
    if not git_ref.startswith("refs/tags/"):
        raise ArtifactMirrorError("git-release git_ref must be an immutable refs/tags/... reference")
    tag_name = git_ref[len("refs/tags/"):]
    if (
        not _GIT_TAG_RE.fullmatch(tag_name)
        or ".." in tag_name
        or "//" in tag_name
        or "@{" in tag_name
        or tag_name.endswith((".", "/", ".lock"))
        or tag_name.startswith(".")
    ):
        raise ArtifactMirrorError("git-release git_ref contains an unsafe tag name")
    if not _GIT_COMMIT_RE.fullmatch(git_commit):
        raise ArtifactMirrorError("git-release git_commit must be an exact 40- or 64-hex commit ID")
    version = str(artifact.get("version") or "")
    if version not in {tag_name, tag_name[1:] if tag_name.startswith("v") else tag_name}:
        raise ArtifactMirrorError("git-release version must match the immutable source tag")
    return git_ref, git_commit


def _validate_git_source(uri: str) -> str:
    _validate_https_source(uri)
    parsed = urlparse(uri)
    if parsed.params or parsed.query or parsed.fragment:
        raise ArtifactMirrorError("git-release source must not contain params, query, or fragment")
    if not parsed.path or parsed.path.endswith("/"):
        raise ArtifactMirrorError("git-release source must identify an HTTPS repository path")
    return uri


def _remote_git_commit(source: str, git_ref: str) -> str:
    peeled_ref = f"{git_ref}^{{}}"
    completed = _run_git_network(["ls-remote", "--exit-code", source, git_ref, peeled_ref])
    refs: dict[str, str] = {}
    for raw in completed.stdout.decode("ascii", errors="strict").splitlines():
        parts = raw.split("\t", 1)
        if len(parts) != 2:
            raise ArtifactMirrorError("git ls-remote returned malformed output")
        object_id, ref_name = parts
        if not _GIT_COMMIT_RE.fullmatch(object_id.lower()):
            raise ArtifactMirrorError("git ls-remote returned an unsupported object ID")
        if ref_name not in {git_ref, peeled_ref}:
            raise ArtifactMirrorError("git ls-remote returned an unexpected reference")
        refs[ref_name] = object_id.lower()
    resolved = refs.get(peeled_ref) or refs.get(git_ref)
    if not resolved:
        raise ArtifactMirrorError("git-release source tag was not found")
    return resolved


def _execute_git_release(typed_plan: dict[str, Any], artifact: dict[str, Any], expected: str, observed_at: int) -> dict[str, Any]:
    artifact_id = str(artifact.get("id") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    base_evidence: dict[str, Any] = {
        "source_scheme": "https",
        "destination_scheme": "file",
        "artifact_kind": "git-release",
        "transport": "git-https-exact-tag",
        "archive_format": "tar",
        "arbitrary_shell": False,
        "caller_git_flags": False,
        "raw_credentials_returned": False,
        "credential_helpers_disabled": True,
        "redirects_followed": False,
        "submodules_supported": False,
        "network_attempt_limit": 2,
    }
    try:
        source = _validate_git_source(source)
        git_ref, git_commit = _git_release_binding(artifact)
        base_evidence = {**base_evidence, "git_ref": git_ref, "git_commit": git_commit}
        mirror_root = _root("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror")
        destination_path = _file_uri_path(destination, root=mirror_root, purpose="git-release destination")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        max_bytes = _max_bytes()
        if destination_path.exists():
            destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
            if destination_digest == expected:
                checks = [
                    {"id": "git-source-commit", "status": "SKIP", "summary": "destination already contains the exact pinned Git release archive", "evidence": {"reason": "idempotent-hit", "git_commit": git_commit}},
                    {"id": "destination-digest", "status": "PASS", "summary": "existing Git release archive matches the pinned SHA-256 digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
                ]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "ALREADY_MIRRORED", "bytes": destination_bytes, "digest": destination_digest, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "idempotent": True, "atomic_replace": False}}}
            if not bool((typed_plan.get("parameters") or {}).get("replace_existing", False)):
                checks = [_failure("destination-digest", "existing Git release archive differs from the pinned digest and replace_existing is false", evidence={"observed_digest": destination_digest})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        remote_commit = _remote_git_commit(source, git_ref)
        if remote_commit != git_commit:
            checks = [_failure("git-source-commit", "Git release tag does not resolve to the exact pinned commit", evidence={"expected_commit": git_commit, "observed_commit": remote_commit})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        with tempfile.TemporaryDirectory(prefix=".hermes-git-release-", dir=mirror_root) as tmp:
            tmp_root = Path(tmp)
            repo_path = tmp_root / "repo.git"
            archive_path = tmp_root / "release.tar"
            _run_git(["init", "--bare", str(repo_path)])
            _run_git_network(["-C", str(repo_path), "fetch", "--no-tags", "--depth=1", source, f"+{git_ref}:{git_ref}"], timeout=min(300, max(30, _timeout_seconds() * 3)))
            resolved = _run_git(["-C", str(repo_path), "rev-parse", f"{git_ref}^{{commit}}"])
            fetched_commit = resolved.stdout.decode("ascii", errors="strict").strip().lower()
            if fetched_commit != git_commit:
                raise ArtifactMirrorError("fetched Git release commit differs from the pinned commit")
            submodule_probe = _run_git(["-C", str(repo_path), "cat-file", "-e", f"{git_commit}:.gitmodules"], allowed_returncodes={0, 1, 128})
            if submodule_probe.returncode == 0:
                raise ArtifactMirrorError("git-release repositories containing .gitmodules are unsupported by the bounded archive runtime")
            _run_git(["-C", str(repo_path), "archive", "--format=tar", f"--output={archive_path}", git_commit], timeout=min(300, max(30, _timeout_seconds() * 3)))
            source_digest, byte_count = _sha256_path(archive_path, max_bytes=max_bytes)
            if source_digest != expected:
                checks = [
                    {"id": "git-source-commit", "status": "PASS", "summary": "Git release tag resolves to the exact pinned commit", "evidence": {"git_ref": git_ref, "git_commit": git_commit}},
                    _failure("source-digest", "canonical Git release archive digest does not match the pinned SHA-256 digest", evidence={"observed_digest": source_digest, "bytes": byte_count}),
                ]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
            os.replace(archive_path, destination_path)

        destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
        if destination_digest != expected:
            checks = [_failure("destination-digest", "mirrored Git release archive does not match the pinned SHA-256 digest", evidence={"observed_digest": destination_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        checks = [
            {"id": "git-source-commit", "status": "PASS", "summary": "Git release tag resolves to the exact pinned commit", "evidence": {"git_ref": git_ref, "git_commit": git_commit}},
            {"id": "source-digest", "status": "PASS", "summary": "canonical Git release archive matches the pinned SHA-256 digest", "evidence": {"digest": expected, "bytes": destination_bytes}},
            {"id": "destination-digest", "status": "PASS", "summary": "mirrored Git release archive matches the pinned SHA-256 digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
        ]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "MIRRORED", "bytes": destination_bytes, "digest": destination_digest, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "idempotent": False, "atomic_replace": True}}}
    except ArtifactMirrorError as exc:
        checks = [_failure("artifact-mirror-runtime", str(exc), evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    except (OSError, UnicodeDecodeError) as exc:
        checks = [_failure("artifact-mirror-runtime", f"Git release mirror I/O failed: {type(exc).__name__}", evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}


def _execute_oci(typed_plan: dict[str, Any], artifact: dict[str, Any], expected: str, observed_at: int) -> dict[str, Any]:
    artifact_id = str(artifact.get("id") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    version = str(artifact.get("version") or "")
    kind = str(artifact.get("kind") or "")
    base_evidence = {
        "source_scheme": "oci",
        "destination_scheme": "oci",
        "artifact_kind": kind,
        "transport": "skopeo-docker-registry",
        "multi_arch": "all" if kind == "oci-image" else "not-applicable",
        "preserve_digests": True,
        "arbitrary_shell": False,
        "raw_credentials_returned": False,
        "authfiles_from_environment_only": True,
    }
    try:
        if kind not in {"oci-image", "helm-chart"}:
            raise ArtifactMirrorError("OCI registry runtime is limited to artifact kinds oci-image and helm-chart")
        if not _OCI_TAG_RE.fullmatch(version):
            raise ArtifactMirrorError("OCI artifact version must be a valid immutable destination tag")
        if kind == "helm-chart" and not _HELM_VERSION_TAG_RE.fullmatch(version):
            raise ArtifactMirrorError("Helm OCI artifact version must be an immutable SemVer-compatible tag")
        src_registry, src_repo = _oci_reference(source, destination=False)
        dst_registry, dst_repo = _oci_reference(destination, destination=True)
        source_authfile = _authfile_path(destination=False)
        destination_authfile = _authfile_path(destination=True)
        source_inspect_auth = ["--authfile", source_authfile] if source_authfile else []
        destination_inspect_auth = ["--authfile", destination_authfile] if destination_authfile else []
        source_copy_auth = ["--src-authfile", source_authfile] if source_authfile else []
        destination_copy_auth = ["--dest-authfile", destination_authfile] if destination_authfile else []
        source_ref = f"docker://{src_registry}/{src_repo}@{expected}"
        destination_tag_ref = f"docker://{dst_registry}/{dst_repo}:{version}"
        destination_digest_ref = f"docker://{dst_registry}/{dst_repo}@{expected}"

        source_manifest = _raw_manifest(source_ref, auth_args=source_inspect_auth)
        if source_manifest is None:
            raise ArtifactMirrorError("source OCI artifact was not found")
        source_digest = "sha256:" + hashlib.sha256(source_manifest).hexdigest()
        if source_digest != expected:
            checks = [_failure("source-digest", "source OCI manifest digest does not match the pinned digest", evidence={"observed_digest": source_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        if kind == "helm-chart":
            base_evidence = {**base_evidence, **_validate_helm_manifest(source_manifest), "helm_oci_typed": True}

        current_tag_digest = _raw_manifest_digest(destination_tag_ref, auth_args=destination_inspect_auth, allow_not_found=True)
        if current_tag_digest == expected:
            destination_manifest = _raw_manifest(destination_digest_ref, auth_args=destination_inspect_auth)
            destination_digest = None if destination_manifest is None else "sha256:" + hashlib.sha256(destination_manifest).hexdigest()
            if destination_digest != expected:
                checks = [_failure("destination-digest", "destination OCI digest reference does not verify after tag lookup", evidence={"observed_digest": destination_digest})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
            if kind == "helm-chart" and destination_manifest is not None:
                _validate_helm_manifest(destination_manifest)
            checks = [
                {"id": "source-digest", "status": "PASS", "summary": "source OCI manifest matches the pinned digest", "evidence": {"digest": source_digest}},
                {"id": "destination-digest", "status": "PASS", "summary": "destination OCI tag already resolves to the pinned digest", "evidence": {"digest": destination_digest}},
            ]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "ALREADY_MIRRORED", "digest": expected, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "idempotent": True}}}
        if current_tag_digest and not bool((typed_plan.get("parameters") or {}).get("replace_existing", False)):
            checks = [_failure("destination-digest", "destination OCI tag resolves to a different digest and replace_existing is false", evidence={"observed_digest": current_tag_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        with tempfile.NamedTemporaryFile(prefix=".hermes-skopeo-digest-", delete=False) as digest_file:
            digest_path = Path(digest_file.name)
        try:
            copy_args = [
                "copy",
                *source_copy_auth,
                *destination_copy_auth,
                "--all",
                "--preserve-digests",
                "--retry-times",
                "2",
                "--digestfile",
                str(digest_path),
                source_ref,
                destination_tag_ref,
            ]
            _run_skopeo(copy_args, timeout=min(300, max(30, _timeout_seconds() * 3)))
            reported = digest_path.read_text(encoding="utf-8").strip() if digest_path.exists() else ""
        finally:
            digest_path.unlink(missing_ok=True)
        if reported and reported != expected:
            checks = [_failure("destination-digest", "OCI copy reported a destination digest different from the pinned digest", evidence={"observed_digest": reported})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        tag_manifest = _raw_manifest(destination_tag_ref, auth_args=destination_inspect_auth)
        destination_manifest = _raw_manifest(destination_digest_ref, auth_args=destination_inspect_auth)
        tag_digest = None if tag_manifest is None else "sha256:" + hashlib.sha256(tag_manifest).hexdigest()
        destination_digest = None if destination_manifest is None else "sha256:" + hashlib.sha256(destination_manifest).hexdigest()
        if tag_digest != expected or destination_digest != expected:
            checks = [_failure("destination-digest", "mirrored OCI destination does not resolve to the pinned digest", evidence={"tag_digest": tag_digest, "digest_reference": destination_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        if kind == "helm-chart":
            if tag_manifest is None or destination_manifest is None:
                raise ArtifactMirrorError("mirrored Helm OCI manifest could not be read back")
            _validate_helm_manifest(tag_manifest)
            _validate_helm_manifest(destination_manifest)
        checks = [
            {"id": "source-digest", "status": "PASS", "summary": "source OCI manifest matches the pinned digest", "evidence": {"digest": source_digest}},
            {"id": "destination-digest", "status": "PASS", "summary": "destination OCI tag and digest reference match the pinned digest", "evidence": {"digest": destination_digest}},
        ]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "MIRRORED", "digest": expected, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "idempotent": False}}}
    except ArtifactMirrorError as exc:
        checks = [_failure("artifact-mirror-runtime", str(exc), evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ArtifactMirrorError("artifact source redirects are forbidden")


def _ansible_collection_binding(artifact: dict[str, Any]) -> tuple[str, str, str]:
    labels = artifact.get("labels") if isinstance(artifact.get("labels"), dict) else {}
    unknown = sorted(set(labels) - {"ansible_namespace", "ansible_name"})
    if unknown:
        raise ArtifactMirrorError(f"ansible-collection labels contain unsupported keys: {', '.join(unknown)}")
    namespace = str(labels.get("ansible_namespace") or "")
    name = str(labels.get("ansible_name") or "")
    version = str(artifact.get("version") or "")
    if not _ANSIBLE_COLLECTION_PART_RE.fullmatch(namespace):
        raise ArtifactMirrorError("ansible-collection namespace is invalid")
    if not _ANSIBLE_COLLECTION_PART_RE.fullmatch(name):
        raise ArtifactMirrorError("ansible-collection name is invalid")
    if not _ANSIBLE_COLLECTION_VERSION_RE.fullmatch(version):
        raise ArtifactMirrorError("ansible-collection version must be semantic-version compatible")
    return namespace, name, version


def _safe_tar_member_name(raw: str) -> str:
    if not raw or "\\" in raw or raw.startswith("/"):
        raise ArtifactMirrorError("Ansible collection archive contains an unsafe member path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactMirrorError("Ansible collection archive contains an unsafe member path")
    return path.as_posix()


def _read_tar_json(archive: tarfile.TarFile, member: tarfile.TarInfo, *, name: str) -> tuple[dict[str, Any], bytes]:
    if not member.isfile():
        raise ArtifactMirrorError(f"Ansible collection {name} must be a regular file")
    if member.size < 1 or member.size > _ANSIBLE_COLLECTION_METADATA_LIMIT:
        raise ArtifactMirrorError(f"Ansible collection {name} exceeds the metadata size limit")
    handle = archive.extractfile(member)
    if handle is None:
        raise ArtifactMirrorError(f"Ansible collection {name} could not be read")
    raw = handle.read(_ANSIBLE_COLLECTION_METADATA_LIMIT + 1)
    if len(raw) > _ANSIBLE_COLLECTION_METADATA_LIMIT:
        raise ArtifactMirrorError(f"Ansible collection {name} exceeds the metadata size limit")
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactMirrorError(f"Ansible collection {name} is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ArtifactMirrorError(f"Ansible collection {name} must contain a JSON object")
    return parsed, raw


def _validate_ansible_collection_archive(path: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    namespace, name, version = _ansible_collection_binding(artifact)
    try:
        archive = tarfile.open(path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ArtifactMirrorError("Ansible collection artifact must be a valid gzip-compressed tar archive") from exc
    with archive:
        members = archive.getmembers()
        if not members or len(members) > _ANSIBLE_COLLECTION_MEMBER_LIMIT:
            raise ArtifactMirrorError("Ansible collection archive has an invalid member count")
        by_name: dict[str, tarfile.TarInfo] = {}
        expanded_bytes = 0
        expanded_limit = _max_bytes()
        for member in members:
            member_name = _safe_tar_member_name(member.name)
            if member_name in by_name:
                raise ArtifactMirrorError("Ansible collection archive contains duplicate member names")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ArtifactMirrorError("Ansible collection archive contains unsupported link/device members")
            if not (member.isfile() or member.isdir()):
                raise ArtifactMirrorError("Ansible collection archive contains an unsupported member type")
            if member.size < 0:
                raise ArtifactMirrorError("Ansible collection archive contains an invalid member size")
            if member.isfile():
                expanded_bytes += member.size
                if expanded_bytes > expanded_limit:
                    raise ArtifactMirrorError("Ansible collection expanded content exceeds the configured byte limit")
            by_name[member_name] = member

        manifest_member = by_name.get("MANIFEST.json")
        files_member = by_name.get("FILES.json")
        if manifest_member is None or files_member is None:
            raise ArtifactMirrorError("Ansible collection artifact must contain root MANIFEST.json and FILES.json")
        manifest, _ = _read_tar_json(archive, manifest_member, name="MANIFEST.json")
        files_manifest, files_raw = _read_tar_json(archive, files_member, name="FILES.json")

        if manifest.get("format") != 1:
            raise ArtifactMirrorError("Ansible collection MANIFEST.json format must be 1")
        info = manifest.get("collection_info")
        if not isinstance(info, dict):
            raise ArtifactMirrorError("Ansible collection MANIFEST.json is missing collection_info")
        observed = (str(info.get("namespace") or ""), str(info.get("name") or ""), str(info.get("version") or ""))
        if observed != (namespace, name, version):
            raise ArtifactMirrorError("Ansible collection MANIFEST.json identity/version does not match the approved artifact plan")

        file_manifest_file = manifest.get("file_manifest_file")
        if not isinstance(file_manifest_file, dict) or file_manifest_file.get("name") != "FILES.json":
            raise ArtifactMirrorError("Ansible collection MANIFEST.json must bind FILES.json")
        if str(file_manifest_file.get("chksum_type") or "").lower() != "sha256":
            raise ArtifactMirrorError("Ansible collection FILES.json checksum type must be sha256")
        expected_files_digest = str(file_manifest_file.get("chksum_sha256") or "").lower()
        observed_files_digest = hashlib.sha256(files_raw).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_files_digest) or observed_files_digest != expected_files_digest:
            raise ArtifactMirrorError("Ansible collection FILES.json checksum does not match MANIFEST.json")

        if files_manifest.get("format") != 1 or not isinstance(files_manifest.get("files"), list):
            raise ArtifactMirrorError("Ansible collection FILES.json format is invalid")
        verified_files = 0
        seen_declared: set[str] = set()
        for entry in files_manifest["files"]:
            if not isinstance(entry, dict):
                raise ArtifactMirrorError("Ansible collection FILES.json contains an invalid file entry")
            entry_name = _safe_tar_member_name(str(entry.get("name") or ""))
            if entry_name in seen_declared:
                raise ArtifactMirrorError("Ansible collection FILES.json contains duplicate file entries")
            seen_declared.add(entry_name)
            ftype = str(entry.get("ftype") or "")
            if ftype == "dir":
                continue
            if ftype != "file":
                raise ArtifactMirrorError("Ansible collection FILES.json contains an unsupported file type")
            member = by_name.get(entry_name)
            if member is None or not member.isfile():
                raise ArtifactMirrorError("Ansible collection FILES.json references a missing regular file")
            if str(entry.get("chksum_type") or "").lower() != "sha256":
                raise ArtifactMirrorError("Ansible collection file checksum type must be sha256")
            expected_digest = str(entry.get("chksum_sha256") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                raise ArtifactMirrorError("Ansible collection file checksum is invalid")
            handle = archive.extractfile(member)
            if handle is None:
                raise ArtifactMirrorError("Ansible collection file could not be read")
            digest = hashlib.sha256()
            remaining = member.size
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                digest.update(chunk)
            if remaining != 0 or digest.hexdigest() != expected_digest:
                raise ArtifactMirrorError("Ansible collection file checksum does not match FILES.json")
            verified_files += 1

    return {
        "ansible_namespace": namespace,
        "ansible_name": name,
        "ansible_version": version,
        "files_manifest_sha256": observed_files_digest,
        "verified_regular_files": verified_files,
        "archive_members": len(members),
        "expanded_bytes": expanded_bytes,
    }


def _execute_ansible_collection(typed_plan: dict[str, Any], artifact: dict[str, Any], expected: str, observed_at: int) -> dict[str, Any]:
    artifact_id = str(artifact.get("id") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    capability = runtime_capability(source, destination, kind="ansible-collection")
    base_evidence: dict[str, Any] = {
        "source_scheme": capability["source_scheme"],
        "destination_scheme": capability["destination_scheme"],
        "artifact_kind": "ansible-collection",
        "archive_format": "ansible-galaxy-collection-tar.gz",
        "arbitrary_shell": False,
        "raw_credentials_returned": False,
        "redirects_followed": False,
        "archive_extracted_to_filesystem": False,
        "symlink_members_allowed": False,
    }
    try:
        namespace, name, version = _ansible_collection_binding(artifact)
        base_evidence.update({"ansible_namespace": namespace, "ansible_name": name, "ansible_version": version})
        max_bytes = _max_bytes()
        source_root = _root("HERMES_ARTIFACT_SOURCE_ROOT", "/data/artifact-source")
        mirror_root = _root("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror")
        destination_path = _file_uri_path(destination, root=mirror_root, purpose="Ansible collection destination")
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        if destination_path.exists():
            destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
            if destination_digest == expected:
                archive_evidence = _validate_ansible_collection_archive(destination_path, artifact)
                checks = [
                    {"id": "collection-identity", "status": "PASS", "summary": "existing Ansible collection archive matches the approved namespace/name/version and internal file manifest", "evidence": archive_evidence},
                    {"id": "destination-digest", "status": "PASS", "summary": "existing Ansible collection archive matches the pinned SHA-256 digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
                ]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "ALREADY_MIRRORED", "bytes": destination_bytes, "digest": destination_digest, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, **archive_evidence, "idempotent": True, "atomic_replace": False}}}
            if not bool((typed_plan.get("parameters") or {}).get("replace_existing", False)):
                checks = [_failure("destination-digest", "existing Ansible collection archive differs from the pinned digest and replace_existing is false", evidence={"observed_digest": destination_digest})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        temp_path: Path | None = None
        source_digest = ""
        byte_count = 0
        archive_evidence: dict[str, Any] = {}
        try:
            with tempfile.NamedTemporaryFile(prefix=".hermes-ansible-collection-", suffix=".tar.gz", dir=destination_path.parent, delete=False) as temp:
                temp_path = Path(temp.name)
                if capability["source_scheme"] == "file":
                    source_path = _file_uri_path(source, root=source_root, purpose="Ansible collection source")
                    if not source_path.is_file():
                        raise ArtifactMirrorError("Ansible collection source file does not exist")
                    with source_path.open("rb") as src:
                        source_digest, byte_count = _copy_stream(src, temp, max_bytes=max_bytes)
                else:
                    with _open_https(source) as src:
                        source_digest, byte_count = _copy_stream(src, temp, max_bytes=max_bytes)
            if source_digest != expected:
                temp_path.unlink(missing_ok=True)
                checks = [_failure("source-digest", "fetched Ansible collection archive does not match the pinned digest", evidence={"observed_digest": source_digest, "bytes": byte_count})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
            archive_evidence = _validate_ansible_collection_archive(temp_path, artifact)
            os.replace(temp_path, destination_path)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
        if destination_digest != expected:
            checks = [_failure("destination-digest", "mirrored Ansible collection archive does not match the pinned digest", evidence={"observed_digest": destination_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        destination_evidence = _validate_ansible_collection_archive(destination_path, artifact)
        checks = [
            {"id": "source-digest", "status": "PASS", "summary": "Ansible collection source archive matches the pinned SHA-256 digest", "evidence": {"digest": expected, "bytes": byte_count}},
            {"id": "collection-identity", "status": "PASS", "summary": "Ansible collection archive identity and internal file checksums match the approved plan", "evidence": archive_evidence},
            {"id": "destination-digest", "status": "PASS", "summary": "mirrored Ansible collection archive matches the pinned SHA-256 digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
        ]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "MIRRORED", "bytes": destination_bytes, "digest": destination_digest, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, **destination_evidence, "idempotent": False, "atomic_replace": True}}}
    except ArtifactMirrorError as exc:
        checks = [_failure("artifact-mirror-runtime", str(exc), evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    except (OSError, tarfile.TarError) as exc:
        checks = [_failure("artifact-mirror-runtime", f"Ansible collection mirror I/O/archive validation failed: {type(exc).__name__}", evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}



def _repository_marker(destination_path: Path) -> Path:
    return destination_path / ".hermes-repository-snapshot.json"


def _write_repository_marker(destination_path: Path, *, artifact: dict[str, Any], digest: str, evidence: dict[str, Any]) -> None:
    marker = {
        "schema_version": 1,
        "kind": str(artifact.get("kind") or ""),
        "repository_id": str((artifact.get("labels") or {}).get("repository_id") or ""),
        "version": str(artifact.get("version") or ""),
        "source_digest": digest,
        "snapshot_manifest_sha256": str(evidence.get("snapshot_manifest_sha256") or ""),
    }
    _repository_marker(destination_path).write_text(json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _read_repository_marker(destination_path: Path) -> dict[str, Any] | None:
    marker_path = _repository_marker(destination_path)
    if not marker_path.is_file() or marker_path.is_symlink():
        return None
    try:
        doc = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _execute_repository_snapshot(typed_plan: dict[str, Any], artifact: dict[str, Any], expected: str, observed_at: int) -> dict[str, Any]:
    artifact_id = str(artifact.get("id") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    kind = str(artifact.get("kind") or "")
    capability = runtime_capability(source, destination, kind=kind)
    base_evidence: dict[str, Any] = {
        "source_scheme": capability["source_scheme"],
        "destination_scheme": capability["destination_scheme"],
        "artifact_kind": kind,
        "transport": "signed-repository-snapshot",
        "arbitrary_shell": False,
        "raw_credentials_returned": False,
        "credentials_in_plan": False,
        "credential_delivery": "trusted-environment-authfile-only",
        "redirects_followed": False,
        "network_attempt_limit": 2 if capability["source_scheme"] == "https" else 0,
        "partial_sync_recovery": "atomic-staging-with-rollback",
    }
    try:
        max_bytes = _max_bytes()
        metadata_limit = _repository_metadata_limit()
        expanded_limit = _repository_max_expanded_bytes()
        source_root = _root("HERMES_ARTIFACT_SOURCE_ROOT", "/data/artifact-source")
        mirror_root = _root("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror")
        destination_path = _file_uri_path(destination, root=mirror_root, purpose=f"{kind} destination")
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        if destination_path.exists():
            if not destination_path.is_dir() or destination_path.is_symlink():
                checks = [_failure("destination-tree", "existing repository destination is not a regular directory")]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
            marker = _read_repository_marker(destination_path)
            if marker and marker.get("source_digest") == expected and marker.get("kind") == kind:
                try:
                    repository_evidence = validate_repository_tree(
                        destination_path,
                        artifact,
                        verify_signature=_verify_repository_signature,
                        metadata_limit=metadata_limit,
                    )
                except RepositorySnapshotError as exc:
                    checks = [_failure("destination-tree", f"existing repository snapshot failed validation: {exc}")]
                    return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
                checks = [
                    {"id": "source-digest", "status": "SKIP", "summary": "destination already contains the exact pinned repository snapshot", "evidence": {"reason": "idempotent-hit", "digest": expected}},
                    {"id": "repository-metadata", "status": "PASS", "summary": "existing repository metadata and package/distribution hashes verify", "evidence": repository_evidence},
                    {"id": "destination-tree", "status": "PASS", "summary": "existing repository tree is bound to the pinned snapshot digest", "evidence": {"source_digest": expected}},
                ]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "ALREADY_MIRRORED", "digest": expected, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, **repository_evidence, "idempotent": True, "atomic_replace": False}}}
            if not bool((typed_plan.get("parameters") or {}).get("replace_existing", False)):
                checks = [_failure("destination-tree", "existing repository destination is not the approved snapshot and replace_existing is false")]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        archive_path: Path | None = None
        staging_container: Path | None = None
        backup_path: Path | None = None
        source_digest = ""
        source_bytes = 0
        repository_evidence: dict[str, Any] = {}
        try:
            with tempfile.NamedTemporaryFile(prefix=".hermes-repository-source-", suffix=".tar", dir=destination_path.parent, delete=False) as temp:
                archive_path = Path(temp.name)
                if capability["source_scheme"] == "file":
                    source_path = _file_uri_path(source, root=source_root, purpose=f"{kind} source")
                    if not source_path.is_file():
                        raise ArtifactMirrorError("repository snapshot source file does not exist")
                    with source_path.open("rb") as src:
                        source_digest, source_bytes = _copy_stream(src, temp, max_bytes=max_bytes)
                else:
                    with _open_https(source) as src:
                        source_digest, source_bytes = _copy_stream(src, temp, max_bytes=max_bytes)
            if source_digest != expected:
                checks = [_failure("source-digest", "repository snapshot source does not match the pinned SHA-256 digest", evidence={"observed_digest": source_digest, "bytes": source_bytes})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

            staging_container = Path(tempfile.mkdtemp(prefix=".hermes-repository-stage-", dir=destination_path.parent))
            staging_root = staging_container / "snapshot"
            archive_evidence = extract_snapshot_archive(
                archive_path,
                staging_root,
                artifact,
                max_expanded_bytes=expanded_limit,
            )
            repository_evidence = validate_repository_tree(
                staging_root,
                artifact,
                verify_signature=_verify_repository_signature,
                metadata_limit=metadata_limit,
            )
            repository_evidence = {**archive_evidence, **repository_evidence}
            _write_repository_marker(staging_root, artifact=artifact, digest=expected, evidence=repository_evidence)

            if destination_path.exists():
                backup_path = Path(tempfile.mkdtemp(prefix=".hermes-repository-backup-", dir=destination_path.parent))
                backup_path.rmdir()
                os.replace(destination_path, backup_path)
            try:
                os.replace(staging_root, destination_path)
            except Exception:
                if backup_path is not None and backup_path.exists() and not destination_path.exists():
                    os.replace(backup_path, destination_path)
                    backup_path = None
                raise
            if backup_path is not None and backup_path.exists():
                shutil.rmtree(backup_path)
                backup_path = None
        finally:
            if archive_path is not None:
                archive_path.unlink(missing_ok=True)
            if staging_container is not None and staging_container.exists():
                shutil.rmtree(staging_container)
            if backup_path is not None and backup_path.exists():
                if not destination_path.exists():
                    os.replace(backup_path, destination_path)
                else:
                    shutil.rmtree(backup_path)

        destination_evidence = validate_repository_tree(
            destination_path,
            artifact,
            verify_signature=_verify_repository_signature,
            metadata_limit=metadata_limit,
        )
        marker = _read_repository_marker(destination_path)
        if not marker or marker.get("source_digest") != expected:
            checks = [_failure("destination-tree", "published repository snapshot marker does not match the pinned source digest")]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        checks = [
            {"id": "source-digest", "status": "PASS", "summary": "repository snapshot source archive matches the pinned SHA-256 digest", "evidence": {"digest": source_digest, "bytes": source_bytes}},
            {"id": "repository-metadata", "status": "PASS", "summary": "repository metadata, signatures/hashes and referenced payloads verify", "evidence": repository_evidence},
            {"id": "destination-tree", "status": "PASS", "summary": "repository snapshot was published atomically and revalidated from the destination tree", "evidence": {"source_digest": expected, **destination_evidence}},
        ]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "MIRRORED", "bytes": source_bytes, "digest": expected, "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, **destination_evidence, "idempotent": False, "atomic_replace": True}}}
    except (ArtifactMirrorError, RepositorySnapshotError) as exc:
        checks = [_failure("artifact-mirror-runtime", str(exc), evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    except OSError as exc:
        checks = [_failure("artifact-mirror-runtime", f"repository snapshot mirror I/O failed: {type(exc).__name__}", evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}


def _max_bytes() -> int:
    raw = os.getenv("HERMES_ARTIFACT_MIRROR_MAX_BYTES", str(512 * 1024 * 1024))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ArtifactMirrorError("HERMES_ARTIFACT_MIRROR_MAX_BYTES must be an integer") from exc
    if value < 1 or value > 4 * 1024 * 1024 * 1024:
        raise ArtifactMirrorError("artifact mirror byte limit must be between 1 and 4294967296")
    return value


def _timeout_seconds() -> int:
    raw = os.getenv("HERMES_ARTIFACT_MIRROR_TIMEOUT_SECONDS", "60")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ArtifactMirrorError("HERMES_ARTIFACT_MIRROR_TIMEOUT_SECONDS must be an integer") from exc
    if value < 1 or value > 300:
        raise ArtifactMirrorError("artifact mirror timeout must be between 1 and 300 seconds")
    return value


def _root(name: str, default: str) -> Path:
    root = Path(os.getenv(name, default)).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _file_uri_path(uri: str, *, root: Path, purpose: str) -> Path:
    parsed = urlparse(uri)
    if parsed.scheme != "file" or parsed.params or parsed.query or parsed.fragment:
        raise ArtifactMirrorError(f"{purpose} must be a plain file:// URI")
    if parsed.username is not None or parsed.password is not None:
        raise ArtifactMirrorError(f"embedded credentials are forbidden in {purpose}")
    if parsed.netloc not in {"", "localhost"}:
        raise ArtifactMirrorError(f"remote file hosts are forbidden in {purpose}")
    candidate = Path(unquote(parsed.path))
    if not candidate.is_absolute():
        raise ArtifactMirrorError(f"{purpose} file path must be absolute")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArtifactMirrorError(f"{purpose} escapes the configured root") from exc
    current = root
    for part in resolved.relative_to(root).parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ArtifactMirrorError(f"symlinked directories are forbidden in {purpose}")
    if resolved.exists() and resolved.is_symlink():
        raise ArtifactMirrorError(f"symlink destinations/sources are forbidden in {purpose}")
    return resolved


def _https_host_allowed(hostname: str) -> bool:
    raw = os.getenv("HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST", "")
    allowed = {item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()}
    host = hostname.lower().rstrip(".")
    return bool(allowed) and host in allowed


def _validate_https_source(uri: str) -> None:
    parsed = urlparse(uri)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ArtifactMirrorError("network artifact sources must use https://")
    if parsed.username is not None or parsed.password is not None:
        raise ArtifactMirrorError("embedded credentials are forbidden in artifact source")
    if parsed.fragment:
        raise ArtifactMirrorError("artifact source fragments are forbidden")
    if not _https_host_allowed(parsed.hostname):
        raise ArtifactMirrorError("artifact HTTPS source host is not allowlisted")


def _sha256_path(path: Path, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ArtifactMirrorError("artifact exceeds configured byte limit")
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}", total


def _copy_stream(source: BinaryIO, destination: BinaryIO, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ArtifactMirrorError("artifact exceeds configured byte limit")
        digest.update(chunk)
        destination.write(chunk)
    destination.flush()
    os.fsync(destination.fileno())
    return f"sha256:{digest.hexdigest()}", total


def _open_https(uri: str):  # noqa: ANN202
    _validate_https_source(uri)
    opener = urllib.request.build_opener(_NoRedirect())
    headers = {"User-Agent": "Hermes-Artifact-Mirror/0.5.11"}
    authorization = _https_authorization_header(uri)
    if authorization is not None:
        headers["Authorization"] = authorization
    request = urllib.request.Request(uri, method="GET", headers=headers)
    last_error: Exception | None = None
    for attempt in range(1, 3):
        try:
            response = opener.open(request, timeout=_timeout_seconds())
            length = response.headers.get("Content-Length")
            if length:
                try:
                    if int(length) > _max_bytes():
                        response.close()
                        raise ArtifactMirrorError("artifact exceeds configured byte limit")
                except ValueError:
                    response.close()
                    raise ArtifactMirrorError("invalid artifact Content-Length")
            return response
        except ArtifactMirrorError:
            raise
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code < 500 or attempt == 2:
                raise ArtifactMirrorError(f"artifact HTTPS fetch failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError, socket.timeout) as exc:
            last_error = exc
            if attempt == 2:
                raise ArtifactMirrorError(f"artifact HTTPS fetch failed: {type(exc).__name__}") from exc
    raise ArtifactMirrorError(f"artifact HTTPS fetch failed: {type(last_error).__name__ if last_error else 'unknown'}")


def runtime_capability(source: str, destination: str, *, kind: str = "") -> dict[str, Any]:
    source_scheme = urlparse(source).scheme.lower()
    destination_scheme = urlparse(destination).scheme.lower()
    git_release_capable = kind == "git-release" and source_scheme == "https" and destination_scheme == "file"
    ansible_collection_capable = kind == "ansible-collection" and source_scheme in {"file", "https"} and destination_scheme == "file"
    repository_capable = kind in REPOSITORY_KINDS and source_scheme in {"file", "https"} and destination_scheme == "file"
    blob_capable = source_scheme in {"file", "https"} and destination_scheme == "file" and not git_release_capable and not ansible_collection_capable and not repository_capable
    oci_capable = kind in {"oci-image", "helm-chart"} and source_scheme == "oci" and destination_scheme == "oci"
    capable = blob_capable or oci_capable or git_release_capable or ansible_collection_capable or repository_capable
    return {
        "capable": capable,
        "executor": "artifact-mirror-worker" if capable else "artifact-mirror-contract",
        "source_scheme": source_scheme,
        "destination_scheme": destination_scheme,
        "credential_delivery": "none-inline; trusted environment-mounted authfiles/keyrings only",
        "redirects_allowed": False,
        "digest_algorithm": "sha256",
        "network_attempt_limit": 2 if source_scheme == "https" else 0,
    }


def _failure(check_id: str, summary: str, *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": check_id, "status": "FAIL", "summary": summary[:1000], "evidence": evidence or {}}


def execute(typed_plan: dict[str, Any]) -> dict[str, Any]:
    artifact = typed_plan.get("artifact") if isinstance(typed_plan.get("artifact"), dict) else {}
    expected = str(artifact.get("digest") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    artifact_id = str(artifact.get("id") or "")
    observed_at = int(time.time())
    capability = runtime_capability(source, destination, kind=str(artifact.get("kind") or ""))
    base_evidence = {
        "source_scheme": capability["source_scheme"],
        "destination_scheme": capability["destination_scheme"],
        "arbitrary_shell": False,
        "raw_credentials_returned": False,
        "redirects_followed": False,
    }
    if typed_plan.get("operation") != "artifact.mirror.apply" or typed_plan.get("mutation_gate") != "changeset-exact-hash-approval":
        checks = [_failure("artifact-plan-binding", "artifact mirror plan is not governed by the required ChangeSet mutation gate")]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    if not capability["capable"]:
        checks = [_failure("artifact-runtime-capability", "artifact source/destination protocol pair is not implemented by the trusted mirror runtime", evidence=capability)]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    if not expected.startswith("sha256:") or len(expected) != 71:
        checks = [_failure("source-digest", "artifact plan is missing a pinned sha256 digest")]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    if str(artifact.get("kind") or "") == "git-release" and capability["source_scheme"] == "https" and capability["destination_scheme"] == "file":
        return _execute_git_release(typed_plan, artifact, expected, observed_at)
    if str(artifact.get("kind") or "") == "ansible-collection" and capability["source_scheme"] in {"file", "https"} and capability["destination_scheme"] == "file":
        return _execute_ansible_collection(typed_plan, artifact, expected, observed_at)
    if str(artifact.get("kind") or "") in REPOSITORY_KINDS and capability["source_scheme"] in {"file", "https"} and capability["destination_scheme"] == "file":
        return _execute_repository_snapshot(typed_plan, artifact, expected, observed_at)
    if capability["source_scheme"] == "oci" and capability["destination_scheme"] == "oci":
        return _execute_oci(typed_plan, artifact, expected, observed_at)

    max_bytes = _max_bytes()
    source_root = _root("HERMES_ARTIFACT_SOURCE_ROOT", "/data/artifact-source")
    mirror_root = _root("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror")
    try:
        destination_path = _file_uri_path(destination, root=mirror_root, purpose="artifact destination")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.exists():
            destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
            if destination_digest == expected:
                checks = [
                    {"id": "source-digest", "status": "SKIP", "summary": "destination already contains the pinned artifact; source re-fetch was not required", "evidence": {"reason": "idempotent-hit"}},
                    {"id": "destination-digest", "status": "PASS", "summary": "existing mirrored artifact matches the pinned digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
                ]
                return {
                    "schema_version": 1,
                    "artifact_id": artifact_id,
                    "state": "ALREADY_MIRRORED",
                    "bytes": destination_bytes,
                    "digest": destination_digest,
                    "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "atomic_replace": False, "idempotent": True}},
                }
            if not bool((typed_plan.get("parameters") or {}).get("replace_existing", False)):
                checks = [_failure("destination-digest", "existing destination digest differs from the pinned artifact and replace_existing is false", evidence={"observed_digest": destination_digest})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        temp_path: Path | None = None
        source_digest = ""
        byte_count = 0
        try:
            with tempfile.NamedTemporaryFile(prefix=".hermes-artifact-", dir=destination_path.parent, delete=False) as temp:
                temp_path = Path(temp.name)
                if capability["source_scheme"] == "file":
                    source_path = _file_uri_path(source, root=source_root, purpose="artifact source")
                    if not source_path.is_file():
                        raise ArtifactMirrorError("artifact source file does not exist")
                    with source_path.open("rb") as src:
                        source_digest, byte_count = _copy_stream(src, temp, max_bytes=max_bytes)
                else:
                    with _open_https(source) as src:
                        source_digest, byte_count = _copy_stream(src, temp, max_bytes=max_bytes)
            if source_digest != expected:
                temp_path.unlink(missing_ok=True)
                checks = [_failure("source-digest", "fetched artifact digest does not match the pinned digest", evidence={"observed_digest": source_digest, "bytes": byte_count})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
            os.replace(temp_path, destination_path)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        destination_digest, destination_bytes = _sha256_path(destination_path, max_bytes=max_bytes)
        if destination_digest != expected:
            checks = [
                {"id": "source-digest", "status": "PASS", "summary": "source artifact matches the pinned digest", "evidence": {"digest": source_digest, "bytes": byte_count}},
                _failure("destination-digest", "mirrored destination digest does not match the pinned digest", evidence={"observed_digest": destination_digest}),
            ]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
        checks = [
            {"id": "source-digest", "status": "PASS", "summary": "source artifact matches the pinned digest", "evidence": {"digest": source_digest, "bytes": byte_count}},
            {"id": "destination-digest", "status": "PASS", "summary": "mirrored destination matches the pinned digest", "evidence": {"digest": destination_digest, "bytes": destination_bytes}},
        ]
        return {
            "schema_version": 1,
            "artifact_id": artifact_id,
            "state": "MIRRORED",
            "bytes": destination_bytes,
            "digest": destination_digest,
            "verification": {"observed_at": observed_at, "checks": checks, "evidence": {**base_evidence, "atomic_replace": True, "idempotent": False}},
        }
    except ArtifactMirrorError as exc:
        checks = [_failure("artifact-mirror-runtime", str(exc), evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
    except OSError as exc:
        checks = [_failure("artifact-mirror-runtime", f"artifact mirror I/O failed: {type(exc).__name__}", evidence={"error_type": type(exc).__name__})]
        return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
