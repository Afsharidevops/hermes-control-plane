from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse
import re


class ArtifactMirrorError(RuntimeError):
    pass




_OCI_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_OCI_REPOSITORY_RE = re.compile(r"^[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*)*$")


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


def _raw_manifest_digest(reference: str, *, auth_args: list[str], allow_not_found: bool = False) -> str | None:
    completed = _run_skopeo(["inspect", *auth_args, "--raw", reference], allow_not_found=allow_not_found)
    if completed is None:
        return None
    return "sha256:" + hashlib.sha256(completed.stdout).hexdigest()


def _execute_oci(typed_plan: dict[str, Any], artifact: dict[str, Any], expected: str, observed_at: int) -> dict[str, Any]:
    artifact_id = str(artifact.get("id") or "")
    source = str(artifact.get("source") or "")
    destination = str(artifact.get("destination") or "")
    version = str(artifact.get("version") or "")
    base_evidence = {
        "source_scheme": "oci",
        "destination_scheme": "oci",
        "transport": "skopeo-docker-registry",
        "multi_arch": "all",
        "preserve_digests": True,
        "arbitrary_shell": False,
        "raw_credentials_returned": False,
        "authfiles_from_environment_only": True,
    }
    try:
        if artifact.get("kind") != "oci-image":
            raise ArtifactMirrorError("OCI registry runtime is limited to artifact kind oci-image")
        if not _OCI_TAG_RE.fullmatch(version):
            raise ArtifactMirrorError("OCI artifact version must be a valid immutable destination tag")
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

        source_digest = _raw_manifest_digest(source_ref, auth_args=source_inspect_auth)
        if source_digest != expected:
            checks = [_failure("source-digest", "source OCI manifest digest does not match the pinned digest", evidence={"observed_digest": source_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}

        current_tag_digest = _raw_manifest_digest(destination_tag_ref, auth_args=destination_inspect_auth, allow_not_found=True)
        if current_tag_digest == expected:
            destination_digest = _raw_manifest_digest(destination_digest_ref, auth_args=destination_inspect_auth)
            if destination_digest != expected:
                checks = [_failure("destination-digest", "destination OCI digest reference does not verify after tag lookup", evidence={"observed_digest": destination_digest})]
                return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
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

        tag_digest = _raw_manifest_digest(destination_tag_ref, auth_args=destination_inspect_auth)
        destination_digest = _raw_manifest_digest(destination_digest_ref, auth_args=destination_inspect_auth)
        if tag_digest != expected or destination_digest != expected:
            checks = [_failure("destination-digest", "mirrored OCI destination does not resolve to the pinned digest", evidence={"tag_digest": tag_digest, "digest_reference": destination_digest})]
            return {"schema_version": 1, "artifact_id": artifact_id, "state": "FAILED", "verification": {"observed_at": observed_at, "checks": checks, "evidence": base_evidence}}
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
    request = urllib.request.Request(uri, method="GET", headers={"User-Agent": "Hermes-Artifact-Mirror/0.5.11-dev.5"})
    try:
        response = opener.open(request, timeout=_timeout_seconds())
    except ArtifactMirrorError:
        raise
    except (urllib.error.URLError, OSError, socket.timeout) as exc:
        raise ArtifactMirrorError(f"artifact HTTPS fetch failed: {type(exc).__name__}") from exc
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


def runtime_capability(source: str, destination: str, *, kind: str = "") -> dict[str, Any]:
    source_scheme = urlparse(source).scheme.lower()
    destination_scheme = urlparse(destination).scheme.lower()
    blob_capable = source_scheme in {"file", "https"} and destination_scheme == "file"
    oci_capable = kind == "oci-image" and source_scheme == "oci" and destination_scheme == "oci"
    capable = blob_capable or oci_capable
    return {
        "capable": capable,
        "executor": "artifact-mirror-worker" if capable else "artifact-mirror-contract",
        "source_scheme": source_scheme,
        "destination_scheme": destination_scheme,
        "credential_delivery": "none-inline; OCI authfiles are trusted environment-mounted files only",
        "redirects_allowed": False,
        "digest_algorithm": "sha256",
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
