from __future__ import annotations

import hashlib
import os
import socket
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse


class ArtifactMirrorError(RuntimeError):
    pass


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


def runtime_capability(source: str, destination: str) -> dict[str, Any]:
    source_scheme = urlparse(source).scheme.lower()
    destination_scheme = urlparse(destination).scheme.lower()
    capable = source_scheme in {"file", "https"} and destination_scheme == "file"
    return {
        "capable": capable,
        "executor": "artifact-mirror-worker" if capable else "artifact-mirror-contract",
        "source_scheme": source_scheme,
        "destination_scheme": destination_scheme,
        "credential_delivery": "none-inline; authenticated registry/repository protocols remain separate runtime work",
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
    capability = runtime_capability(source, destination)
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
