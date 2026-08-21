from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import lzma
import re
import tarfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import unquote, urlparse


class RepositorySnapshotError(RuntimeError):
    pass


SNAPSHOT_MANIFEST = "HERMES-REPOSITORY-SNAPSHOT.json"
REPOSITORY_KINDS = frozenset({"apt-repository", "rpm-repository", "python-repository"})
_MANIFEST_MAX_BYTES = 4 * 1024 * 1024
_MEMBER_LIMIT = 100000
_REPOSITORY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_APT_DIST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PY_DIST_SUFFIXES = (".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip")


def _sha256_path(path: Path) -> tuple[str, int]:
    if not path.is_file() or path.is_symlink():
        raise RepositorySnapshotError(f"repository snapshot referenced file is missing or unsafe: {path.name}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total


def _safe_relpath(raw: str, *, purpose: str) -> str:
    if not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw:
        raise RepositorySnapshotError(f"{purpose} contains an unsafe path")
    if "//" in raw:
        raise RepositorySnapshotError(f"{purpose} contains an unsafe path")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise RepositorySnapshotError(f"{purpose} contains an unsafe path")
    normalized = pure.as_posix()
    if normalized != raw.rstrip("/"):
        raise RepositorySnapshotError(f"{purpose} contains a non-canonical path")
    return normalized


def _read_limited(path: Path, *, limit: int, purpose: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise RepositorySnapshotError(f"{purpose} must be a regular file")
    size = path.stat().st_size
    if size < 0 or size > limit:
        raise RepositorySnapshotError(f"{purpose} exceeds the configured metadata size limit")
    data = path.read_bytes()
    if len(data) != size:
        raise RepositorySnapshotError(f"{purpose} could not be read completely")
    return data


def _snapshot_binding(artifact: dict[str, Any]) -> tuple[str, str, str]:
    kind = str(artifact.get("kind") or "")
    if kind not in REPOSITORY_KINDS:
        raise RepositorySnapshotError("unsupported repository snapshot kind")
    version = str(artifact.get("version") or "").strip()
    if not version or len(version) > 160:
        raise RepositorySnapshotError("repository snapshot version is invalid")
    labels = artifact.get("labels") if isinstance(artifact.get("labels"), dict) else {}
    repository_id = str(labels.get("repository_id") or "")
    if not _REPOSITORY_ID_RE.fullmatch(repository_id):
        raise RepositorySnapshotError("repository snapshot repository_id is invalid")
    allowed_by_kind = {
        "apt-repository": {"repository_id", "apt_distribution", "apt_components", "apt_architectures", "signature_policy", "component", "depends_on"},
        "rpm-repository": {"repository_id", "signature_policy", "component", "depends_on"},
        "python-repository": {"repository_id", "signature_policy", "component", "depends_on"},
    }
    unknown = sorted(set(labels) - allowed_by_kind[kind])
    if unknown:
        raise RepositorySnapshotError(f"repository snapshot labels contain unsupported keys: {', '.join(unknown)}")
    signature_policy = str(labels.get("signature_policy") or "")
    if kind in {"apt-repository", "rpm-repository"} and signature_policy != "required":
        raise RepositorySnapshotError(f"{kind} signature_policy must be required")
    if kind == "python-repository" and signature_policy not in {"sha256", "pep503-sha256"}:
        raise RepositorySnapshotError("python-repository signature_policy must be pep503-sha256")
    return kind, version, repository_id


def _load_snapshot_manifest(root: Path, artifact: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    kind, version, repository_id = _snapshot_binding(artifact)
    manifest_path = root / SNAPSHOT_MANIFEST
    raw = _read_limited(manifest_path, limit=_MANIFEST_MAX_BYTES, purpose="repository snapshot manifest")
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepositorySnapshotError("repository snapshot manifest is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise RepositorySnapshotError("repository snapshot manifest schema_version must be 1")
    if doc.get("kind") != kind or str(doc.get("version") or "") != version or str(doc.get("repository_id") or "") != repository_id:
        raise RepositorySnapshotError("repository snapshot manifest identity does not match the approved artifact plan")
    files = doc.get("files")
    if not isinstance(files, list) or not files:
        raise RepositorySnapshotError("repository snapshot manifest files must be a non-empty list")
    manifest_entries: dict[str, dict[str, Any]] = {}
    for entry in files:
        if not isinstance(entry, dict):
            raise RepositorySnapshotError("repository snapshot manifest contains an invalid file entry")
        path = _safe_relpath(str(entry.get("path") or ""), purpose="repository snapshot manifest")
        if path == SNAPSHOT_MANIFEST or path in manifest_entries:
            raise RepositorySnapshotError("repository snapshot manifest contains duplicate/reserved file entries")
        digest = str(entry.get("sha256") or "").lower()
        size = entry.get("size")
        if not _SHA256_RE.fullmatch(digest) or not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RepositorySnapshotError("repository snapshot manifest contains invalid SHA-256/size metadata")
        manifest_entries[path] = {"sha256": digest, "size": size}

    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != ".hermes-repository-snapshot.json"
    }
    expected = {SNAPSHOT_MANIFEST, *manifest_entries}
    if actual != expected:
        raise RepositorySnapshotError("repository snapshot file inventory does not match its manifest")

    for rel, entry in manifest_entries.items():
        path = root / rel
        if path.is_symlink() or not path.is_file():
            raise RepositorySnapshotError("repository snapshot manifest references a non-regular file")
        digest, size = _sha256_path(path)
        if digest != entry["sha256"] or size != entry["size"]:
            raise RepositorySnapshotError(f"repository snapshot file checksum/size mismatch: {rel}")
    return doc, manifest_entries


def extract_snapshot_archive(archive_path: Path, destination_root: Path, artifact: dict[str, Any], *, max_expanded_bytes: int) -> dict[str, Any]:
    if destination_root.exists():
        raise RepositorySnapshotError("repository snapshot staging directory already exists")
    destination_root.mkdir(parents=True, mode=0o700)
    expanded_bytes = 0
    member_names: set[str] = set()
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MEMBER_LIMIT:
                raise RepositorySnapshotError("repository snapshot archive has an invalid member count")
            for member in members:
                raw_name = member.name.rstrip("/") if member.isdir() else member.name
                rel = _safe_relpath(raw_name, purpose="repository snapshot archive")
                if rel in member_names:
                    raise RepositorySnapshotError("repository snapshot archive contains duplicate member names")
                member_names.add(rel)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise RepositorySnapshotError("repository snapshot archive contains unsupported link/device members")
                target = destination_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.size < 0:
                    raise RepositorySnapshotError("repository snapshot archive contains an unsupported member type")
                expanded_bytes += member.size
                if expanded_bytes > max_expanded_bytes:
                    raise RepositorySnapshotError("repository snapshot expanded content exceeds the configured byte limit")
                source = archive.extractfile(member)
                if source is None:
                    raise RepositorySnapshotError("repository snapshot archive member could not be read")
                remaining = member.size
                with target.open("xb") as handle:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        handle.write(chunk)
                        remaining -= len(chunk)
                if remaining != 0:
                    raise RepositorySnapshotError("repository snapshot archive member was truncated")
        doc, entries = _load_snapshot_manifest(destination_root, artifact)
        return {
            "archive_members": len(member_names),
            "expanded_bytes": expanded_bytes,
            "snapshot_manifest_sha256": hashlib.sha256((destination_root / SNAPSHOT_MANIFEST).read_bytes()).hexdigest(),
            "snapshot_files": len(entries),
            "repository_id": doc["repository_id"],
        }
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, RepositorySnapshotError):
            raise
        raise RepositorySnapshotError(f"repository snapshot archive validation failed: {type(exc).__name__}") from exc


def _parse_control_paragraphs(text: str) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue
        if raw[:1].isspace():
            if last_key is not None:
                current[last_key] = current[last_key] + "\n" + raw.strip()
            continue
        if ":" not in raw:
            raise RepositorySnapshotError("APT metadata contains a malformed control line")
        key, value = raw.split(":", 1)
        current[key] = value.strip()
        last_key = key
    if current:
        paragraphs.append(current)
    return paragraphs


def _parse_release_sha256(text: str) -> tuple[dict[str, tuple[str, int]], dict[str, str]]:
    checksums: dict[str, tuple[str, int]] = {}
    fields: dict[str, str] = {}
    in_sha = False
    for raw in text.splitlines():
        if raw == "SHA256:":
            in_sha = True
            continue
        if raw and not raw[:1].isspace():
            in_sha = False
            if ":" in raw:
                key, value = raw.split(":", 1)
                fields[key] = value.strip()
            continue
        if in_sha and raw.strip():
            parts = raw.split()
            if len(parts) != 3 or not _SHA256_RE.fullmatch(parts[0].lower()):
                raise RepositorySnapshotError("APT Release SHA256 section is malformed")
            try:
                size = int(parts[1])
            except ValueError as exc:
                raise RepositorySnapshotError("APT Release SHA256 section has an invalid size") from exc
            rel = _safe_relpath(parts[2], purpose="APT Release SHA256 entry")
            checksums[rel] = (parts[0].lower(), size)
    if not checksums:
        raise RepositorySnapshotError("APT Release file contains no SHA256 index bindings")
    return checksums, fields


def _decompress_metadata(path: Path, *, max_bytes: int) -> bytes:
    data = path.read_bytes()
    try:
        if path.name.endswith(".gz"):
            result = gzip.decompress(data)
        elif path.name.endswith(".xz"):
            result = lzma.decompress(data)
        elif path.name.endswith(".bz2"):
            result = bz2.decompress(data)
        else:
            result = data
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise RepositorySnapshotError(f"repository metadata decompression failed: {path.name}") from exc
    if len(result) > max_bytes:
        raise RepositorySnapshotError("repository metadata expanded content exceeds the configured byte limit")
    return result


def validate_apt_repository(root: Path, artifact: dict[str, Any], *, verify_signature: Callable[[Path, Path], None], metadata_limit: int) -> dict[str, Any]:
    labels = artifact.get("labels") if isinstance(artifact.get("labels"), dict) else {}
    distribution = str(labels.get("apt_distribution") or "")
    if not _APT_DIST_RE.fullmatch(distribution):
        raise RepositorySnapshotError("apt-repository apt_distribution is invalid")
    release = root / "dists" / distribution / "Release"
    signature = root / "dists" / distribution / "Release.gpg"
    release_raw = _read_limited(release, limit=metadata_limit, purpose="APT Release")
    _read_limited(signature, limit=metadata_limit, purpose="APT Release.gpg")
    verify_signature(release, signature)
    try:
        release_text = release_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositorySnapshotError("APT Release file is not UTF-8") from exc
    release_checksums, release_fields = _parse_release_sha256(release_text)
    if distribution not in {release_fields.get("Suite"), release_fields.get("Codename")}:
        raise RepositorySnapshotError("APT Release Suite/Codename does not match apt_distribution")

    configured_components = {item for item in str(labels.get("apt_components") or "").split(",") if item}
    configured_arches = {item for item in str(labels.get("apt_architectures") or "").split(",") if item}
    if configured_components:
        release_components = set((release_fields.get("Components") or "").split())
        if not configured_components.issubset(release_components):
            raise RepositorySnapshotError("APT Release Components do not cover the approved component set")
    if configured_arches:
        release_arches = set((release_fields.get("Architectures") or "").split())
        if not configured_arches.issubset(release_arches):
            raise RepositorySnapshotError("APT Release Architectures do not cover the approved architecture set")

    package_indexes = sorted(
        p for p in (root / "dists" / distribution).rglob("Packages*")
        if p.is_file() and p.name in {"Packages", "Packages.gz", "Packages.xz"}
    )
    if not package_indexes:
        raise RepositorySnapshotError("APT repository snapshot contains no supported Packages index")
    referenced_packages: set[str] = set()
    verified_indexes = 0
    for index in package_indexes:
        rel_from_release = index.relative_to(root / "dists" / distribution).as_posix()
        binding = release_checksums.get(rel_from_release)
        if binding is None:
            raise RepositorySnapshotError(f"APT Packages index is not bound by Release SHA256: {rel_from_release}")
        observed, size = _sha256_path(index)
        if (observed, size) != binding:
            raise RepositorySnapshotError(f"APT Packages index checksum/size does not match Release: {rel_from_release}")
        try:
            package_text = _decompress_metadata(index, max_bytes=metadata_limit).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositorySnapshotError("APT Packages index is not UTF-8") from exc
        for stanza in _parse_control_paragraphs(package_text):
            filename = _safe_relpath(str(stanza.get("Filename") or ""), purpose="APT Packages Filename")
            digest = str(stanza.get("SHA256") or "").lower()
            if not _SHA256_RE.fullmatch(digest):
                raise RepositorySnapshotError("APT Packages stanza is missing a valid SHA256")
            try:
                expected_size = int(str(stanza.get("Size") or ""))
            except ValueError as exc:
                raise RepositorySnapshotError("APT Packages stanza has an invalid Size") from exc
            package_path = root / filename
            observed_digest, observed_size = _sha256_path(package_path)
            if observed_digest != digest or observed_size != expected_size:
                raise RepositorySnapshotError(f"APT package checksum/size mismatch: {filename}")
            referenced_packages.add(filename)
        verified_indexes += 1

    actual_packages = {p.relative_to(root).as_posix() for p in root.rglob("*.deb") if p.is_file()}
    if not actual_packages or actual_packages != referenced_packages:
        raise RepositorySnapshotError("APT repository package inventory does not exactly match Packages metadata")
    return {
        "repository_format": "apt",
        "apt_distribution": distribution,
        "release_signature_verified": True,
        "release_sha256_entries": len(release_checksums),
        "verified_package_indexes": verified_indexes,
        "verified_packages": len(referenced_packages),
        "provenance_chain": "gpgv-release->sha256-packages-index->sha256-deb",
    }


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def validate_rpm_repository(root: Path, artifact: dict[str, Any], *, verify_signature: Callable[[Path, Path], None], metadata_limit: int) -> dict[str, Any]:
    repomd = root / "repodata" / "repomd.xml"
    signature = root / "repodata" / "repomd.xml.asc"
    repomd_raw = _read_limited(repomd, limit=metadata_limit, purpose="RPM repomd.xml")
    _read_limited(signature, limit=metadata_limit, purpose="RPM repomd.xml.asc")
    verify_signature(repomd, signature)
    try:
        doc = ET.fromstring(repomd_raw)
    except ET.ParseError as exc:
        raise RepositorySnapshotError("RPM repomd.xml is malformed") from exc

    primary_path: Path | None = None
    verified_metadata = 0
    for data in doc.iter():
        if _xml_local(data.tag) != "data":
            continue
        data_type = str(data.attrib.get("type") or "")
        location = next((child for child in data if _xml_local(child.tag) == "location"), None)
        checksum = next((child for child in data if _xml_local(child.tag) == "checksum"), None)
        size_node = next((child for child in data if _xml_local(child.tag) == "size"), None)
        if location is None or checksum is None:
            raise RepositorySnapshotError("RPM repomd.xml data entry is missing location/checksum")
        href = _safe_relpath(str(location.attrib.get("href") or ""), purpose="RPM repomd.xml location")
        if str(checksum.attrib.get("type") or "").lower() != "sha256" or not _SHA256_RE.fullmatch((checksum.text or "").strip().lower()):
            raise RepositorySnapshotError("RPM repomd.xml metadata checksum must be SHA-256")
        path = root / href
        observed_digest, observed_size = _sha256_path(path)
        if observed_digest != (checksum.text or "").strip().lower():
            raise RepositorySnapshotError(f"RPM metadata checksum mismatch: {href}")
        if size_node is not None and (size_node.text or "").strip():
            try:
                expected_size = int((size_node.text or "").strip())
            except ValueError as exc:
                raise RepositorySnapshotError("RPM repomd.xml metadata size is invalid") from exc
            if observed_size != expected_size:
                raise RepositorySnapshotError(f"RPM metadata size mismatch: {href}")
        verified_metadata += 1
        if data_type == "primary":
            primary_path = path
    if primary_path is None:
        raise RepositorySnapshotError("RPM repository snapshot has no primary metadata")

    primary_raw = _decompress_metadata(primary_path, max_bytes=metadata_limit)
    try:
        primary_doc = ET.fromstring(primary_raw)
    except ET.ParseError as exc:
        raise RepositorySnapshotError("RPM primary metadata is malformed") from exc
    referenced_packages: set[str] = set()
    for package in primary_doc.iter():
        if _xml_local(package.tag) != "package":
            continue
        location = next((child for child in package if _xml_local(child.tag) == "location"), None)
        checksum = next((child for child in package if _xml_local(child.tag) == "checksum"), None)
        size_node = next((child for child in package if _xml_local(child.tag) == "size"), None)
        if location is None or checksum is None:
            raise RepositorySnapshotError("RPM primary package entry is missing location/checksum")
        href = _safe_relpath(str(location.attrib.get("href") or ""), purpose="RPM package location")
        digest = (checksum.text or "").strip().lower()
        if str(checksum.attrib.get("type") or "").lower() != "sha256" or not _SHA256_RE.fullmatch(digest):
            raise RepositorySnapshotError("RPM package checksum must be SHA-256")
        path = root / href
        observed_digest, observed_size = _sha256_path(path)
        if observed_digest != digest:
            raise RepositorySnapshotError(f"RPM package checksum mismatch: {href}")
        if size_node is not None and size_node.attrib.get("package"):
            try:
                expected_size = int(size_node.attrib["package"])
            except ValueError as exc:
                raise RepositorySnapshotError("RPM package size is invalid") from exc
            if observed_size != expected_size:
                raise RepositorySnapshotError(f"RPM package size mismatch: {href}")
        referenced_packages.add(href)
    actual_packages = {p.relative_to(root).as_posix() for p in root.rglob("*.rpm") if p.is_file()}
    if not actual_packages or actual_packages != referenced_packages:
        raise RepositorySnapshotError("RPM package inventory does not exactly match primary metadata")
    return {
        "repository_format": "rpm",
        "repomd_signature_verified": True,
        "verified_repodata_files": verified_metadata,
        "verified_packages": len(referenced_packages),
        "provenance_chain": "gpgv-repomd->sha256-primary->sha256-rpm",
    }


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        values = {key.lower(): value for key, value in attrs}
        self._href = values.get("href")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def _resolve_python_href(page_rel: str, href: str) -> tuple[str, str | None]:
    parsed = urlparse(href)
    if parsed.scheme or parsed.netloc or parsed.params or parsed.query:
        raise RepositorySnapshotError("Python Simple index links must be relative offline references")
    if not parsed.path:
        raise RepositorySnapshotError("Python Simple index contains an empty link")
    base_parts = list(PurePosixPath(page_rel).parent.parts)
    for part in unquote(parsed.path).split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not base_parts:
                raise RepositorySnapshotError("Python Simple index link escapes repository root")
            base_parts.pop()
        else:
            if "\\" in part or "\x00" in part:
                raise RepositorySnapshotError("Python Simple index link contains an unsafe path")
            base_parts.append(part)
    rel = _safe_relpath("/".join(base_parts), purpose="Python Simple index link")
    return rel, parsed.fragment or None


def validate_python_repository(root: Path, artifact: dict[str, Any], *, metadata_limit: int) -> dict[str, Any]:
    root_index = root / "simple" / "index.html"
    root_raw = _read_limited(root_index, limit=metadata_limit, purpose="Python Simple root index")
    try:
        root_text = root_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositorySnapshotError("Python Simple root index is not UTF-8") from exc
    project_pages = sorted(
        p for p in (root / "simple").rglob("index.html")
        if p.is_file() and p != root_index
    )
    if not project_pages:
        raise RepositorySnapshotError("Python repository snapshot contains no project Simple index pages")
    root_parser = _AnchorParser()
    root_parser.feed(root_text)
    root_projects: set[str] = set()
    for href, anchor_text in root_parser.anchors:
        rel, fragment = _resolve_python_href("simple/index.html", href)
        if fragment is not None or not anchor_text:
            raise RepositorySnapshotError("Python Simple root index contains an invalid project link")
        page_rel = f"{rel.rstrip('/')}/index.html"
        root_projects.add(page_rel)
    actual_project_pages = {p.relative_to(root).as_posix() for p in project_pages}
    if not root_projects or root_projects != actual_project_pages:
        raise RepositorySnapshotError("Python Simple root index project inventory does not match project pages")
    referenced_files: set[str] = set()
    verified_links = 0
    for page in project_pages:
        raw = _read_limited(page, limit=metadata_limit, purpose="Python Simple project index")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositorySnapshotError("Python Simple project index is not UTF-8") from exc
        parser = _AnchorParser()
        parser.feed(text)
        if not parser.anchors:
            raise RepositorySnapshotError("Python Simple project index contains no distribution links")
        page_rel = page.relative_to(root).as_posix()
        for href, anchor_text in parser.anchors:
            rel, fragment = _resolve_python_href(page_rel, href)
            filename = PurePosixPath(rel).name
            if anchor_text != filename:
                raise RepositorySnapshotError("Python Simple anchor text must match the distribution filename")
            if not filename.endswith(_PY_DIST_SUFFIXES):
                raise RepositorySnapshotError("Python Simple index references an unsupported distribution file type")
            if fragment is None or not fragment.startswith("sha256=") or not _SHA256_RE.fullmatch(fragment[7:].lower()):
                raise RepositorySnapshotError("Python Simple distribution links must include a sha256 fragment")
            path = root / rel
            observed, _ = _sha256_path(path)
            if observed != fragment[7:].lower():
                raise RepositorySnapshotError(f"Python distribution SHA-256 mismatch: {rel}")
            referenced_files.add(rel)
            verified_links += 1
    actual_distributions = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.name.endswith(_PY_DIST_SUFFIXES)
    }
    if not actual_distributions or actual_distributions != referenced_files:
        raise RepositorySnapshotError("Python distribution inventory does not exactly match Simple index links")
    return {
        "repository_format": "python-simple",
        "simple_api": "PEP-503-compatible-bounded-offline",
        "verified_project_pages": len(project_pages),
        "verified_distribution_links": verified_links,
        "verified_distributions": len(referenced_files),
        "provenance_chain": "snapshot-sha256->simple-index-sha256-fragment->distribution",
    }


def validate_repository_tree(
    root: Path,
    artifact: dict[str, Any],
    *,
    verify_signature: Callable[[Path, Path], None],
    metadata_limit: int,
) -> dict[str, Any]:
    doc, entries = _load_snapshot_manifest(root, artifact)
    kind = str(artifact.get("kind") or "")
    if kind == "apt-repository":
        native = validate_apt_repository(root, artifact, verify_signature=verify_signature, metadata_limit=metadata_limit)
    elif kind == "rpm-repository":
        native = validate_rpm_repository(root, artifact, verify_signature=verify_signature, metadata_limit=metadata_limit)
    elif kind == "python-repository":
        native = validate_python_repository(root, artifact, metadata_limit=metadata_limit)
    else:
        raise RepositorySnapshotError("unsupported repository snapshot kind")
    return {
        "repository_id": doc["repository_id"],
        "repository_version": doc["version"],
        "snapshot_files": len(entries),
        "snapshot_manifest_sha256": hashlib.sha256((root / SNAPSHOT_MANIFEST).read_bytes()).hexdigest(),
        **native,
    }
