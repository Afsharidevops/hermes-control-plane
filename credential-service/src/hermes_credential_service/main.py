from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from contextlib import asynccontextmanager, closing
from typing import Any

import httpx
import yaml
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Header, HTTPException

from . import store
from .models import CredentialCreate, CredentialRevoke, CredentialRotate, CredentialSyncRetry, CredentialTest, CredentialUpdate

VERSION = "0.5.11-dev.2"
EXTERNAL_BACKENDS = {
    "kubernetes-secret": "Kubernetes Secret reference",
    "external-secrets": "External Secrets operator reference",
    "vault": "Vault-compatible secret reference",
    "aws-secrets-manager": "AWS Secrets Manager reference",
    "azure-key-vault": "Azure Key Vault reference",
    "gcp-secret-manager": "Google Secret Manager reference",
}
FORBIDDEN_METADATA_KEYS = {
    "secret", "password", "passphrase", "token", "access_token", "refresh_token",
    "private_key", "privatekey", "kubeconfig", "credential", "credentials", "raw", "content", "value",
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.init_db()
    yield


app = FastAPI(
    title="Hermes Credential Service",
    version=VERSION,
    description="Isolated encrypted credential administration boundary for Hermes Control Plane.",
    lifespan=lifespan,
)


def _admin_token() -> str:
    return os.getenv("HERMES_CREDENTIAL_ADMIN_TOKEN", "")


def _sync_token() -> str:
    return os.getenv("HERMES_CREDENTIAL_SERVICE_TOKEN", "")


def _control_plane_url() -> str:
    return os.getenv("HERMES_CONTROL_PLANE_URL", "").rstrip("/")


def _require_admin(authorization: str | None) -> None:
    token = _admin_token()
    if not token:
        raise HTTPException(status_code=503, detail="HERMES_CREDENTIAL_ADMIN_TOKEN is not configured")
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid credential-service admin token")


def _fernet() -> Fernet:
    raw = os.getenv("HERMES_CREDENTIAL_MASTER_KEY", "").encode("ascii")
    if not raw:
        raise HTTPException(status_code=503, detail="HERMES_CREDENTIAL_MASTER_KEY is not configured")
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="credential master key must be urlsafe-base64") from exc
    if len(decoded) != 32:
        raise HTTPException(status_code=503, detail="credential master key must decode to exactly 32 bytes")
    try:
        return Fernet(raw)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="invalid credential master key") from exc


def _validate_metadata(metadata: dict[str, Any]) -> None:
    def walk(value: Any, path: str = "metadata") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower().replace("-", "_")
                if normalized in FORBIDDEN_METADATA_KEYS or normalized.endswith(("_secret", "_password", "_token", "_private_key")):
                    raise HTTPException(status_code=422, detail=f"raw secret material is forbidden in {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, f"{path}[{idx}]")
    walk(metadata)


def _fingerprint(secret: bytes) -> str:
    return "sha256:" + hashlib.sha256(secret).hexdigest()


def _redacted(row: Any) -> dict[str, Any]:
    item = dict(row)
    item.pop("ciphertext", None)
    metadata = json.loads(item.pop("metadata_json") or "{}")
    item["metadata"] = metadata
    item["material_state"] = "encrypted" if row["backend"] == "local-encrypted" else "external-reference"
    return item


def _sync_payload(row: Any) -> dict[str, Any]:
    metadata = json.loads(row["metadata_json"] or "{}")
    metadata.update(
        {
            "backend": row["backend"],
            "fingerprint": row["fingerprint"],
            "version": int(row["version"]),
            "key_version": row["key_version"],
            "external_ref": row["external_ref"],
            "last_test_status": row["last_test_status"],
            "last_test_at": row["last_test_at"],
        }
    )
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "provider": row["backend"],
        "status": "configured" if row["status"] == "ACTIVE" else ("revoked" if row["status"] == "REVOKED" else "disabled"),
        "metadata": {key: value for key, value in metadata.items() if value is not None},
    }


def _sync_to_control_plane(row: Any) -> None:
    base = _control_plane_url()
    token = _sync_token()
    if not base or not token:
        raise HTTPException(status_code=503, detail="credential metadata sync is not configured")
    try:
        response = httpx.post(
            f"{base}/v1/internal/credential-refs/sync",
            headers={"Authorization": f"Bearer {token}"},
            json=_sync_payload(row),
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="control-plane credential metadata sync failed") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"control-plane credential metadata sync rejected: {response.status_code}")


def _delete_from_control_plane(credential_id: str) -> None:
    base = _control_plane_url()
    token = _sync_token()
    if not base or not token:
        raise HTTPException(status_code=503, detail="credential metadata sync is not configured")
    try:
        response = httpx.delete(
            f"{base}/v1/internal/credential-refs/{credential_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="control-plane credential metadata delete failed") from exc
    if response.status_code >= 400:
        detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else None
        raise HTTPException(status_code=409 if response.status_code == 409 else 502, detail=detail or "control-plane rejected credential metadata delete")


def _validate_secret(kind: str, secret: bytes) -> tuple[str, dict[str, Any]]:
    if kind == "kubeconfig":
        try:
            parsed = yaml.safe_load(secret.decode("utf-8"))
        except Exception as exc:
            return "INVALID", {"reason": f"invalid kubeconfig YAML: {type(exc).__name__}"}
        if not isinstance(parsed, dict) or not all(isinstance(parsed.get(key), list) for key in ("clusters", "contexts", "users")):
            return "INVALID", {"reason": "kubeconfig must contain clusters, contexts, and users lists"}
        return "VALID", {"clusters": len(parsed["clusters"]), "contexts": len(parsed["contexts"]), "users": len(parsed["users"])}
    if kind == "ssh-key":
        loaders = (serialization.load_ssh_private_key, serialization.load_pem_private_key)
        for loader in loaders:
            try:
                loader(secret, password=None)
                return "VALID", {"format": "private-key"}
            except (ValueError, TypeError, UnsupportedAlgorithm):
                continue
        return "INVALID", {"reason": "unsupported, invalid, or passphrase-protected private key"}
    if not secret:
        return "INVALID", {"reason": "empty credential material"}
    return "VALID", {"format": "opaque"}


@app.get("/health")
def health() -> dict[str, Any]:
    master_configured = bool(os.getenv("HERMES_CREDENTIAL_MASTER_KEY"))
    return {"status": "ok" if master_configured else "degraded", "version": VERSION, "master_key_configured": master_configured}


@app.get("/v1/backends")
def list_backends(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    rows = [{"id": "local-encrypted", "mode": "encrypted-local", "secret_material_accepted": True, "ready": bool(os.getenv("HERMES_CREDENTIAL_MASTER_KEY"))}]
    rows.extend({"id": key, "mode": "external-reference", "secret_material_accepted": False, "ready": True, "description": value} for key, value in EXTERNAL_BACKENDS.items())
    return rows


@app.get("/v1/credentials")
def list_credentials(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_admin(authorization)
    with closing(store.connect()) as conn:
        rows = conn.execute("SELECT * FROM credentials ORDER BY name").fetchall()
    return [_redacted(row) for row in rows]


@app.get("/v1/credentials/{credential_id}")
def get_credential(credential_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="credential not found")
    return _redacted(row)


@app.post("/v1/credentials", status_code=201)
def create_credential(payload: CredentialCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _validate_metadata(payload.metadata)
    now = int(time.time())
    credential_id = f"cred_{uuid.uuid4().hex[:16]}"
    ciphertext: bytes | None = None
    fingerprint: str | None = None
    if payload.backend == "local-encrypted":
        secret = payload.secret_material.get_secret_value().encode("utf-8")  # type: ignore[union-attr]
        ciphertext = _fernet().encrypt(secret)
        fingerprint = _fingerprint(secret)
    else:
        fingerprint = "ref:" + hashlib.sha256(payload.external_ref.encode("utf-8")).hexdigest()  # type: ignore[union-attr]
    key_version = os.getenv("HERMES_CREDENTIAL_MASTER_KEY_VERSION", "v1") if payload.backend == "local-encrypted" else None
    with closing(store.connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO credentials (id,name,kind,backend,external_ref,ciphertext,fingerprint,metadata_json,status,version,key_version,sync_status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (credential_id, payload.name, payload.kind, payload.backend, payload.external_ref, ciphertext, fingerprint, json.dumps(payload.metadata, sort_keys=True), "ACTIVE", 1, key_version, "PENDING", now, now),
            )
            row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
            _sync_to_control_plane(row)
            conn.execute("UPDATE credentials SET sync_status='SYNCED' WHERE id=?", (credential_id,))
            store.audit(conn, "credential.created", "credential-admin", credential_id, json.dumps({"kind": payload.kind, "backend": payload.backend}))
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="credential name already exists") from exc
            raise
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _redacted(row)


@app.patch("/v1/credentials/{credential_id}")
def update_credential(credential_id: str, payload: CredentialUpdate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        if row["status"] == "REVOKED":
            raise HTTPException(status_code=409, detail="credential is revoked")
        name = payload.name if payload.name is not None else row["name"]
        metadata = payload.metadata if payload.metadata is not None else json.loads(row["metadata_json"] or "{}")
        _validate_metadata(metadata)
        try:
            conn.execute(
                "UPDATE credentials SET name=?,metadata_json=?,sync_status='PENDING',updated_at=? WHERE id=?",
                (name, json.dumps(metadata, sort_keys=True), now, credential_id),
            )
            updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
            _sync_to_control_plane(updated)
            conn.execute("UPDATE credentials SET sync_status='SYNCED' WHERE id=?", (credential_id,))
            fields = []
            if payload.name is not None:
                fields.append("name")
            if payload.metadata is not None:
                fields.append("metadata")
            store.audit(conn, "credential.updated", payload.actor, credential_id, json.dumps({"fields": fields}, sort_keys=True))
            conn.commit()
        except Exception as exc:
            if "UNIQUE constraint failed: credentials.name" in str(exc):
                raise HTTPException(status_code=409, detail="credential name already exists") from exc
            raise
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _redacted(updated)


@app.post("/v1/credentials/{credential_id}/rotate")
def rotate_credential(credential_id: str, payload: CredentialRotate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        metadata = json.loads(row["metadata_json"] or "{}") if payload.metadata is None else payload.metadata
        _validate_metadata(metadata)
        if row["backend"] == "local-encrypted":
            if payload.external_ref is not None or payload.secret_material is None:
                raise HTTPException(status_code=422, detail="local-encrypted rotation requires replacement secret_material only")
            secret = payload.secret_material.get_secret_value().encode("utf-8")
            ciphertext = _fernet().encrypt(secret)
            fingerprint = _fingerprint(secret)
            external_ref = None
            key_version = os.getenv("HERMES_CREDENTIAL_MASTER_KEY_VERSION", "v1")
        else:
            if payload.secret_material is not None:
                raise HTTPException(status_code=422, detail="external reference backend must not receive secret_material")
            external_ref = payload.external_ref or row["external_ref"]
            if not external_ref:
                raise HTTPException(status_code=422, detail="external reference rotation requires external_ref")
            ciphertext = None
            fingerprint = "ref:" + hashlib.sha256(external_ref.encode("utf-8")).hexdigest()
            key_version = None
        conn.execute(
            "UPDATE credentials SET external_ref=?,ciphertext=?,fingerprint=?,metadata_json=?,version=version+1,key_version=?,sync_status='PENDING',updated_at=? WHERE id=?",
            (external_ref, ciphertext, fingerprint, json.dumps(metadata, sort_keys=True), key_version, now, credential_id),
        )
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        _sync_to_control_plane(updated)
        conn.execute("UPDATE credentials SET sync_status='SYNCED' WHERE id=?", (credential_id,))
        store.audit(conn, "credential.rotated", "credential-admin", credential_id, json.dumps({"version": int(updated["version"]), "backend": updated["backend"]}))
        conn.commit()
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _redacted(updated)


@app.post("/v1/credentials/{credential_id}/test")
def test_credential(credential_id: str, payload: CredentialTest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        if row["status"] == "REVOKED":
            raise HTTPException(status_code=409, detail="credential is revoked")
        if row["backend"] == "local-encrypted":
            try:
                plaintext = _fernet().decrypt(row["ciphertext"])
            except InvalidToken as exc:
                status, detail = "INVALID", {"reason": "credential ciphertext cannot be decrypted with configured master key"}
            else:
                status, detail = _validate_secret(row["kind"], plaintext)
        else:
            status, detail = "REFERENCE_CONFIGURED", {"backend": row["backend"], "external_ref": row["external_ref"]}
        conn.execute("UPDATE credentials SET last_test_at=?,last_test_status=?,sync_status='PENDING',updated_at=? WHERE id=?", (now, status, now, credential_id))
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        _sync_to_control_plane(updated)
        conn.execute("UPDATE credentials SET sync_status='SYNCED' WHERE id=?", (credential_id,))
        store.audit(conn, "credential.tested", payload.actor, credential_id, json.dumps({"status": status, "detail": detail}, sort_keys=True))
        conn.commit()
    return {"id": credential_id, "status": status, "detail": detail, "tested_at": now}


@app.post("/v1/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: str, payload: CredentialRevoke, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    now = int(time.time())
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        if row["status"] == "REVOKED":
            return _redacted(row)
        conn.execute("UPDATE credentials SET status='REVOKED',sync_status='PENDING',updated_at=? WHERE id=?", (now, credential_id))
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        _sync_to_control_plane(updated)
        # Erase locally stored secret material only after the metadata revoke is accepted.
        conn.execute("UPDATE credentials SET ciphertext=NULL,sync_status='SYNCED' WHERE id=?", (credential_id,))
        store.audit(conn, "credential.revoked", payload.actor, credential_id, json.dumps({"reason": payload.reason, "backend": row["backend"], "version": int(row["version"])}, sort_keys=True))
        conn.commit()
        updated = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _redacted(updated)


@app.post("/v1/credentials/{credential_id}/sync")
def retry_sync(credential_id: str, payload: CredentialSyncRetry, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        _sync_to_control_plane(row)
        conn.execute("UPDATE credentials SET sync_status='SYNCED',updated_at=? WHERE id=?", (int(time.time()), credential_id))
        store.audit(conn, "credential.synced", payload.actor, credential_id)
        conn.commit()
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _redacted(row)


@app.delete("/v1/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: str, authorization: str | None = Header(default=None)) -> None:
    _require_admin(authorization)
    with closing(store.connect()) as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="credential not found")
        _delete_from_control_plane(credential_id)
        store.audit(conn, "credential.deleted", "credential-admin", credential_id, json.dumps({"kind": row["kind"], "backend": row["backend"]}))
        conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        conn.commit()


@app.get("/v1/audit")
def list_audit(authorization: str | None = Header(default=None), limit: int = 200) -> list[dict[str, Any]]:
    _require_admin(authorization)
    limit = max(1, min(limit, 1000))
    with closing(store.connect()) as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(row), "payload": json.loads(row["payload_json"] or "{}"), "payload_json": None} for row in rows]
