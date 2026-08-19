from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

from .canonical import canonical_json


def execution_key() -> str:
    return os.getenv("HERMES_EXECUTION_HMAC_KEY", "")


def issue_ticket(
    changeset_id: str,
    plan_hash: str,
    plan: dict[str, Any],
    ttl_seconds: int = 120,
    preconditions: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    key = execution_key()
    if not key:
        raise RuntimeError("HERMES_EXECUTION_HMAC_KEY is not configured")
    now = int(time.time())
    ticket = {
        "changeset_id": changeset_id,
        "plan_hash": plan_hash,
        "plan": plan,
        "preconditions": preconditions or {},
        "issued_at": now,
        "expires_at": now + ttl_seconds,
    }
    signature = hmac.new(key.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature


def verify_ticket(
    ticket: dict[str, Any],
    signature: str,
    *,
    now: int | None = None,
    require_fresh: bool = True,
) -> None:
    key = execution_key()
    if not key:
        raise RuntimeError("HERMES_EXECUTION_HMAC_KEY is not configured")
    expected = hmac.new(key.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid execution ticket signature")
    observed = int(time.time()) if now is None else int(now)
    if require_fresh and int(ticket.get("expires_at") or 0) < observed:
        raise ValueError("execution ticket expired")
    if int(ticket.get("issued_at") or 0) > observed + 30:
        raise ValueError("execution ticket issued_at is in the future")
