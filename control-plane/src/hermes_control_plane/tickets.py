from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

from .canonical import canonical_json


def execution_key() -> str:
    return os.getenv("HERMES_EXECUTION_HMAC_KEY", "")


def issue_ticket(changeset_id: str, plan_hash: str, plan: dict[str, Any], ttl_seconds: int = 120) -> tuple[dict[str, Any], str]:
    key = execution_key()
    if not key:
        raise RuntimeError("HERMES_EXECUTION_HMAC_KEY is not configured")
    now = int(time.time())
    ticket = {
        "changeset_id": changeset_id,
        "plan_hash": plan_hash,
        "plan": plan,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
    }
    signature = hmac.new(key.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    return ticket, signature
