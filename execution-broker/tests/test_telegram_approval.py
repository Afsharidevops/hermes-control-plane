from __future__ import annotations

import time

import pytest

from broker.approver import ApprovalRequestStore, ApproverError


def payload(capability: str = "cap_" + "a" * 64) -> dict:
    return {
        "capability": capability,
        "target": "docker",
        "feature": "docker",
        "digest": "b" * 64,
        "request": {"action": "restart", "container": "demo"},
        "summary": "Restart demo container",
        "user_id": "123456",
        "session": "telegram:session-1",
        "generation": "7",
    }


def test_delivered_telegram_approval_resolves_only_once(tmp_path):
    store = ApprovalRequestStore(tmp_path / "approvals.sqlite3")
    request = payload()
    token = store.create(request, ttl_seconds=60)
    store.mark_delivered(request["capability"])
    resolved = store.resolve(token, "approved", request["user_id"])
    assert resolved["decision"] == "approved"
    assert resolved["digest"] == request["digest"]
    with pytest.raises(ApproverError, match="already resolved"):
        store.resolve(token, "approved", request["user_id"])


def test_telegram_approval_expires_fail_closed(tmp_path):
    store = ApprovalRequestStore(tmp_path / "approvals.sqlite3")
    request = payload("cap_" + "c" * 64)
    token = store.create(request, ttl_seconds=0)
    store.mark_delivered(request["capability"])
    time.sleep(0.01)
    with pytest.raises(ApproverError, match="expired"):
        store.resolve(token, "approved", request["user_id"])
