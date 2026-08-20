from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections import Counter
from typing import Any


MAX_EVENTS = 200
MAX_LINE_BYTES = 256 * 1024
DEFAULT_TIMEOUT = int(os.getenv("HERMES_HUBBLE_COMMAND_TIMEOUT", "30"))


class HubbleError(RuntimeError):
    pass


def _workload(endpoint: Any) -> str | None:
    if not isinstance(endpoint, dict):
        return None
    workloads = endpoint.get("workloads") or []
    if isinstance(workloads, list) and workloads:
        first = workloads[0]
        if isinstance(first, dict):
            name = str(first.get("name") or "").strip()
            kind = str(first.get("kind") or "").strip()
            if name:
                return f"{kind}/{name}" if kind else name
    pod = str(endpoint.get("pod_name") or endpoint.get("podName") or "").strip()
    return pod or None


def _endpoint(endpoint: Any) -> dict[str, Any]:
    if not isinstance(endpoint, dict):
        return {"namespace": None, "workload": None}
    namespace = str(endpoint.get("namespace") or "").strip() or None
    return {"namespace": namespace, "workload": _workload(endpoint)}


def _destination_port(flow: dict[str, Any]) -> int | None:
    l4 = flow.get("l4") if isinstance(flow.get("l4"), dict) else {}
    for proto in ("TCP", "tcp", "UDP", "udp", "SCTP", "sctp"):
        entry = l4.get(proto)
        if isinstance(entry, dict):
            value = entry.get("destination_port", entry.get("destinationPort"))
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                return port
    return None


def _protocol(flow: dict[str, Any]) -> str | None:
    l7 = flow.get("l7") if isinstance(flow.get("l7"), dict) else {}
    if isinstance(l7.get("http"), dict):
        return "HTTP"
    if isinstance(l7.get("dns"), dict):
        return "DNS"
    l4 = flow.get("l4") if isinstance(flow.get("l4"), dict) else {}
    for proto in ("TCP", "tcp", "UDP", "udp", "SCTP", "sctp", "ICMPv4", "icmpv4", "ICMPv6", "icmpv6"):
        if proto in l4:
            return proto.upper()
    return None


def _http(flow: dict[str, Any]) -> dict[str, Any] | None:
    l7 = flow.get("l7") if isinstance(flow.get("l7"), dict) else {}
    http = l7.get("http")
    if not isinstance(http, dict):
        return None
    method = str(http.get("method") or "").upper().strip() or None
    code_raw = http.get("code")
    try:
        code = int(code_raw)
    except (TypeError, ValueError):
        code = None
    status_class = f"{code // 100}xx" if code is not None and 100 <= code <= 599 else None
    return {"method": method, "status_class": status_class}


def sanitize_response(payload: dict[str, Any]) -> dict[str, Any] | None:
    flow = payload.get("flow") if isinstance(payload.get("flow"), dict) else payload
    if not isinstance(flow, dict):
        return None
    item = {
        "time": flow.get("time"),
        "verdict": str(flow.get("verdict") or "UNKNOWN").upper(),
        "source": _endpoint(flow.get("source")),
        "destination": _endpoint(flow.get("destination")),
        "protocol": _protocol(flow),
        "destination_port": _destination_port(flow),
        "http": _http(flow),
        "drop_reason": str(flow.get("drop_reason_desc") or flow.get("dropReasonDesc") or "").strip() or None,
        "traffic_direction": str(flow.get("traffic_direction") or flow.get("trafficDirection") or "").strip() or None,
        "is_reply": bool(flow.get("is_reply", flow.get("isReply", False))),
    }
    # Stable fingerprint over the sanitized representation only. No raw L7 data is retained.
    item["fingerprint"] = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return item


def _namespace_allowed(event: dict[str, Any], scope: dict[str, Any]) -> bool:
    allow = {str(x).lower() for x in (scope.get("namespace_allowlist") or []) if str(x).strip()}
    deny = {str(x).lower() for x in (scope.get("namespace_denylist") or []) if str(x).strip()}
    namespaces = {
        str((event.get(side) or {}).get("namespace") or "").lower()
        for side in ("source", "destination")
        if str((event.get(side) or {}).get("namespace") or "").strip()
    }
    if namespaces & deny or "*" in deny:
        return False
    if not allow or "*" in allow:
        return True
    # Keep only flows whose namespaced endpoints are all inside the target allowlist.
    return bool(namespaces) and namespaces <= allow


def aggregate(events: list[dict[str, Any]], *, observed_at: int | None = None) -> dict[str, Any]:
    verdicts: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    status_classes: Counter[str] = Counter()
    namespace_pairs: Counter[str] = Counter()
    workload_pairs: Counter[str] = Counter()
    policy_drops: Counter[str] = Counter()

    for event in events:
        verdict = str(event.get("verdict") or "UNKNOWN")
        verdicts[verdict] += 1
        if event.get("protocol"):
            protocols[str(event["protocol"])] += 1
        if event.get("destination_port"):
            ports[str(event["destination_port"])] += 1
        http = event.get("http") if isinstance(event.get("http"), dict) else {}
        if http.get("method"):
            methods[str(http["method"])] += 1
        if http.get("status_class"):
            status_classes[str(http["status_class"])] += 1
        src = event.get("source") if isinstance(event.get("source"), dict) else {}
        dst = event.get("destination") if isinstance(event.get("destination"), dict) else {}
        src_ns, dst_ns = src.get("namespace"), dst.get("namespace")
        if src_ns or dst_ns:
            namespace_pairs[f"{src_ns or '_'}->{dst_ns or '_'}"] += 1
        src_work, dst_work = src.get("workload"), dst.get("workload")
        if src_work or dst_work:
            workload_pairs[f"{src_ns or '_'}/{src_work or '_'}->{dst_ns or '_'}/{dst_work or '_'}"] += 1
        if verdict == "DROPPED":
            policy_drops[str(event.get("drop_reason") or "DROPPED")] += 1

    return {
        "observed_at": int(observed_at or time.time()),
        "event_count": len(events),
        "verdict_counts": dict(sorted(verdicts.items())),
        "protocol_counts": dict(sorted(protocols.items())),
        "port_counts": dict(sorted(ports.items())),
        "http_method_counts": dict(sorted(methods.items())),
        "http_status_class_counts": dict(sorted(status_classes.items())),
        "namespace_pairs": [{"pair": k, "count": v} for k, v in namespace_pairs.most_common(100)],
        "workload_pairs": [{"pair": k, "count": v} for k, v in workload_pairs.most_common(100)],
        "policy_drop_counts": dict(sorted(policy_drops.items())),
    }


def collect(*, snapshot: dict[str, Any], env: dict[str, str], last: int = 50, since_seconds: int | None = None, timeout: int | None = None) -> dict[str, Any]:
    if not 1 <= int(last) <= MAX_EVENTS:
        raise HubbleError(f"last must be between 1 and {MAX_EVENTS}")
    if since_seconds is not None and not 1 <= int(since_seconds) <= 3600:
        raise HubbleError("since_seconds must be between 1 and 3600")

    args = ["hubble", "observe", "--port-forward", "--output", "jsonpb", "--last", str(int(last))]
    if since_seconds is not None:
        args.extend(["--since", f"{int(since_seconds)}s"])

    try:
        proc = subprocess.run(args, text=True, capture_output=True, env=env, timeout=timeout or DEFAULT_TIMEOUT, check=False)
    except FileNotFoundError as exc:
        raise HubbleError("hubble CLI is not installed in Kubernetes Broker") from exc
    except subprocess.TimeoutExpired as exc:
        raise HubbleError(f"hubble observe timed out after {timeout or DEFAULT_TIMEOUT}s") from exc

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "")[-4000:]
        raise HubbleError(f"hubble observe failed with exit {proc.returncode}: {detail}")

    scope = snapshot.get("scope") if isinstance(snapshot.get("scope"), dict) else {}
    events: list[dict[str, Any]] = []
    rejected_lines = 0
    for raw in (proc.stdout or "").splitlines():
        if not raw.strip():
            continue
        if len(raw.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            rejected_lines += 1
            continue
        try:
            payload = json.loads(raw)
        except ValueError:
            rejected_lines += 1
            continue
        event = sanitize_response(payload) if isinstance(payload, dict) else None
        if event is None or not _namespace_allowed(event, scope):
            continue
        events.append(event)
        if len(events) >= MAX_EVENTS:
            break

    observed_at = int(time.time())
    return {
        "provider": "cilium-hubble",
        "transport": "hubble-relay-via-port-forward",
        "observed_at": observed_at,
        "events": events,
        "summary": aggregate(events, observed_at=observed_at),
        "raw_flow_bodies_returned": False,
        "rejected_lines": rejected_lines,
    }
