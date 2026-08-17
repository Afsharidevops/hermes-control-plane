#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request


def get_json(base: str, path: str):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def methods(spec: dict) -> set[tuple[str, str]]:
    allowed = {"get", "post", "put", "patch", "delete", "head", "options"}
    return {(path, method) for path, item in spec.get("paths", {}).items() for method in item if method in allowed}


ap = argparse.ArgumentParser(description="Compare public Hermes product API surfaces between two deployment modes")
ap.add_argument("left", help="first Control Plane base URL")
ap.add_argument("right", help="second Control Plane base URL")
args = ap.parse_args()
left_health, right_health = get_json(args.left, "/health"), get_json(args.right, "/health")
left_spec, right_spec = get_json(args.left, "/openapi.json"), get_json(args.right, "/openapi.json")
if left_health.get("version") != right_health.get("version"):
    raise SystemExit(f"version mismatch: {left_health.get('version')} != {right_health.get('version')}")
lm, rm = methods(left_spec), methods(right_spec)
if lm != rm:
    missing_right = sorted(lm - rm)
    missing_left = sorted(rm - lm)
    raise SystemExit(f"API mismatch; missing on right={missing_right}, missing on left={missing_left}")
print(json.dumps({"status": "PASS", "version": left_health.get("version"), "operations": len(lm)}, sort_keys=True))
