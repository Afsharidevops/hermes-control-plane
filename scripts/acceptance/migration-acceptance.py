#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request


def get_json(base: str, path: str):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


ap = argparse.ArgumentParser(description="Verify Docker -> Kubernetes Control Plane state migration")
ap.add_argument("docker_url")
ap.add_argument("kubernetes_url")
args = ap.parse_args()
source = get_json(args.docker_url, "/v1/system")
dest = get_json(args.kubernetes_url, "/v1/system")
if source.get("version") != dest.get("version"):
    raise SystemExit(f"version mismatch: {source.get('version')} != {dest.get('version')}")
if source.get("policy_generation") != dest.get("policy_generation"):
    raise SystemExit(f"policy generation mismatch: {source.get('policy_generation')} != {dest.get('policy_generation')}")
if source.get("counts") != dest.get("counts"):
    raise SystemExit(f"registry count mismatch: {source.get('counts')} != {dest.get('counts')}")
print(json.dumps({"status": "PASS", "version": source.get("version"), "policy_generation": source.get("policy_generation"), "counts": source.get("counts")}, sort_keys=True))
