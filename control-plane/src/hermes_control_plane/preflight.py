from __future__ import annotations

from typing import Any

# Commands are fixed product code, not model-generated shell. They are intentionally
# read-only and are suitable for a constrained SSH/agent executor.
CHECKS: list[dict[str, Any]] = [
    {"id": "ssh-connectivity", "required": True, "command": "printf hermes-preflight-ok"},
    {"id": "authority", "required": True, "command": "id -u; if command -v sudo >/dev/null 2>&1; then sudo -n true >/dev/null 2>&1 && echo sudo-nopasswd || echo sudo-unavailable; else echo sudo-missing; fi"},
    {"id": "os", "required": True, "command": "cat /etc/os-release 2>/dev/null || true; uname -srm"},
    {"id": "cpu", "required": True, "command": "command -v lscpu >/dev/null 2>&1 && lscpu || getconf _NPROCESSORS_ONLN"},
    {"id": "memory", "required": True, "command": "cat /proc/meminfo"},
    {"id": "disks", "required": True, "command": "lsblk -J -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL"},
    {"id": "network", "required": True, "command": "ip -j address; ip -j route"},
    {"id": "dns", "required": True, "command": "cat /etc/resolv.conf; getent hosts localhost"},
    {"id": "time", "required": True, "command": "date -u +%s; command -v timedatectl >/dev/null 2>&1 && timedatectl show -p NTPSynchronized -p TimeUSec --value || true"},
    {"id": "kernel", "required": True, "command": "uname -r; cat /proc/modules 2>/dev/null || true"},
    {"id": "ports", "required": False, "command": "ss -H -lntu 2>/dev/null || true"},
    {"id": "runtime", "required": False, "command": "for x in containerd docker crio crictl; do command -v $x >/dev/null 2>&1 && echo $x=$(command -v $x); done"},
    {"id": "kubernetes", "required": False, "command": "for x in kubelet kubectl k3s rke2; do command -v $x >/dev/null 2>&1 && echo $x=$(command -v $x); done; systemctl is-active kubelet 2>/dev/null || true"},
    {"id": "filesystem", "required": True, "command": "df -PT -B1"},
    {"id": "hostname", "required": True, "command": "hostname; hostname -f 2>/dev/null || true"},
]


def spec() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transport": "ssh",
        "host_key_policy": "pinned-fingerprint-required",
        "command_policy": "fixed-read-only-checks",
        "checks": CHECKS,
    }
