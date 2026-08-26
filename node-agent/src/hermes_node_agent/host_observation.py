from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

COLLECTOR_KIND = "host-network-local-v1"
CONTRACT_VERSION = "host-network-local-v1"
MAX_INTERFACES = 64
MAX_BONDS = 32
MAX_VLANS = 128
_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,30}$")
_BOND_MODE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def _sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_text(path: Path, *, maximum: int = 128) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("host network value is empty or exceeds the fixed bound")
    return value


def _safe_interface_names(sys_net_root: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        if not sys_net_root.is_dir():
            return [], "host sysfs network root is unavailable"
        entries = sorted(sys_net_root.iterdir(), key=lambda item: item.name)
    except OSError:
        return [], "host sysfs network root is unreadable"

    interfaces: list[dict[str, Any]] = []
    try:
        for entry in entries:
            if entry.name == "lo" or not _INTERFACE_NAME_RE.fullmatch(entry.name):
                continue
            if len(interfaces) >= MAX_INTERFACES:
                return [], "host interface inventory exceeds the fixed bound"
            if not entry.is_dir():
                continue
            state = _read_text(entry / "operstate").lower()
            mtu_raw = _read_text(entry / "mtu")
            if state not in {"up", "down", "unknown", "dormant", "lowerlayerdown", "notpresent", "testing"}:
                raise ValueError("host interface state is invalid")
            if not mtu_raw.isdigit() or not 576 <= int(mtu_raw) <= 9216:
                raise ValueError("host interface MTU is invalid")
            interfaces.append({"name": entry.name, "state": state, "mtu": int(mtu_raw)})
    except (OSError, ValueError):
        return [], "host interface inventory contains unreadable or invalid values"
    return interfaces, None


def _bond_count(sys_net_root: Path) -> tuple[int, str | None]:
    try:
        bonds = [entry for entry in sorted(sys_net_root.iterdir(), key=lambda item: item.name) if entry.name.startswith("bond") and entry.is_dir()]
    except OSError:
        return 0, "host bond inventory is unreadable"
    if len(bonds) > MAX_BONDS:
        return 0, "host bond inventory exceeds the fixed bound"
    try:
        for entry in bonds:
            if not _INTERFACE_NAME_RE.fullmatch(entry.name):
                return 0, "host bond inventory contains an invalid interface name"
            mode_path = entry / "bonding" / "mode"
            if mode_path.exists():
                mode = _read_text(mode_path).split(None, 1)[0]
                if not _BOND_MODE_RE.fullmatch(mode):
                    return 0, "host bond inventory contains an invalid mode"
    except (OSError, ValueError):
        return 0, "host bond inventory contains unreadable or invalid values"
    return len(bonds), None


def _vlan_count(vlan_config_path: Path) -> tuple[int, str | None]:
    try:
        if not vlan_config_path.is_file():
            return 0, "host procfs VLAN configuration is unavailable"
        lines = vlan_config_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0, "host procfs VLAN configuration is unreadable"

    count = 0
    try:
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 3 or parts[2] != "|":
                continue
            if not parts[0].isdigit() or not 1 <= int(parts[0]) <= 4094 or not _INTERFACE_NAME_RE.fullmatch(parts[1]):
                return 0, "host procfs VLAN configuration contains invalid values"
            count += 1
            if count > MAX_VLANS:
                return 0, "host VLAN inventory exceeds the fixed bound"
    except ValueError:
        return 0, "host procfs VLAN configuration contains invalid values"
    return count, None


def collect_host_network(
    *,
    collector_identity: str,
    sys_net_root: Path = Path("/host-sys/class/net"),
    vlan_config_path: Path = Path("/host-proc/net/vlan/config"),
    observed_at: int | None = None,
) -> dict[str, Any]:
    """Collect a fixed, redacted host network inventory from mounted host roots only."""
    now = int(time.time()) if observed_at is None else observed_at
    interfaces, interface_error = _safe_interface_names(sys_net_root)
    bond_count, bond_error = _bond_count(sys_net_root) if interface_error is None else (0, interface_error)
    vlan_count, vlan_error = _vlan_count(vlan_config_path) if interface_error is None and bond_error is None else (0, interface_error or bond_error)
    errors = [message for message in (interface_error, bond_error, vlan_error) if message]

    if errors:
        status = "SKIP" if any("unavailable" in message or "unreadable" in message for message in errors) else "FAIL"
        facts: dict[str, Any] = {"interfaces": [], "bond_count": 0, "vlan_count": 0}
        summary = "Host network roots are not available for safe observation." if status == "SKIP" else "Host network observation rejected invalid host-root data."
        host_roots_visible = False if status == "SKIP" else True
    elif not interfaces:
        status = "SKIP"
        facts = {"interfaces": [], "bond_count": bond_count, "vlan_count": vlan_count}
        summary = "Host network roots are visible but contain no eligible non-loopback interfaces."
        host_roots_visible = True
    else:
        status = "PASS"
        facts = {"interfaces": interfaces, "bond_count": bond_count, "vlan_count": vlan_count}
        summary = "Read-only host network inventory collected from explicitly mounted host roots."
        host_roots_visible = True

    result = {
        "contract_version": CONTRACT_VERSION,
        "collector_kind": COLLECTOR_KIND,
        "collector_identity": collector_identity,
        "status": status,
        "summary": summary,
        "observed_at": now,
        "host_roots_visible": host_roots_visible,
        "facts": facts,
        "mutation_commands_executed": False,
        "credential_material_returned": False,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }
    result["observation_hash"] = _sha256(result)
    return result
