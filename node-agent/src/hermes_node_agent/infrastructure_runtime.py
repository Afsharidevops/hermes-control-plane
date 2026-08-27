from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from fastapi import HTTPException

from . import proxmox_runtime

TOKEN = os.getenv("HERMES_PROVIDER_WORKER_TOKEN", "")
EXECUTION_KEY = os.getenv("HERMES_EXECUTION_HMAC_KEY", "")
EXECUTION_ENABLED = os.getenv("HERMES_INFRASTRUCTURE_EXECUTION_ENABLED", "false").lower() == "true"
ALLOW_HTTP = os.getenv("HERMES_INFRASTRUCTURE_ALLOW_HTTP", "false").lower() == "true"
CREDENTIAL_ROOT = Path(os.getenv("HERMES_INFRASTRUCTURE_CREDENTIAL_ROOT", "/credentials/infrastructure"))
ARTIFACT_MIRROR_ROOT = Path(os.getenv("HERMES_ARTIFACT_MIRROR_ROOT", "/data/artifact-mirror"))
REQUEST_TIMEOUT = float(os.getenv("HERMES_INFRASTRUCTURE_REQUEST_TIMEOUT_SECONDS", "20"))
VERIFY_ATTEMPTS = int(os.getenv("HERMES_INFRASTRUCTURE_VERIFY_ATTEMPTS", "5"))
VERIFY_DELAY_SECONDS = float(os.getenv("HERMES_INFRASTRUCTURE_VERIFY_DELAY_SECONDS", "1"))
FIRMWARE_VERIFY_ATTEMPTS = int(os.getenv("HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_ATTEMPTS", "60"))
FIRMWARE_VERIFY_DELAY_SECONDS = float(os.getenv("HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_DELAY_SECONDS", "5"))
PLATFORM_VERIFY_ATTEMPTS = int(os.getenv("HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_ATTEMPTS", "90"))
PLATFORM_VERIFY_DELAY_SECONDS = float(os.getenv("HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_DELAY_SECONDS", "5"))
IPMI_TIMEOUT_SECONDS = float(os.getenv("HERMES_INFRASTRUCTURE_IPMI_TIMEOUT_SECONDS", "20"))

_USED_TICKETS: set[str] = set()
_USED_LOCK = threading.Lock()
CRED_RE = re.compile(r"^cred_[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
SAFE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUNTIME_PROVIDER_OPERATIONS = {
    "redfish": {"inventory.refresh", "power.set", "boot.set", "boot-order.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "virtual-media.insert", "virtual-media.eject", "bios.apply", "firmware.apply", "storage.volume.apply", "storage.volume.delete"},
    "ipmi": {"power.set", "boot.set"},
    "pxe": {"os.provision", "os.reimage"},
    "host-network": {"interface.configure", "interface.bond", "vlan.configure", "mtu.configure", "address.configure", "network.discover"},
    "network-switch": {"vlan.ensure", "port.configure", "lldp.observe"},
    "proxmox": proxmox_runtime.OPERATIONS,
}
POWER_RESET_TYPES = {
    "on": "On",
    "force-off": "ForceOff",
    "graceful-shutdown": "GracefulShutdown",
    "restart": "ForceRestart",
    "graceful-restart": "GracefulRestart",
    "power-cycle": "PowerCycle",
}
BOOT_TARGETS = {
    "pxe": "Pxe",
    "disk": "Hdd",
    "cd": "Cd",
    "none": "None",
}
BOOT_ENABLED = {
    "once": "Once",
    "continuous": "Continuous",
    "disabled": "Disabled",
}
BOOT_MODES = {"uefi": "UEFI", "legacy": "Legacy"}
BOOT_ORDER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
PLATFORM_FEATURES = {"sriov", "iommu"}
PLATFORM_ACTIVATIONS = {"immediate", "reboot"}
PLATFORM_RESET_TYPES = {"GracefulRestart", "ForceRestart"}
BIOS_ATTRIBUTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
FIRMWARE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
STORAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,79}$")
RAID_TYPES = {"RAID0", "RAID1", "RAID5", "RAID6", "RAID10", "RAID50", "RAID60"}
IPMI_POWER_STATES = {"on", "force-off", "graceful-shutdown"}
IPMI_POWER_COMMANDS = {
    "on": "on",
    "force-off": "off",
    "graceful-shutdown": "soft",
}
IPMI_BOOT_DEVICES = {"pxe": "pxe", "disk": "disk", "cd": "cdrom"}
IPMI_BOOT_ENABLED = {"once", "continuous"}
PXE_BOOT_METHODS = {"pxe", "ipxe"}
PXE_STATES = {"idle", "requested", "booting", "installer-started", "installing", "complete", "failed"}
PXE_PROGRESS_STATES = ("requested", "booting", "installer-started", "installing", "complete")
PXE_PROGRESS_RANK = {state: index for index, state in enumerate(PXE_PROGRESS_STATES)}
PXE_ARTIFACT_ROLES = {"kernel", "initrd", "rootfs", "installer", "unattended"}
PXE_REQUIRED_ARTIFACT_ROLES = {"kernel", "initrd", "unattended"}
PXE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$")
PXE_ARTIFACT_ID_RE = re.compile(r"^art_[A-Za-z0-9]{8,64}$")
PXE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PXE_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
PXE_NIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
PXE_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,159}$")
PXE_PROFILE_OS = {"ubuntu", "debian", "rhel", "rocky", "alma", "sles"}
SWITCH_RESTCONF_PROFILE = "openconfig-restconf-v1"
SWITCH_RESTCONF_API_VERSION = "openconfig-restconf-1.0"
SWITCH_RESTCONF_IMPLEMENTATION_VERSION = "openconfig-restconf-v1"
SWITCH_PORT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")
SWITCH_VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def require_token(authorization: str | None) -> None:
    if not TOKEN:
        raise HTTPException(503, "provider worker token not configured")
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "invalid provider worker token")


def _typed_plan(changeset_plan: dict[str, Any]) -> dict[str, Any]:
    params = changeset_plan.get("parameters") or {}
    typed = params.get("typed_plan")
    if not isinstance(typed, dict):
        raise HTTPException(422, "ChangeSet does not contain a typed infrastructure plan")
    embedded = str(typed.get("plan_hash") or "")
    unsigned = dict(typed)
    unsigned.pop("plan_hash", None)
    if not embedded or sha256_hex(unsigned) != embedded:
        raise HTTPException(409, "typed infrastructure plan hash mismatch")
    return typed


def _provider_target(typed: dict[str, Any]) -> dict[str, Any]:
    provider = typed.get("provider") or {}
    provider_id = str(provider.get("id") or "")
    provider_kind = str(provider.get("kind") or "")
    for target in typed.get("targets") or []:
        if str(target.get("id") or "") == provider_id and str(target.get("kind") or "") == provider_kind:
            if str(target.get("snapshot_hash") or "") != str(provider.get("snapshot_hash") or ""):
                raise HTTPException(409, "infrastructure provider snapshot hash binding mismatch")
            if str(target.get("credential_ref") or "") != str(provider.get("credential_ref") or ""):
                raise HTTPException(409, "infrastructure provider credential reference binding mismatch")
            return target
    raise HTTPException(422, "typed infrastructure plan has no exact provider snapshot")


def _operation(typed: dict[str, Any]) -> tuple[str, str]:
    provider = typed.get("provider") or {}
    kind = str(provider.get("kind") or "")
    operation = str(typed.get("operation") or "")
    if operation not in RUNTIME_PROVIDER_OPERATIONS.get(kind, set()):
        raise HTTPException(422, f"operation {operation!r} is not supported by trusted {kind or 'infrastructure'} runtime")
    return kind, operation


def _validate_desired_state(kind: str, operation: str, desired: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(desired, dict):
        raise HTTPException(422, "infrastructure desired_state must be an object")
    if kind == "ipmi":
        if operation == "power.set":
            if set(desired) != {"state"}:
                raise HTTPException(422, "IPMI power.set requires only desired_state.state")
            state = str(desired.get("state") or "").lower()
            if state not in IPMI_POWER_STATES:
                raise HTTPException(422, "unsupported IPMI power state")
            return {"state": state}
        if operation == "boot.set":
            allowed = {"target", "enabled", "mode"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported IPMI boot desired_state field(s): " + ", ".join(unknown))
            target = str(desired.get("target") or "").lower()
            enabled = str(desired.get("enabled") or "once").lower()
            mode = str(desired.get("mode") or "").lower()
            if target not in IPMI_BOOT_DEVICES:
                raise HTTPException(422, "unsupported IPMI boot target")
            if enabled not in IPMI_BOOT_ENABLED:
                raise HTTPException(422, "unsupported IPMI boot enable mode")
            if mode and mode not in BOOT_MODES:
                raise HTTPException(422, "unsupported IPMI boot mode")
            result = {"target": target, "enabled": enabled}
            if mode:
                result["mode"] = mode
            return result
        raise HTTPException(422, "unsupported IPMI runtime operation")
    if kind == "pxe":
        allowed = {
            "boot_method", "artifacts", "unattended_profile_ref", "callback_ref", "callback_token_sha256",
            "completion_timeout_seconds", "host_ready_timeout_seconds", "boot_mode", "confirm_server",
        }
        unknown = sorted(set(desired) - allowed)
        if unknown:
            raise HTTPException(422, "unsupported PXE desired_state field(s): " + ", ".join(unknown))
        boot_method = str(desired.get("boot_method") or "").lower()
        if boot_method not in PXE_BOOT_METHODS:
            raise HTTPException(422, "PXE boot_method must be pxe or ipxe")
        boot_mode = str(desired.get("boot_mode") or "uefi").lower()
        if boot_mode not in BOOT_MODES:
            raise HTTPException(422, "PXE boot_mode must be uefi or legacy")
        artifacts = desired.get("artifacts")
        if not isinstance(artifacts, dict):
            raise HTTPException(422, "PXE desired_state.artifacts must be an object")
        unknown_roles = sorted(set(artifacts) - PXE_ARTIFACT_ROLES)
        missing_roles = sorted(PXE_REQUIRED_ARTIFACT_ROLES - set(artifacts))
        if unknown_roles:
            raise HTTPException(422, "unsupported PXE artifact role(s): " + ", ".join(unknown_roles))
        if missing_roles:
            raise HTTPException(422, "PXE artifacts require: " + ", ".join(missing_roles))
        if len(set(str(value) for value in artifacts.values())) != len(artifacts):
            raise HTTPException(422, "PXE artifact IDs must be unique across roles")
        normalized_artifacts: dict[str, str] = {}
        for role, artifact_id in artifacts.items():
            value = str(artifact_id or "")
            if not PXE_ARTIFACT_ID_RE.fullmatch(value):
                raise HTTPException(422, "PXE artifacts must reference exact artifact mirror IDs")
            normalized_artifacts[str(role)] = value
        unattended_ref = str(desired.get("unattended_profile_ref") or "")
        callback_ref = str(desired.get("callback_ref") or "")
        if not PXE_REF_RE.fullmatch(unattended_ref):
            raise HTTPException(422, "PXE unattended_profile_ref is invalid")
        if not PXE_REF_RE.fullmatch(callback_ref):
            raise HTTPException(422, "PXE callback_ref is invalid")
        callback_hash = str(desired.get("callback_token_sha256") or "")
        if not PXE_SHA256_RE.fullmatch(callback_hash):
            raise HTTPException(422, "PXE callback_token_sha256 must be an exact lowercase SHA-256 digest")
        completion = desired.get("completion_timeout_seconds", 3600)
        host_ready = desired.get("host_ready_timeout_seconds", 300)
        if not isinstance(completion, int) or isinstance(completion, bool) or not 60 <= completion <= 7200:
            raise HTTPException(422, "PXE completion_timeout_seconds must be between 60 and 7200")
        if not isinstance(host_ready, int) or isinstance(host_ready, bool) or not 10 <= host_ready <= 900:
            raise HTTPException(422, "PXE host_ready_timeout_seconds must be between 10 and 900")
        confirm = str(desired.get("confirm_server") or "")
        if operation == "os.reimage" and not confirm:
            raise HTTPException(422, "PXE os.reimage requires confirm_server")
        if operation == "os.provision" and confirm:
            raise HTTPException(422, "PXE os.provision does not accept confirm_server")
        result = {
            "boot_method": boot_method, "boot_mode": boot_mode, "artifacts": dict(sorted(normalized_artifacts.items())),
            "unattended_profile_ref": unattended_ref, "callback_ref": callback_ref, "callback_token_sha256": callback_hash,
            "completion_timeout_seconds": completion, "host_ready_timeout_seconds": host_ready,
        }
        if confirm:
            result["confirm_server"] = confirm
        return result
    if kind == "host-network":
        NETWORK_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
        NETWORK_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
        NETWORK_VLAN_RE = re.compile(r"^[1-9][0-9]{0,3}$|^[1-5][0-9]{4}$|^6[0-4][0-9]{3}$|^65[0-4][0-9][0-9]$|^655[0-2][0-9]$|^6553[0-5]$")
        NETWORK_MTU_RE = re.compile(r"^(?:[6-9][0-9]{2,3}|1[0-8][0-9]{2}|19[0-9]{2}|20[0-9]{2}|21[0-9]{2}|22[0-9]{2}|9[0-9]{3}|[1-8][0-9]{4})$")
        if operation == "network.discover":
            if desired:
                raise HTTPException(422, "host-network network.discover does not accept desired_state fields")
            return {}
        if operation == "interface.configure":
            allowed = {"interface", "mac", "state", "mtu"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported host-network interface.configure field(s): " + ", ".join(unknown))
            interface = str(desired.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise HTTPException(422, "host-network interface name is invalid")
            result_h: dict[str, Any] = {"interface": interface}
            if "mac" in desired:
                mac = str(desired["mac"] or "").lower()
                if not NETWORK_MAC_RE.fullmatch(mac):
                    raise HTTPException(422, "host-network MAC address is invalid")
                result_h["mac"] = mac
            if "state" in desired:
                state = str(desired["state"] or "").lower()
                if state not in {"up", "down"}:
                    raise HTTPException(422, "host-network interface state must be up or down")
                result_h["state"] = state
            if "mtu" in desired:
                mtu = str(desired["mtu"] or "")
                if not NETWORK_MTU_RE.fullmatch(mtu):
                    raise HTTPException(422, "host-network MTU is invalid")
                result_h["mtu"] = int(mtu)
            return result_h
        if operation == "interface.bond":
            allowed = {"bond_interface", "mode", "slaves", "miimon", "lacp_rate"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported host-network interface.bond field(s): " + ", ".join(unknown))
            bond = str(desired.get("bond_interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(bond) or not bond.startswith("bond"):
                raise HTTPException(422, "host-network bond interface name must start with 'bond'")
            mode = str(desired.get("mode") or "802.3ad").lower()
            if mode not in {"802.3ad", "active-backup", "balance-tlb", "balance-alb", "balance-rr", "balance-xor", "broadcast"}:
                raise HTTPException(422, "host-network bond mode must be a supported bonding mode")
            slaves = desired.get("slaves")
            if not isinstance(slaves, list) or not 1 <= len(slaves) <= 16:
                raise HTTPException(422, "host-network bond requires between 1 and 16 slave interfaces")
            for slave in slaves:
                if not NETWORK_INTERFACE_RE.fullmatch(str(slave or "")):
                    raise HTTPException(422, "host-network bond slave interface name is invalid")
            result_h = {"bond_interface": bond, "mode": mode, "slaves": [str(s) for s in slaves]}
            if "miimon" in desired:
                miimon = desired["miimon"]
                if not isinstance(miimon, int) or isinstance(miimon, bool) or miimon < 0 or miimon > 1000:
                    raise HTTPException(422, "host-network bond miimon must be 0-1000")
                result_h["miimon"] = miimon
            if "lacp_rate" in desired:
                lacp = desired["lacp_rate"]
                if lacp not in {"slow", "fast"}:
                    raise HTTPException(422, "host-network bond lacp_rate must be slow or fast")
                result_h["lacp_rate"] = lacp
            return result_h
        if operation == "vlan.configure":
            allowed = {"interface", "vlan_id"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported host-network vlan.configure field(s): " + ", ".join(unknown))
            vlan_id = str(desired.get("vlan_id") or "")
            interface = str(desired.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise HTTPException(422, "host-network vlan interface name is invalid")
            if not NETWORK_VLAN_RE.fullmatch(vlan_id) or not 1 <= int(vlan_id) <= 4094:
                raise HTTPException(422, "host-network vlan_id must be a valid VLAN ID (1-4094)")
            return {"interface": interface, "vlan_id": int(vlan_id)}
        if operation == "mtu.configure":
            allowed = {"interface", "mtu"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported host-network mtu.configure field(s): " + ", ".join(unknown))
            mtu = str(desired.get("mtu") or "")
            interface = str(desired.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise HTTPException(422, "host-network mtu interface name is invalid")
            if not NETWORK_MTU_RE.fullmatch(mtu):
                raise HTTPException(422, "host-network MTU is invalid")
            return {"interface": interface, "mtu": int(mtu)}
        if operation == "address.configure":
            allowed = {"interface", "address", "prefix", "gateway", "dns"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported host-network address.configure field(s): " + ", ".join(unknown))
            address = str(desired.get("address") or "")
            prefix = desired.get("prefix")
            interface = str(desired.get("interface") or "")
            if not NETWORK_INTERFACE_RE.fullmatch(interface):
                raise HTTPException(422, "host-network address interface name is invalid")
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise HTTPException(422, "host-network address is not a valid IP address") from exc
            if prefix is not None:
                if not isinstance(prefix, int) or isinstance(prefix, bool) or not 1 <= prefix <= 128:
                    raise HTTPException(422, "host-network prefix must be between 1 and 128")
            result_h = {"interface": interface, "address": address}
            if prefix is not None:
                result_h["prefix"] = prefix
            if "gateway" in desired:
                gw = str(desired["gateway"] or "")
                try:
                    ipaddress.ip_address(gw)
                except ValueError as exc:
                    raise HTTPException(422, "host-network gateway is not a valid IP address") from exc
                result_h["gateway"] = gw
            if "dns" in desired:
                dns = desired["dns"]
                if not isinstance(dns, list) or len(dns) > 4:
                    raise HTTPException(422, "host-network dns must be a list of up to 4 addresses")
                for dns_entry in dns:
                    try:
                        ipaddress.ip_address(str(dns_entry or ""))
                    except ValueError as exc:
                        raise HTTPException(422, "host-network dns entry is not a valid IP address") from exc
                result_h["dns"] = [str(d) for d in dns]
            return result_h
        raise HTTPException(422, "unsupported host-network runtime operation")
    if kind == "network-switch":
        if operation == "lldp.observe":
            if desired:
                raise HTTPException(422, "network-switch lldp.observe does not accept desired_state fields")
            return {}
        if operation == "vlan.ensure":
            if set(desired) != {"vlan_id", "name"}:
                raise HTTPException(422, "network-switch vlan.ensure requires only vlan_id and name")
            vlan_id = desired.get("vlan_id")
            name = str(desired.get("name") or "")
            if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
                raise HTTPException(422, "network-switch vlan_id must be an integer between 1 and 4094")
            if not SWITCH_VLAN_NAME_RE.fullmatch(name):
                raise HTTPException(422, "network-switch VLAN name is unsafe")
            return {"vlan_id": vlan_id, "name": name}
        if operation == "port.configure":
            allowed = {"port", "mode", "access_vlan", "trunk_vlans"}
            unknown = sorted(set(desired) - allowed)
            if unknown:
                raise HTTPException(422, "unsupported network-switch port.configure field(s): " + ", ".join(unknown))
            port = str(desired.get("port") or "")
            mode = str(desired.get("mode") or "").lower()
            if not SWITCH_PORT_RE.fullmatch(port):
                raise HTTPException(422, "network-switch port identifier is unsafe")
            if mode == "access":
                if set(desired) != {"port", "mode", "access_vlan"}:
                    raise HTTPException(422, "network-switch access port requires only port, mode and access_vlan")
                vlan_id = desired.get("access_vlan")
                if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
                    raise HTTPException(422, "network-switch access_vlan must be an integer between 1 and 4094")
                return {"port": port, "mode": mode, "access_vlan": vlan_id}
            if mode == "trunk":
                if set(desired) != {"port", "mode", "trunk_vlans"}:
                    raise HTTPException(422, "network-switch trunk port requires only port, mode and trunk_vlans")
                vlan_ids = desired.get("trunk_vlans")
                if not isinstance(vlan_ids, list) or not 1 <= len(vlan_ids) <= 64:
                    raise HTTPException(422, "network-switch trunk_vlans must contain between 1 and 64 VLAN IDs")
                if any(not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 4094 for item in vlan_ids):
                    raise HTTPException(422, "network-switch trunk_vlans must contain VLAN IDs between 1 and 4094")
                if len(set(vlan_ids)) != len(vlan_ids):
                    raise HTTPException(422, "network-switch trunk_vlans must be unique")
                return {"port": port, "mode": mode, "trunk_vlans": sorted(vlan_ids)}
            raise HTTPException(422, "network-switch port mode must be access or trunk")
    if kind == "proxmox":
        return proxmox_runtime.validate_desired(operation, desired)
    if kind in {"vmware-workstation", "vmware", "openstack", "aws", "azure", "gcp"}:
        return desired
    if kind != "redfish":
        raise HTTPException(422, f"trusted runtime is not implemented for provider kind {kind!r}")
    if operation == "inventory.refresh":
        if desired:
            raise HTTPException(422, "Redfish inventory.refresh does not accept desired_state fields")
        return {}
    if operation == "power.set":
        if set(desired) != {"state"}:
            raise HTTPException(422, "Redfish power.set requires only desired_state.state")
        state = str(desired.get("state") or "").lower()
        if state not in POWER_RESET_TYPES:
            raise HTTPException(422, "unsupported Redfish power state")
        return {"state": state}
    if operation == "virtual-media.eject":
        if desired:
            raise HTTPException(422, "Redfish virtual-media.eject does not accept desired_state fields")
        return {}
    if operation == "virtual-media.insert":
        allowed = {"image_url", "write_protected"}
        unknown = sorted(set(desired) - allowed)
        if unknown:
            raise HTTPException(422, "unsupported Redfish virtual-media.insert desired_state field(s): " + ", ".join(unknown))
        image_url = str(desired.get("image_url") or "")
        parsed = urlparse(image_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise HTTPException(422, "Redfish virtual media image_url must be credential-free HTTPS without query/fragment")
        if desired.get("write_protected", True) is not True:
            raise HTTPException(422, "Redfish virtual media must be write-protected")
        return {"image_url": image_url, "write_protected": True}
    if operation == "secure-boot.apply":
        if set(desired) != {"enabled", "activation"}:
            raise HTTPException(422, "Redfish secure-boot.apply requires enabled and activation")
        if not isinstance(desired.get("enabled"), bool):
            raise HTTPException(422, "Redfish secure boot enabled must be boolean")
        activation = str(desired.get("activation") or "").lower()
        if activation != "reboot":
            raise HTTPException(422, "Redfish SecureBootEnable is activated on reboot; activation must be reboot")
        return {"enabled": desired["enabled"], "activation": activation}
    if operation in {"sriov.apply", "iommu.apply"}:
        if set(desired) != {"enabled", "activation"}:
            raise HTTPException(422, f"Redfish {operation} requires enabled and activation")
        if not isinstance(desired.get("enabled"), bool):
            raise HTTPException(422, f"Redfish {operation} enabled must be boolean")
        activation = str(desired.get("activation") or "").lower()
        if activation not in PLATFORM_ACTIVATIONS:
            raise HTTPException(422, f"Redfish {operation} activation must be immediate or reboot")
        return {"enabled": desired["enabled"], "activation": activation}
    if operation == "boot-order.apply":
        if set(desired) != {"order", "activation"}:
            raise HTTPException(422, "Redfish boot-order.apply requires order and activation")
        order = desired.get("order")
        if not isinstance(order, list) or not 1 <= len(order) <= 32:
            raise HTTPException(422, "Redfish boot order must contain between 1 and 32 exact boot option references")
        normalized = [str(item or "") for item in order]
        if any(not BOOT_ORDER_REF_RE.fullmatch(item) for item in normalized):
            raise HTTPException(422, "Redfish boot order contains an unsafe boot option reference")
        if len(set(normalized)) != len(normalized):
            raise HTTPException(422, "Redfish boot order references must be unique")
        activation = str(desired.get("activation") or "").lower()
        if activation not in PLATFORM_ACTIVATIONS:
            raise HTTPException(422, "Redfish boot order activation must be immediate or reboot")
        return {"order": normalized, "activation": activation}
    if operation == "bios.apply":
        if set(desired) != {"attributes"}:
            raise HTTPException(422, "Redfish bios.apply requires only desired_state.attributes")
        attributes = desired.get("attributes")
        if not isinstance(attributes, dict) or not attributes or len(attributes) > 64:
            raise HTTPException(422, "Redfish bios.apply attributes must contain between 1 and 64 entries")
        normalized: dict[str, Any] = {}
        for raw_name, raw_value in attributes.items():
            name = str(raw_name)
            if not BIOS_ATTRIBUTE_RE.fullmatch(name):
                raise HTTPException(422, "Redfish BIOS attribute name is unsafe")
            if isinstance(raw_value, bool):
                value: Any = raw_value
            elif isinstance(raw_value, int) and not isinstance(raw_value, bool):
                if raw_value < -(2**63) or raw_value > 2**63 - 1:
                    raise HTTPException(422, "Redfish BIOS integer attribute is out of range")
                value = raw_value
            elif isinstance(raw_value, str):
                if not raw_value or len(raw_value) > 256 or any(ord(ch) < 32 for ch in raw_value):
                    raise HTTPException(422, "Redfish BIOS string attribute is invalid")
                value = raw_value
            else:
                raise HTTPException(422, "Redfish BIOS attribute values must be string, integer or boolean scalars")
            normalized[name] = value
        return {"attributes": dict(sorted(normalized.items()))}
    if operation == "firmware.apply":
        if set(desired) != {"image_url", "component_id", "expected_version"}:
            raise HTTPException(422, "Redfish firmware.apply requires only image_url, component_id and expected_version")
        image_url = str(desired.get("image_url") or "")
        parsed = urlparse(image_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise HTTPException(422, "Redfish firmware image_url must be credential-free HTTPS without query/fragment")
        component_id = str(desired.get("component_id") or "")
        if not FIRMWARE_COMPONENT_RE.fullmatch(component_id):
            raise HTTPException(422, "Redfish firmware component_id is unsafe")
        expected_version = str(desired.get("expected_version") or "")
        if not expected_version or len(expected_version) > 160 or any(ord(ch) < 32 for ch in expected_version):
            raise HTTPException(422, "Redfish firmware expected_version must be a bounded printable string")
        return {"image_url": image_url, "component_id": component_id, "expected_version": expected_version}
    if operation == "storage.volume.apply":
        if set(desired) != {"controller_id", "volume_name", "raid_type", "drive_ids"}:
            raise HTTPException(422, "Redfish storage.volume.apply requires only controller_id, volume_name, raid_type and drive_ids")
        controller_id = str(desired.get("controller_id") or "")
        volume_name = str(desired.get("volume_name") or "")
        raid_type = str(desired.get("raid_type") or "").upper()
        drive_ids = desired.get("drive_ids")
        if not STORAGE_ID_RE.fullmatch(controller_id):
            raise HTTPException(422, "Redfish storage controller_id is unsafe")
        if not VOLUME_NAME_RE.fullmatch(volume_name):
            raise HTTPException(422, "Redfish storage volume_name is unsafe")
        if raid_type not in RAID_TYPES:
            raise HTTPException(422, "unsupported Redfish RAID type")
        if not isinstance(drive_ids, list) or not 1 <= len(drive_ids) <= 64:
            raise HTTPException(422, "Redfish storage drive_ids must contain between 1 and 64 exact drive IDs")
        normalized = [str(item or "") for item in drive_ids]
        if any(not STORAGE_ID_RE.fullmatch(item) for item in normalized):
            raise HTTPException(422, "Redfish storage drive_id is unsafe")
        if len(set(normalized)) != len(normalized):
            raise HTTPException(422, "Redfish storage drive_ids must be unique")
        minimum = {"RAID0": 1, "RAID1": 2, "RAID5": 3, "RAID6": 4, "RAID10": 4, "RAID50": 6, "RAID60": 8}[raid_type]
        if len(normalized) < minimum:
            raise HTTPException(422, f"{raid_type} requires at least {minimum} drives")
        return {"controller_id": controller_id, "volume_name": volume_name, "raid_type": raid_type, "drive_ids": sorted(normalized)}
    if operation == "storage.volume.delete":
        if set(desired) != {"controller_id", "volume_id", "confirm_volume_id"}:
            raise HTTPException(422, "Redfish storage.volume.delete requires controller_id, volume_id and confirm_volume_id")
        controller_id = str(desired.get("controller_id") or "")
        volume_id = str(desired.get("volume_id") or "")
        confirm = str(desired.get("confirm_volume_id") or "")
        if not STORAGE_ID_RE.fullmatch(controller_id) or not STORAGE_ID_RE.fullmatch(volume_id):
            raise HTTPException(422, "Redfish storage controller/volume ID is unsafe")
        if confirm != volume_id:
            raise HTTPException(422, "Redfish storage volume deletion confirmation must exactly match volume_id")
        return {"controller_id": controller_id, "volume_id": volume_id, "confirm_volume_id": confirm}
    if operation == "boot.set":
        allowed = {"target", "enabled", "mode"}
        unknown = sorted(set(desired) - allowed)
        if unknown:
            raise HTTPException(422, "unsupported Redfish boot desired_state field(s): " + ", ".join(unknown))
        target = str(desired.get("target") or "").lower()
        enabled = str(desired.get("enabled") or "once").lower()
        mode = str(desired.get("mode") or "").lower()
        if target not in BOOT_TARGETS:
            raise HTTPException(422, "unsupported Redfish boot target")
        if enabled not in BOOT_ENABLED:
            raise HTTPException(422, "unsupported Redfish boot enable mode")
        if mode and mode not in BOOT_MODES:
            raise HTTPException(422, "unsupported Redfish boot mode")
        result = {"target": target, "enabled": enabled}
        if mode:
            result["mode"] = mode
        return result
    raise HTTPException(422, "unsupported Redfish runtime operation")


def _safe_child(directory: Path, name: str) -> Path:
    if not SAFE_FILE_RE.fullmatch(name):
        raise HTTPException(503, "infrastructure credential profile contains an unsafe file reference")
    root = directory.resolve(strict=True)
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise HTTPException(503, "infrastructure credential profile file is unavailable")
    resolved = path.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        raise HTTPException(503, "infrastructure credential profile escapes credential root")
    return resolved


def _credential_profile(credential_ref: str) -> dict[str, Any]:
    if not CRED_RE.fullmatch(credential_ref):
        raise HTTPException(422, "invalid infrastructure credential reference")
    try:
        root = CREDENTIAL_ROOT.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(503, "infrastructure credential root is not mounted") from exc
    directory_candidate = root / credential_ref
    if directory_candidate.exists():
        try:
            directory = directory_candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise HTTPException(503, "infrastructure credential profile is not mounted") from exc
        if root != directory and root not in directory.parents:
            raise HTTPException(503, "infrastructure credential directory escapes credential root")
        profile_path = directory / "profile.json"
    else:
        directory = root
        profile_path = root / f"{credential_ref}.profile.json"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise HTTPException(503, "infrastructure credential profile.json is unavailable")
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "infrastructure credential profile.json is invalid") from exc
    if not isinstance(profile, dict):
        raise HTTPException(503, "infrastructure credential profile must be an object")
    allowed = {"auth", "username_file", "password_file", "ca_file"}
    if set(profile) - allowed:
        raise HTTPException(503, "infrastructure credential profile has unsupported fields")
    if profile.get("auth") != "basic":
        raise HTTPException(503, "Redfish runtime currently requires a basic-auth worker credential profile")
    username_file = _safe_child(directory, str(profile.get("username_file") or ""))
    password_file = _safe_child(directory, str(profile.get("password_file") or ""))
    try:
        username = username_file.read_text(encoding="utf-8").strip()
        password = password_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(503, "infrastructure credential material is unreadable") from exc
    if not username or not password:
        raise HTTPException(503, "infrastructure credential profile is incomplete")
    ca_file = None
    if profile.get("ca_file"):
        ca_file = _safe_child(directory, str(profile["ca_file"]))
    return {"username": username, "password": password, "ca_file": ca_file}


def _switch_endpoint(provider: dict[str, Any]) -> str:
    raw = str(provider.get("endpoint") or "").rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise HTTPException(422, "network-switch endpoint must be credential-free HTTPS")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise HTTPException(422, "network-switch endpoint must use an IP literal, not a hostname") from exc
    if parsed.path != "/restconf/data":
        raise HTTPException(422, "network-switch endpoint must use the fixed /restconf/data root")
    return raw


def _switch_policy(provider: dict[str, Any], desired: dict[str, Any] | None = None, operation: str | None = None) -> dict[str, Any]:
    if str(provider.get("api_version") or "") != SWITCH_RESTCONF_API_VERSION or str(provider.get("implementation_version") or "") != SWITCH_RESTCONF_IMPLEMENTATION_VERSION:
        raise HTTPException(422, "network-switch provider versions do not match the supported RESTCONF profile")
    caps = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    if set(caps) - {"profile", "model", "port_allowlist", "vlan_allowlist", "port_modes"} or caps.get("profile") != SWITCH_RESTCONF_PROFILE:
        raise HTTPException(422, "network-switch requires the supported pinned RESTCONF profile")
    model = str(caps.get("model") or "")
    ports = caps.get("port_allowlist")
    vlans = caps.get("vlan_allowlist")
    if not SWITCH_VLAN_NAME_RE.fullmatch(model) or not isinstance(ports, list) or not 1 <= len(ports) <= 128 or not isinstance(vlans, list) or not 1 <= len(vlans) <= 256:
        raise HTTPException(422, "network-switch capability policy is incomplete")
    port_set = {str(item) for item in ports}
    vlan_set = set(vlans)
    if len(port_set) != len(ports) or any(not SWITCH_PORT_RE.fullmatch(port) for port in port_set):
        raise HTTPException(422, "network-switch port allowlist contains unsafe or duplicate entries")
    if len(vlan_set) != len(vlans) or any(not isinstance(vlan, int) or isinstance(vlan, bool) or not 1 <= vlan <= 4094 for vlan in vlan_set):
        raise HTTPException(422, "network-switch VLAN allowlist contains invalid or duplicate entries")
    raw_modes = caps.get("port_modes", {})
    if not isinstance(raw_modes, dict) or set(raw_modes) - port_set:
        raise HTTPException(422, "network-switch port mode policy is invalid")
    modes: dict[str, set[str]] = {}
    for port, values in raw_modes.items():
        if not isinstance(values, list) or not values or len(values) > 2 or set(values) - {"access", "trunk"}:
            raise HTTPException(422, "network-switch port mode policy is invalid")
        modes[str(port)] = set(values)
    if desired is not None and operation == "vlan.ensure" and desired["vlan_id"] not in vlan_set:
        raise HTTPException(422, "network-switch VLAN is not allowlisted by provider capabilities")
    if desired is not None and operation == "port.configure":
        if desired["port"] not in port_set:
            raise HTTPException(422, "network-switch port is not allowlisted by provider capabilities")
        if modes.get(desired["port"]) and desired["mode"] not in modes[desired["port"]]:
            raise HTTPException(422, "network-switch port mode is not permitted by provider capabilities")
        ids = [desired["access_vlan"]] if desired["mode"] == "access" else desired["trunk_vlans"]
        if set(ids) - vlan_set:
            raise HTTPException(422, "network-switch VLAN is not allowlisted by provider capabilities")
    return {"ports": sorted(port_set), "vlans": sorted(vlan_set), "modes": modes}


def _switch_credential_profile(credential_ref: str) -> dict[str, Any]:
    credential = _credential_profile(credential_ref)
    return credential


def _switch_request_json(method: str, url: str, *, credential: dict[str, Any], body: dict[str, Any] | None = None, etag: str = "", allow_not_found: bool = False) -> tuple[dict[str, Any] | None, str]:
    auth = base64.b64encode(f"{credential['username']}:{credential['password']}".encode()).decode()
    headers = {"Accept": "application/yang-data+json", "Authorization": f"Basic {auth}"}
    if etag:
        headers["If-Match"] = etag
    payload = None
    if body is not None:
        payload = canonical_json(body).encode()
        if len(payload) > 1024 * 1024:
            raise HTTPException(422, "network-switch request exceeds the bounded JSON limit")
        headers["Content-Type"] = "application/yang-data+json"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        context = ssl.create_default_context(cafile=str(credential["ca_file"]) if credential.get("ca_file") else None)
    except (OSError, ssl.SSLError) as exc:
        raise HTTPException(503, "network-switch credential CA bundle is invalid") from exc
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise HTTPException(502, "network-switch response exceeded the bounded JSON limit")
            if not data:
                return {}, str(response.headers.get("ETag") or "")[:256]
            decoded = json.loads(data.decode("utf-8"))
            response_etag = str(response.headers.get("ETag") or "")[:256]
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None, ""
        if 300 <= exc.code < 400:
            raise HTTPException(502, f"network-switch redirect rejected with HTTP {exc.code}") from exc
        raise HTTPException(502, f"network-switch request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, f"network-switch request failed: {type(exc).__name__}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(502, "network-switch returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise HTTPException(502, "network-switch returned a non-object JSON response")
    return decoded, response_etag


def _switch_url(provider: dict[str, Any], path: str) -> str:
    return _switch_endpoint(provider) + path


def _switch_vlan_url(provider: dict[str, Any], vlan_id: int) -> str:
    return _switch_url(provider, "/openconfig-network-instance:network-instances/network-instance=default/vlans/vlan=" + str(vlan_id))


def _switch_port_url(provider: dict[str, Any], port: str) -> str:
    if not SWITCH_PORT_RE.fullmatch(port):
        raise HTTPException(422, "network-switch port identifier is unsafe")
    return _switch_url(provider, "/openconfig-interfaces:interfaces/interface=" + quote(port, safe=""))


def _switch_lldp_url(provider: dict[str, Any], port: str) -> str:
    return _switch_url(provider, "/openconfig-lldp:lldp/interfaces/interface=" + quote(port, safe="") + "/neighbors")


def _switch_vlan_snapshot(raw: dict[str, Any] | None, vlan_id: int, etag: str) -> dict[str, Any]:
    if raw is None:
        return {"vlan_id": vlan_id, "present": False, "name": "", "etag": ""}
    vlan = raw.get("openconfig-network-instance:vlan") if isinstance(raw.get("openconfig-network-instance:vlan"), dict) else raw
    config = vlan.get("config") if isinstance(vlan.get("config"), dict) else {}
    observed_id = config.get("vlan-id", vlan.get("vlan-id"))
    if observed_id != vlan_id:
        raise HTTPException(502, "network-switch VLAN response did not match requested VLAN")
    name = str(config.get("name", vlan.get("name", "")) or "")
    if name and not SWITCH_VLAN_NAME_RE.fullmatch(name):
        raise HTTPException(502, "network-switch returned an unsafe VLAN name")
    return {"vlan_id": vlan_id, "present": True, "name": name, "etag": etag}


def _switch_port_snapshot(raw: dict[str, Any], port: str, etag: str) -> dict[str, Any]:
    interface = raw.get("openconfig-interfaces:interface") if isinstance(raw.get("openconfig-interfaces:interface"), dict) else raw
    config = interface.get("config") if isinstance(interface.get("config"), dict) else {}
    observed_port = str(config.get("name", interface.get("name", "")) or "")
    if observed_port != port:
        raise HTTPException(502, "network-switch port response did not match requested port")
    vlan = interface.get("switched-vlan") if isinstance(interface.get("switched-vlan"), dict) else {}
    vlan_config = vlan.get("config") if isinstance(vlan.get("config"), dict) else {}
    mode = str(vlan_config.get("interface-mode") or "").lower()
    access = vlan_config.get("access-vlan")
    trunks = vlan_config.get("trunk-vlans") or []
    if mode not in {"access", "trunk", ""} or (access is not None and (not isinstance(access, int) or isinstance(access, bool) or not 1 <= access <= 4094)) or not isinstance(trunks, list) or len(trunks) > 64 or any(not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 4094 for item in trunks):
        raise HTTPException(502, "network-switch port response is invalid")
    return {"port": port, "mode": mode, "access_vlan": access if isinstance(access, int) else None, "trunk_vlans": sorted(trunks), "etag": etag}


def _switch_lldp_snapshot(raw: dict[str, Any], port: str, etag: str) -> dict[str, Any]:
    neighbors = raw.get("openconfig-lldp:neighbors") if isinstance(raw.get("openconfig-lldp:neighbors"), dict) else raw
    entries = neighbors.get("neighbor") if isinstance(neighbors.get("neighbor"), list) else []
    if len(entries) > 64:
        raise HTTPException(502, "network-switch LLDP response exceeds the bounded neighbor limit")
    safe: list[dict[str, str]] = []
    for entry in entries:
        state = entry.get("state") if isinstance(entry, dict) and isinstance(entry.get("state"), dict) else {}
        remote_port = str(state.get("port-id") or "")[:128]
        remote_system = str(state.get("system-name") or "")[:128]
        if remote_port and any(ord(char) < 32 for char in remote_port):
            raise HTTPException(502, "network-switch LLDP response contains unsafe neighbor data")
        if remote_system and any(ord(char) < 32 for char in remote_system):
            raise HTTPException(502, "network-switch LLDP response contains unsafe neighbor data")
        safe.append({"port": remote_port, "system_name": remote_system})
    return {"port": port, "neighbors": sorted(safe, key=lambda item: (item["port"], item["system_name"])), "etag": etag}


def _switch_current(provider: dict[str, Any], credential: dict[str, Any], operation: str, desired: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    policy = _switch_policy(provider, desired, operation)
    if operation == "vlan.ensure":
        url = _switch_vlan_url(provider, desired["vlan_id"])
        raw, etag = _switch_request_json("GET", url, credential=credential, allow_not_found=True)
        return url, {"etag": etag}, _switch_vlan_snapshot(raw, desired["vlan_id"], etag)
    if operation == "port.configure":
        url = _switch_port_url(provider, desired["port"])
        raw, etag = _switch_request_json("GET", url, credential=credential)
        if raw is None:
            raise HTTPException(409, "network-switch allowlisted port is not present")
        return url, {"etag": etag}, _switch_port_snapshot(raw, desired["port"], etag)
    observations: list[dict[str, Any]] = []
    for port in policy["ports"]:
        raw, etag = _switch_request_json("GET", _switch_lldp_url(provider, port), credential=credential)
        if raw is None:
            raise HTTPException(502, "network-switch LLDP collector returned an empty response")
        observations.append(_switch_lldp_snapshot(raw, port, etag))
    return _switch_endpoint(provider), {}, {"ports": observations}


def _switch_diff(operation: str, current: dict[str, Any], desired: dict[str, Any]) -> list[dict[str, Any]]:
    if operation == "lldp.observe":
        return []
    if operation == "vlan.ensure":
        return [] if current.get("present") and current.get("name") == desired["name"] else [{"field": f"vlan.{desired['vlan_id']}", "from": {"present": current.get("present"), "name": current.get("name")}, "to": {"name": desired["name"]}}]
    if desired["mode"] == "access":
        exact = current.get("mode") == "access" and current.get("access_vlan") == desired["access_vlan"] and not current.get("trunk_vlans")
        target: dict[str, Any] = {"mode": "access", "access_vlan": desired["access_vlan"]}
    else:
        exact = current.get("mode") == "trunk" and current.get("trunk_vlans") == desired["trunk_vlans"] and current.get("access_vlan") is None
        target = {"mode": "trunk", "trunk_vlans": desired["trunk_vlans"]}
    return [] if exact else [{"field": f"port.{desired['port']}.switched_vlan", "from": {"mode": current.get("mode"), "access_vlan": current.get("access_vlan"), "trunk_vlans": current.get("trunk_vlans")}, "to": target}]


def _apply_switch(operation: str, provider: dict[str, Any], resource_url: str, resource: dict[str, Any], desired: dict[str, Any], credential: dict[str, Any]) -> None:
    if operation == "lldp.observe":
        return
    etag = str(resource.get("etag") or "")
    if operation == "vlan.ensure":
        body = {"openconfig-network-instance:vlan": {"vlan-id": desired["vlan_id"], "config": {"vlan-id": desired["vlan_id"], "name": desired["name"]}}}
    elif desired["mode"] == "access":
        body = {"openconfig-interfaces:interface": {"name": desired["port"], "config": {"name": desired["port"]}, "switched-vlan": {"config": {"interface-mode": "ACCESS", "access-vlan": desired["access_vlan"]}}}}
    else:
        body = {"openconfig-interfaces:interface": {"name": desired["port"], "config": {"name": desired["port"]}, "switched-vlan": {"config": {"interface-mode": "TRUNK", "trunk-vlans": desired["trunk_vlans"]}}}}
    _switch_request_json("PUT", resource_url, credential=credential, body=body, etag=etag)


def _switch_verify(operation: str, current: dict[str, Any], desired: dict[str, Any]) -> bool:
    return bool(current.get("ports")) if operation == "lldp.observe" else not _switch_diff(operation, current, desired)


def _ipmi_credential_profile(credential_ref: str) -> dict[str, str]:
    if not CRED_RE.fullmatch(credential_ref):
        raise HTTPException(422, "invalid infrastructure credential reference")
    try:
        root = CREDENTIAL_ROOT.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(503, "infrastructure credential root is not mounted") from exc
    directory_candidate = root / credential_ref
    if directory_candidate.exists():
        try:
            directory = directory_candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise HTTPException(503, "infrastructure credential profile is not mounted") from exc
        if root != directory and root not in directory.parents:
            raise HTTPException(503, "infrastructure credential directory escapes credential root")
        profile_path = directory / "profile.json"
    else:
        directory = root
        profile_path = root / f"{credential_ref}.profile.json"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise HTTPException(503, "infrastructure credential profile.json is unavailable")
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "infrastructure credential profile.json is invalid") from exc
    if not isinstance(profile, dict):
        raise HTTPException(503, "infrastructure credential profile must be an object")
    allowed = {"auth", "username_file", "password_file"}
    if set(profile) - allowed:
        raise HTTPException(503, "IPMI credential profile has unsupported fields")
    if profile.get("auth") != "ipmi-lanplus":
        raise HTTPException(503, "IPMI runtime requires an ipmi-lanplus worker credential profile")
    username_file = _safe_child(directory, str(profile.get("username_file") or ""))
    password_file = _safe_child(directory, str(profile.get("password_file") or ""))
    try:
        username = username_file.read_text(encoding="utf-8").strip()
        password = password_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(503, "infrastructure credential material is unreadable") from exc
    if not username or not password:
        raise HTTPException(503, "IPMI credential profile is incomplete")
    return {"username": username, "password": password}


def _ipmi_endpoint(provider: dict[str, Any]) -> tuple[str, int | None]:
    raw = str(provider.get("endpoint") or "")
    parsed = urlparse(raw)
    if parsed.scheme != "ipmi" or not parsed.hostname:
        raise HTTPException(422, "IPMI endpoint must use ipmi://host[:port]")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise HTTPException(422, "IPMI endpoint contains forbidden credential/query material")
    if parsed.path not in {"", "/"}:
        raise HTTPException(422, "IPMI endpoint must not contain a path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(422, "IPMI endpoint port is invalid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(422, "IPMI endpoint port is invalid")
    return parsed.hostname, port


def _run_ipmitool(provider: dict[str, Any], credential: dict[str, str], args: list[str]) -> str:
    tool = shutil.which("ipmitool")
    if not tool:
        raise HTTPException(503, "trusted IPMI runtime requires ipmitool")
    host, port = _ipmi_endpoint(provider)
    argv = [tool, "-I", "lanplus", "-H", host, "-U", credential["username"], "-E"]
    if port is not None:
        argv.extend(["-p", str(port)])
    argv.extend(args)
    env = {"IPMI_PASSWORD": credential["password"], "LC_ALL": "C", "LANG": "C"}
    try:
        completed = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=max(1.0, IPMI_TIMEOUT_SECONDS), env=env, shell=False, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(502, f"IPMI provider request failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise HTTPException(502, "IPMI provider command failed")
    output = completed.stdout or ""
    if len(output.encode("utf-8", errors="ignore")) > 65536:
        raise HTTPException(502, "IPMI provider response exceeded the bounded text limit")
    return output


def _parse_ipmi_power(output: str) -> dict[str, Any]:
    lowered = output.lower()
    if "chassis power is on" in lowered:
        power = "On"
    elif "chassis power is off" in lowered:
        power = "Off"
    else:
        raise HTTPException(502, "IPMI power status response was not recognized")
    return {
        "resource_id": "ipmi-chassis", "name": "IPMI chassis", "manufacturer": "", "model": "",
        "serial_number": "", "power_state": power, "last_reset_time": "", "boot_progress": "",
        "boot_progress_time": "", "health": "UNKNOWN", "state": "Enabled",
        "boot_target": "", "boot_enabled": "", "boot_mode": "",
    }


def _parse_ipmi_boot(output: str) -> dict[str, Any]:
    lowered = output.lower()
    selectors = [
        ("force pxe", "Pxe"),
        ("force boot from default hard-drive", "Hdd"),
        ("force boot from default hard drive", "Hdd"),
        ("force boot from cd/dvd", "Cd"),
        ("force boot from cd-rom", "Cd"),
        ("no override", "None"),
    ]
    target = next((value for marker, value in selectors if marker in lowered), "")
    if not target:
        raise HTTPException(502, "IPMI boot parameter response was not recognized")
    if "boot flag valid" not in lowered:
        enabled = "Disabled"
    elif "persistent" in lowered or "all future boots" in lowered:
        enabled = "Continuous"
    else:
        enabled = "Once"
    if "efi" in lowered and "legacy" not in lowered:
        mode = "UEFI"
    elif "bios pc compatible" in lowered or "legacy" in lowered:
        mode = "Legacy"
    else:
        mode = ""
    return {
        "resource_id": "ipmi-chassis", "name": "IPMI chassis", "manufacturer": "", "model": "",
        "serial_number": "", "power_state": "", "last_reset_time": "", "boot_progress": "",
        "boot_progress_time": "", "health": "UNKNOWN", "state": "Enabled",
        "boot_target": target, "boot_enabled": enabled, "boot_mode": mode,
    }


def _ipmi_current(provider: dict[str, Any], credential: dict[str, str], operation: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    host, port = _ipmi_endpoint(provider)
    endpoint = f"ipmi://{host}" + (f":{port}" if port is not None else "")
    if operation == "power.set":
        current = _parse_ipmi_power(_run_ipmitool(provider, credential, ["chassis", "power", "status"]))
    elif operation == "boot.set":
        current = _parse_ipmi_boot(_run_ipmitool(provider, credential, ["chassis", "bootparam", "get", "5"]))
    else:
        raise HTTPException(422, "unsupported IPMI runtime operation")
    return endpoint, {}, current


def _apply_ipmi(operation: str, provider: dict[str, Any], desired: dict[str, Any], credential: dict[str, str]) -> None:
    if operation == "power.set":
        _run_ipmitool(provider, credential, ["chassis", "power", IPMI_POWER_COMMANDS[desired["state"]]])
        return
    if operation == "boot.set":
        target = IPMI_BOOT_DEVICES[desired["target"]]
        argv = ["chassis", "bootdev", target]
        options: list[str] = []
        if desired["enabled"] == "continuous":
            options.append("persistent")
        if desired.get("mode") == "uefi":
            options.append("efiboot")
        if options:
            argv.append("options=" + ",".join(options))
        _run_ipmitool(provider, credential, argv)
        return
    raise HTTPException(422, "unsupported IPMI runtime operation")



def _pxe_credential_profile(credential_ref: str) -> dict[str, Any]:
    if not CRED_RE.fullmatch(credential_ref):
        raise HTTPException(422, "invalid infrastructure credential reference")
    try:
        root = CREDENTIAL_ROOT.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(503, "infrastructure credential root is not mounted") from exc
    directory_candidate = root / credential_ref
    if directory_candidate.exists():
        directory = directory_candidate.resolve(strict=True)
        if root != directory and root not in directory.parents:
            raise HTTPException(503, "PXE credential directory escapes credential root")
        profile_path = directory / "profile.json"
    else:
        directory = root
        profile_path = root / f"{credential_ref}.profile.json"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise HTTPException(503, "PXE credential profile.json is unavailable")
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "PXE credential profile.json is invalid") from exc
    if not isinstance(profile, dict):
        raise HTTPException(503, "PXE credential profile must be an object")
    allowed = {"auth", "token_file", "ca_file", "unattended_profiles", "callback_tokens"}
    if set(profile) - allowed:
        raise HTTPException(503, "PXE credential profile has unsupported fields")
    if profile.get("auth") != "bearer-pxe-controller":
        raise HTTPException(503, "PXE runtime requires a bearer-pxe-controller worker credential profile")
    token_path = _safe_child(directory, str(profile.get("token_file") or ""))
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(503, "PXE controller token is unreadable") from exc
    if not token or len(token) > 4096:
        raise HTTPException(503, "PXE controller token is invalid")
    ca_file = _safe_child(directory, str(profile["ca_file"])) if profile.get("ca_file") else None
    resolved_maps: dict[str, dict[str, Path]] = {}
    for field in ("unattended_profiles", "callback_tokens"):
        mapping = profile.get(field)
        if not isinstance(mapping, dict) or not mapping or len(mapping) > 128:
            raise HTTPException(503, f"PXE credential profile requires a bounded {field} map")
        resolved: dict[str, Path] = {}
        for raw_ref, raw_name in mapping.items():
            ref = str(raw_ref)
            if not PXE_REF_RE.fullmatch(ref):
                raise HTTPException(503, f"PXE credential profile contains an invalid {field} reference")
            resolved[ref] = _safe_child(directory, str(raw_name or ""))
        resolved_maps[field] = resolved
    return {"token": token, "ca_file": ca_file, **resolved_maps}


def _pxe_callback_token(credential: dict[str, Any], ref: str, expected_sha256: str) -> str:
    path = (credential.get("callback_tokens") or {}).get(ref)
    if not isinstance(path, Path):
        raise HTTPException(503, "PXE callback_ref is not mounted in the worker credential profile")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(503, "PXE callback token is unreadable") from exc
    if not token or len(token) > 1024 or hashlib.sha256(token.encode()).hexdigest() != expected_sha256:
        raise HTTPException(409, "PXE callback token does not match the exact approved token hash")
    return token


def _pxe_unattended_profile(credential: dict[str, Any], ref: str) -> dict[str, Any]:
    path = (credential.get("unattended_profiles") or {}).get(ref)
    if not isinstance(path, Path):
        raise HTTPException(503, "PXE unattended_profile_ref is not mounted in the worker credential profile")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HTTPException(503, "PXE unattended profile is unreadable") from exc
    if len(raw) > 65536:
        raise HTTPException(503, "PXE unattended profile exceeds the bounded profile size")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(503, "PXE unattended profile is invalid JSON") from exc
    if not isinstance(profile, dict):
        raise HTTPException(503, "PXE unattended profile must be an object")
    allowed = {
        "schema_version", "os_family", "hostname_template", "locale", "timezone", "keyboard", "packages",
        "storage_profile_ref", "network_profile_ref", "secret_refs",
    }
    if set(profile) - allowed:
        raise HTTPException(503, "PXE unattended profile contains unsupported fields; command/script surfaces are forbidden")
    if profile.get("schema_version") != 1 or str(profile.get("os_family") or "") not in PXE_PROFILE_OS:
        raise HTTPException(503, "PXE unattended profile schema/os_family is unsupported")
    for field in ("hostname_template", "locale", "timezone", "keyboard"):
        value = str(profile.get(field) or "")
        if value and (len(value) > 160 or any(ord(ch) < 32 for ch in value)):
            raise HTTPException(503, f"PXE unattended profile {field} is invalid")
    packages = profile.get("packages") or []
    if not isinstance(packages, list) or len(packages) > 128 or any(not PXE_PACKAGE_RE.fullmatch(str(item)) for item in packages):
        raise HTTPException(503, "PXE unattended profile packages are invalid")
    for field in ("storage_profile_ref", "network_profile_ref"):
        value = str(profile.get(field) or "")
        if value and not PXE_REF_RE.fullmatch(value):
            raise HTTPException(503, f"PXE unattended profile {field} is invalid")
    secret_refs = profile.get("secret_refs") or []
    if not isinstance(secret_refs, list) or len(secret_refs) > 64 or any(not PXE_REF_RE.fullmatch(str(item)) for item in secret_refs):
        raise HTTPException(503, "PXE unattended profile secret_refs are invalid")
    return {
        "schema_version": 1,
        "os_family": str(profile["os_family"]),
        "hostname_template": str(profile.get("hostname_template") or ""),
        "locale": str(profile.get("locale") or ""),
        "timezone": str(profile.get("timezone") or ""),
        "keyboard": str(profile.get("keyboard") or ""),
        "packages": [str(item) for item in packages],
        "storage_profile_ref": str(profile.get("storage_profile_ref") or ""),
        "network_profile_ref": str(profile.get("network_profile_ref") or ""),
        "secret_refs": [str(item) for item in secret_refs],
    }


def _pxe_endpoint(provider: dict[str, Any]) -> str:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    if capabilities.get("network_scope") != "private-offline":
        raise HTTPException(422, "PXE controller must be explicitly bound to the private-offline network scope")
    if capabilities.get("artifact_delivery") != "shared-readonly-mirror":
        raise HTTPException(422, "PXE controller must use the shared-readonly-mirror artifact delivery contract")
    raw = str(provider.get("endpoint") or "").rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(422, "PXE controller endpoint must use HTTPS")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise HTTPException(422, "PXE controller endpoint contains forbidden credential/query material")
    return raw


def _pxe_node_url(provider: dict[str, Any], server_id: str) -> str:
    if not re.fullmatch(r"srv_[A-Za-z0-9]{8,64}", server_id):
        raise HTTPException(422, "PXE target server id is invalid")
    return _pxe_endpoint(provider) + "/nodes/" + server_id


def _pxe_request_json(
    method: str, url: str, *, credential: dict[str, Any], body: dict[str, Any] | None = None, allow_not_found: bool = False
) -> dict[str, Any] | None:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {credential['token']}"}
    payload = None
    if body is not None:
        payload = canonical_json(body).encode()
        if len(payload) > 1024 * 1024:
            raise HTTPException(422, "PXE controller request exceeds the bounded JSON limit")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
    try:
        context = ssl.create_default_context(cafile=str(credential["ca_file"]) if credential.get("ca_file") else None)
    except (OSError, ssl.SSLError) as exc:
        raise HTTPException(503, "PXE credential CA bundle is invalid") from exc
    handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise HTTPException(502, "PXE controller response exceeded the bounded JSON limit")
            if not data:
                return {}
            decoded = json.loads(data.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        if 300 <= exc.code < 400:
            raise HTTPException(502, f"PXE controller redirect rejected with HTTP {exc.code}") from exc
        raise HTTPException(502, f"PXE controller request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, f"PXE controller request failed: {type(exc).__name__}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(502, "PXE controller returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise HTTPException(502, "PXE controller returned a non-object JSON response")
    return decoded


def _pxe_server_target(typed: dict[str, Any]) -> dict[str, Any]:
    servers = [target for target in typed.get("targets") or [] if isinstance(target, dict) and target.get("entity_type") == "server"]
    if len(servers) != 1:
        raise HTTPException(422, "PXE runtime requires exactly one registered server snapshot")
    server = servers[0]
    labels = server.get("labels") if isinstance(server.get("labels"), dict) else {}
    mac = str(labels.get("provisioning_mac") or "").lower()
    nic = str(labels.get("provisioning_nic") or "")
    boot_provider_id = str(labels.get("boot_provider_id") or "")
    if not PXE_MAC_RE.fullmatch(mac):
        raise HTTPException(422, "PXE target server provisioning_mac label must be canonical lowercase colon MAC")
    if not PXE_NIC_RE.fullmatch(nic):
        raise HTTPException(422, "PXE target server provisioning_nic label is invalid")
    if not re.fullmatch(r"ipr_[A-Za-z0-9]{8,64}", boot_provider_id):
        raise HTTPException(422, "PXE target server boot_provider_id label is invalid")
    provisioning_ip = str(server.get("provisioning_ip") or "")
    management_ip = str(server.get("management_ip") or "")
    if not provisioning_ip or not management_ip:
        raise HTTPException(422, "PXE target server requires management and provisioning IPs")
    return {**server, "pxe_identity": {"mac": mac, "nic": nic, "boot_provider_id": boot_provider_id}}


def _pxe_boot_provider_target(typed: dict[str, Any], server: dict[str, Any]) -> dict[str, Any]:
    boot_provider_id = server["pxe_identity"]["boot_provider_id"]
    matches = [
        target for target in typed.get("targets") or []
        if isinstance(target, dict) and target.get("id") == boot_provider_id and target.get("kind") in {"redfish", "ipmi"}
    ]
    if len(matches) != 1:
        raise HTTPException(422, "PXE plan does not contain the exact trusted boot provider snapshot")
    return matches[0]


def _pxe_artifact_supply(typed: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    supply = typed.get("artifact_supply") if isinstance(typed.get("artifact_supply"), dict) else {}
    if supply.get("mode") != "pxe-ready-manifest-bound" or supply.get("credential_material_in_plan") is not False or supply.get("public_network_required") is not False:
        raise HTTPException(422, "PXE runtime requires an exact credential-free READY artifact supply")
    supply_hash = str(supply.get("supply_hash") or "")
    unsigned = dict(supply)
    unsigned.pop("supply_hash", None)
    if not PXE_SHA256_RE.fullmatch(supply_hash) or sha256_hex(unsigned) != supply_hash:
        raise HTTPException(409, "PXE artifact supply hash binding mismatch")
    if not PXE_SHA256_RE.fullmatch(str(supply.get("manifest_hash") or "")):
        raise HTTPException(409, "PXE artifact manifest hash binding is invalid")
    artifacts = supply.get("artifacts") if isinstance(supply.get("artifacts"), dict) else {}
    if set(artifacts) != set(desired["artifacts"]):
        raise HTTPException(409, "PXE artifact role set no longer matches the approved desired state")
    normalized: dict[str, dict[str, Any]] = {}
    for role, artifact_id in desired["artifacts"].items():
        item = artifacts.get(role)
        if not isinstance(item, dict) or str(item.get("artifact_id") or "") != artifact_id:
            raise HTTPException(409, "PXE artifact ID binding mismatch")
        digest = str(item.get("digest") or "")
        reference = str(item.get("offline_reference") or "")
        parsed = urlparse(reference)
        if not digest.startswith("sha256:") or len(digest) != 71 or parsed.scheme != "file" or parsed.netloc or not parsed.path.startswith("/"):
            raise HTTPException(409, "PXE artifact supply contains an unsafe runtime reference")
        normalized[role] = {"artifact_id": artifact_id, "kind": str(item.get("kind") or ""), "version": str(item.get("version") or ""), "digest": digest, "offline_reference": reference}
    return {**supply, "artifacts": normalized}


def _pxe_verify_artifact_files(supply: dict[str, Any]) -> None:
    raw_root = ARTIFACT_MIRROR_ROOT.expanduser()
    try:
        if raw_root.is_symlink():
            raise HTTPException(503, "PXE artifact mirror root must not be a symlink")
        root = raw_root.resolve(strict=True)
    except OSError as exc:
        raise HTTPException(503, "PXE artifact mirror root is unavailable") from exc
    if not root.is_dir():
        raise HTTPException(503, "PXE artifact mirror root must be an existing directory")
    for role, item in supply["artifacts"].items():
        candidate = Path(urlparse(item["offline_reference"]).path)
        try:
            relative = candidate.relative_to(root)
        except ValueError as exc:
            raise HTTPException(409, f"PXE {role} artifact escapes the configured mirror root") from exc
        try:
            cursor = root
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise HTTPException(409, f"PXE {role} artifact path must not contain symlinks")
            path = candidate.resolve(strict=True)
            if root != path and root not in path.parents:
                raise HTTPException(409, f"PXE {role} artifact escapes the configured mirror root")
            if not path.is_file():
                raise HTTPException(409, f"PXE {role} artifact is unavailable at its exact mirrored path")
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        except OSError as exc:
            raise HTTPException(409, f"PXE {role} artifact could not be verified") from exc
        if "sha256:" + digest != item["digest"]:
            raise HTTPException(409, f"PXE {role} artifact digest drifted after approval")


def _pxe_state_history(raw_history: Any, current_state: str) -> list[str]:
    history = raw_history if isinstance(raw_history, list) else []
    if len(history) > 32 or any(str(state) not in PXE_STATES for state in history):
        raise HTTPException(502, "PXE controller returned an invalid provisioning state history")
    normalized: list[str] = []
    for raw_state in history:
        state = str(raw_state)
        if not normalized or normalized[-1] != state:
            normalized.append(state)
    if current_state != "idle" and not normalized:
        raise HTTPException(502, "PXE controller omitted provisioning state history")
    if normalized and normalized[-1] != current_state:
        raise HTTPException(502, "PXE controller state history does not terminate at the current state")
    if "idle" in normalized[1:]:
        raise HTTPException(502, "PXE controller provisioning state history returned to idle")
    if "failed" in normalized and (current_state != "failed" or normalized[-1] != "failed"):
        raise HTTPException(502, "PXE controller provisioning state history continued after failure")
    progress = [state for state in normalized if state in PXE_PROGRESS_RANK]
    expected_prefix = list(PXE_PROGRESS_STATES[:len(progress)])
    if progress != expected_prefix:
        raise HTTPException(502, "PXE controller provisioning state history skipped or regressed")
    if current_state == "complete" and progress != list(PXE_PROGRESS_STATES):
        raise HTTPException(502, "PXE completion lacks the required requested-to-complete state history")
    return normalized


def _pxe_safe_controller_snapshot(raw: dict[str, Any] | None, server: dict[str, Any]) -> dict[str, Any]:
    identity = server["pxe_identity"]
    if raw is None:
        return {
            "registered": False, "node_id": server["id"], "nic": identity["nic"], "mac": identity["mac"], "state": "idle",
            "state_history": [], "plan_hash": "", "artifact_manifest_hash": "", "callback_token_sha256": "", "management_ip": "",
        }
    node_id = str(raw.get("node_id") or "")
    nic = str(raw.get("nic") or "")
    mac = str(raw.get("mac") or "").lower()
    state = str(raw.get("state") or "")
    if node_id != server["id"] or nic != identity["nic"] or mac != identity["mac"]:
        raise HTTPException(409, "PXE controller node/NIC/MAC identity does not match the registered server snapshot")
    if state not in PXE_STATES:
        raise HTTPException(502, "PXE controller returned an unsupported provisioning state")
    plan_hash = str(raw.get("plan_hash") or "")
    manifest_hash = str(raw.get("artifact_manifest_hash") or "")
    callback_hash = str(raw.get("callback_token_sha256") or "")
    for value, label in ((plan_hash, "plan_hash"), (manifest_hash, "artifact_manifest_hash"), (callback_hash, "callback_token_sha256")):
        if value and not PXE_SHA256_RE.fullmatch(value):
            raise HTTPException(502, f"PXE controller returned an invalid {label}")
    management_ip = str(raw.get("management_ip") or "")
    if len(management_ip) > 64:
        raise HTTPException(502, "PXE controller returned an invalid management_ip")
    history = _pxe_state_history(raw.get("state_history"), state)
    return {
        "registered": True, "node_id": node_id, "nic": nic, "mac": mac, "state": state,
        "state_history": history, "plan_hash": plan_hash, "artifact_manifest_hash": manifest_hash, "callback_token_sha256": callback_hash,
        "management_ip": management_ip,
    }


def _pxe_current(provider: dict[str, Any], credential: dict[str, Any], server: dict[str, Any]) -> dict[str, Any]:
    raw = _pxe_request_json("GET", _pxe_node_url(provider, server["id"]), credential=credential, allow_not_found=True)
    return _pxe_safe_controller_snapshot(raw, server)


def _boot_provider_current(provider: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    kind = str(provider.get("kind") or "")
    credential_ref = str(provider.get("credential_ref") or "")
    if kind == "redfish":
        credential = _credential_profile(credential_ref)
        _, _, current = _redfish_current(provider, credential, "boot.set")
        return credential, {**current, "provider_kind": "redfish"}
    if kind == "ipmi":
        credential = _ipmi_credential_profile(credential_ref)
        _, _, power = _ipmi_current(provider, credential, "power.set")
        _, _, boot = _ipmi_current(provider, credential, "boot.set")
        return credential, {**power, "provider_kind": "ipmi", "boot_target": boot.get("boot_target", ""), "boot_enabled": boot.get("boot_enabled", ""), "boot_mode": boot.get("boot_mode", "")}
    raise HTTPException(422, "PXE boot provider must be Redfish or IPMI")


def _pxe_preview_current(typed: dict[str, Any], provider: dict[str, Any], credential: dict[str, Any], server: dict[str, Any]) -> dict[str, Any]:
    boot_provider = _pxe_boot_provider_target(typed, server)
    _, boot = _boot_provider_current(boot_provider)
    return {"controller": _pxe_current(provider, credential, server), "boot_provider": boot}


def _pxe_desired_diff(current: dict[str, Any], desired: dict[str, Any], server: dict[str, Any], supply: dict[str, Any]) -> list[dict[str, Any]]:
    controller = current.get("controller") if isinstance(current.get("controller"), dict) else {}
    boot = current.get("boot_provider") if isinstance(current.get("boot_provider"), dict) else {}
    changes: list[dict[str, Any]] = []
    if controller.get("state") != "complete":
        changes.append({"field": "provisioning_state", "from": controller.get("state") or "idle", "to": "complete"})
    if controller.get("artifact_manifest_hash") != supply["manifest_hash"]:
        changes.append({"field": "artifact_manifest_hash", "from": controller.get("artifact_manifest_hash") or "", "to": supply["manifest_hash"]})
    if controller.get("callback_token_sha256") != desired["callback_token_sha256"]:
        changes.append({"field": "callback_token_sha256", "from": controller.get("callback_token_sha256") or "", "to": desired["callback_token_sha256"]})
    expected_target = "Pxe"
    expected_enabled = "Once"
    if str(boot.get("boot_target") or "") != expected_target:
        changes.append({"field": "boot_target", "from": boot.get("boot_target") or "", "to": expected_target})
    if str(boot.get("boot_enabled") or "") != expected_enabled:
        changes.append({"field": "boot_enabled", "from": boot.get("boot_enabled") or "", "to": expected_enabled})
    return changes


def _pxe_prepare(
    typed: dict[str, Any], provider: dict[str, Any], credential: dict[str, Any], server: dict[str, Any], desired: dict[str, Any], supply: dict[str, Any]
) -> None:
    callback_token = _pxe_callback_token(credential, desired["callback_ref"], desired["callback_token_sha256"])
    profile = _pxe_unattended_profile(credential, desired["unattended_profile_ref"])
    body = {
        "node_id": server["id"],
        "nic": server["pxe_identity"]["nic"],
        "mac": server["pxe_identity"]["mac"],
        "provisioning_ip": server["provisioning_ip"],
        "management_ip": server["management_ip"],
        "boot_method": desired["boot_method"],
        "artifact_manifest_hash": supply["manifest_hash"],
        "artifacts": supply["artifacts"],
        "unattended_profile_ref": desired["unattended_profile_ref"],
        "unattended_profile": profile,
        "callback": {
            "token": callback_token,
            "token_sha256": desired["callback_token_sha256"],
            "node_id": server["id"],
            "plan_hash": typed["plan_hash"],
        },
        "idempotency_key": hashlib.sha256(f"{typed['plan_hash']}:{server['id']}".encode()).hexdigest(),
    }
    _pxe_request_json("PUT", _pxe_node_url(provider, server["id"]), credential=credential, body=body)


def _pxe_verify_boot_setting(provider: dict[str, Any], credential: dict[str, Any], desired_boot: dict[str, Any]) -> dict[str, Any]:
    kind = str(provider.get("kind") or "")
    after: dict[str, Any] = {}
    for attempt in range(max(1, VERIFY_ATTEMPTS)):
        if kind == "redfish":
            _, _, after = _redfish_current(provider, credential, "boot.set")
        else:
            _, _, after = _ipmi_current(provider, credential, "boot.set")
        if _verification_matches("boot.set", after, desired_boot):
            return after
        if attempt + 1 < max(1, VERIFY_ATTEMPTS):
            time.sleep(max(0.0, VERIFY_DELAY_SECONDS))
    raise HTTPException(502, "PXE one-time network boot setting did not verify")


def _pxe_set_one_time_boot_and_start(boot_provider: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    kind = str(boot_provider.get("kind") or "")
    credential, before = _boot_provider_current(boot_provider)
    desired_boot = {"target": "pxe", "enabled": "once", "mode": desired["boot_mode"]}
    if not _verification_matches("boot.set", before, desired_boot):
        if kind == "redfish":
            system_url, system = _redfish_system(boot_provider, credential)
            _apply_redfish("boot.set", system_url, system, desired_boot, credential)
        else:
            _apply_ipmi("boot.set", boot_provider, desired_boot, credential)
        _pxe_verify_boot_setting(boot_provider, credential, desired_boot)
    if kind == "redfish":
        system_url, system, power_before = _redfish_current(boot_provider, credential, "power.set")
        state = str(power_before.get("power_state") or "").lower()
        power_desired = {"state": "restart" if state == "on" else "on"}
        _apply_redfish("power.set", system_url, system, power_desired, credential)
        for attempt in range(max(1, VERIFY_ATTEMPTS)):
            _, _, power_after = _redfish_current(boot_provider, credential, "power.set")
            if _verification_matches("power.set", power_after, power_desired, before=power_before):
                return power_after
            if attempt + 1 < max(1, VERIFY_ATTEMPTS):
                time.sleep(max(0.0, VERIFY_DELAY_SECONDS))
        raise HTTPException(502, "PXE boot-provider power transition did not verify")
    _, _, power_before = _ipmi_current(boot_provider, credential, "power.set")
    if str(power_before.get("power_state") or "").lower() == "on":
        _apply_ipmi("power.set", boot_provider, {"state": "force-off"}, credential)
        for attempt in range(max(1, VERIFY_ATTEMPTS)):
            _, _, off = _ipmi_current(boot_provider, credential, "power.set")
            if _verification_matches("power.set", off, {"state": "force-off"}):
                break
            if attempt + 1 < max(1, VERIFY_ATTEMPTS):
                time.sleep(max(0.0, VERIFY_DELAY_SECONDS))
        else:
            raise HTTPException(502, "PXE IPMI power-off transition did not verify")
    _apply_ipmi("power.set", boot_provider, {"state": "on"}, credential)
    for attempt in range(max(1, VERIFY_ATTEMPTS)):
        _, _, on = _ipmi_current(boot_provider, credential, "power.set")
        if _verification_matches("power.set", on, {"state": "on"}):
            return on
        if attempt + 1 < max(1, VERIFY_ATTEMPTS):
            time.sleep(max(0.0, VERIFY_DELAY_SECONDS))
    raise HTTPException(502, "PXE IPMI power-on transition did not verify")


def _pxe_start(provider: dict[str, Any], credential: dict[str, Any], server: dict[str, Any], typed: dict[str, Any]) -> None:
    _pxe_request_json(
        "POST", _pxe_node_url(provider, server["id"]) + "/actions/provision", credential=credential,
        body={"plan_hash": typed["plan_hash"], "idempotency_key": hashlib.sha256(f"{typed['plan_hash']}:{server['id']}".encode()).hexdigest()},
    )


def _pxe_wait_complete(
    provider: dict[str, Any], credential: dict[str, Any], server: dict[str, Any], desired: dict[str, Any], supply: dict[str, Any], typed_plan_hash: str
) -> tuple[dict[str, Any], list[str]]:
    deadline = time.monotonic() + desired["completion_timeout_seconds"]
    observed_states: list[str] = []
    while True:
        current = _pxe_current(provider, credential, server)
        state = current["state"]
        if not observed_states or observed_states[-1] != state:
            observed_states.append(state)
        if current.get("plan_hash") and current["plan_hash"] != typed_plan_hash:
            raise HTTPException(409, "PXE controller plan hash drifted during provisioning")
        if current.get("artifact_manifest_hash") and current["artifact_manifest_hash"] != supply["manifest_hash"]:
            raise HTTPException(409, "PXE controller artifact manifest hash drifted during provisioning")
        if current.get("callback_token_sha256") and current["callback_token_sha256"] != desired["callback_token_sha256"]:
            raise HTTPException(409, "PXE callback token hash binding drifted during provisioning")
        if state == "complete":
            if current.get("plan_hash") != typed_plan_hash or current.get("artifact_manifest_hash") != supply["manifest_hash"] or current.get("callback_token_sha256") != desired["callback_token_sha256"]:
                raise HTTPException(409, "PXE completion callback is missing exact plan/artifact/token bindings")
            if current.get("management_ip") and current["management_ip"] != server["management_ip"]:
                raise HTTPException(409, "PXE completion callback reported the wrong management IP")
            return current, list(current.get("state_history") or observed_states)
        if state == "failed":
            raise HTTPException(502, "PXE provisioning controller reported a bounded failure")
        if time.monotonic() >= deadline:
            raise HTTPException(504, "PXE provisioning did not reach callback/complete before the approved timeout")
        time.sleep(min(2.0, max(0.05, VERIFY_DELAY_SECONDS)))


def _pxe_host_ready(server: dict[str, Any], timeout_seconds: int) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            with socket.create_connection((str(server["management_ip"]), int(server.get("ssh_port") or 22)), timeout=min(3.0, max(0.5, REQUEST_TIMEOUT))):
                return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(2.0, max(0.05, VERIFY_DELAY_SECONDS)))


def _execute_pxe(
    typed: dict[str, Any], provider: dict[str, Any], desired: dict[str, Any], credential: dict[str, Any], runtime_preview: dict[str, Any]
) -> dict[str, Any]:
    server = _pxe_server_target(typed)
    if desired.get("confirm_server") and desired["confirm_server"] != server.get("hostname"):
        raise HTTPException(409, "PXE reimage confirmation no longer matches the exact server snapshot")
    supply = _pxe_artifact_supply(typed, desired)
    _pxe_callback_token(credential, desired["callback_ref"], desired["callback_token_sha256"])
    _pxe_unattended_profile(credential, desired["unattended_profile_ref"])
    current = _pxe_preview_current(typed, provider, credential, server)
    if sha256_hex(current) != str(runtime_preview.get("current_hash") or ""):
        raise HTTPException(409, "infrastructure state drifted after deterministic preview; re-plan and re-approve")
    controller = current["controller"]
    if controller.get("plan_hash") and controller["plan_hash"] != typed["plan_hash"] and controller.get("state") not in {"idle", "failed", "complete"}:
        raise HTTPException(409, "PXE controller already has a different active plan for this node")
    if str(typed.get("operation") or "") == "os.provision" and controller.get("state") == "complete" and controller.get("plan_hash") != typed["plan_hash"]:
        raise HTTPException(409, "PXE node is already provisioned; use the governed os.reimage operation")
    idempotent_complete = (
        controller.get("state") == "complete" and controller.get("plan_hash") == typed["plan_hash"]
        and controller.get("artifact_manifest_hash") == supply["manifest_hash"]
        and controller.get("callback_token_sha256") == desired["callback_token_sha256"]
    )
    observed_states = [str(controller.get("state") or "idle")]
    mutation_applied = not idempotent_complete
    if mutation_applied:
        _pxe_verify_artifact_files(supply)
        _pxe_prepare(typed, provider, credential, server, desired, supply)
        boot_provider = _pxe_boot_provider_target(typed, server)
        _pxe_set_one_time_boot_and_start(boot_provider, desired)
        _pxe_start(provider, credential, server, typed)
        controller, observed_states = _pxe_wait_complete(provider, credential, server, desired, supply, typed["plan_hash"])
    host_ready = _pxe_host_ready(server, desired["host_ready_timeout_seconds"])
    observed_at = int(time.time())
    checks = [
        {"id": "provider-state-drift", "status": "PASS", "summary": "PXE controller and boot-provider state matched the exact approved preview before execution", "evidence": {"provider_id": provider["id"], "before_hash": sha256_hex(current)}},
        {"id": "pxe-artifact-binding", "status": "PASS", "summary": "PXE execution consumed the exact READY mirrored artifact manifest", "evidence": {"manifest_hash": supply["manifest_hash"], "artifact_roles": sorted(supply["artifacts"])}},
        {"id": "pxe-callback-binding", "status": "PASS", "summary": "PXE completion callback matched the exact node, plan and callback-token hash", "evidence": {"node_id": server["id"], "plan_hash": typed["plan_hash"], "callback_token_sha256": desired["callback_token_sha256"]}},
        {"id": "pxe-state-machine", "status": "PASS", "summary": "PXE provisioning reached controller callback/complete through bounded typed states", "evidence": {"observed_states": observed_states, "final_state": controller.get("state")}},
        {"id": "pxe-host-readiness", "status": "PASS" if host_ready else "FAIL", "summary": "Post-install host readiness probe reached the registered management endpoint" if host_ready else "Post-install host readiness probe did not reach the registered management endpoint", "evidence": {"server_id": server["id"], "management_ip": server["management_ip"], "ssh_port": int(server.get("ssh_port") or 22)}},
    ]
    return {
        "state": "SUCCEEDED" if host_ready else "FAILED", "provider_kind": "pxe", "operation": typed["operation"], "typed_plan_hash": typed["plan_hash"],
        "verification": {
            "checks": checks,
            "evidence": {
                "provider_id": provider["id"], "provider_kind": "pxe", "operation": typed["operation"],
                "node_id": server["id"], "provisioning_nic": server["pxe_identity"]["nic"], "provisioning_mac": server["pxe_identity"]["mac"],
                "artifact_manifest_hash": supply["manifest_hash"], "callback_token_sha256": desired["callback_token_sha256"],
                "arbitrary_cli": False, "arbitrary_shell": False, "arbitrary_ipxe_script": False,
                "raw_credentials_returned": False, "mutation_applied": mutation_applied, "stdout_returned": False, "stderr_returned": False,
            },
            "observed_at": observed_at,
        },
    }

def _endpoint(provider: dict[str, Any]) -> str:
    raw = str(provider.get("endpoint") or "").rstrip("/")
    parsed = urlparse(raw)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise HTTPException(422, "infrastructure endpoint contains forbidden credential/query material")
    allowed_schemes = {"https"} | ({"http"} if ALLOW_HTTP else set())
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        raise HTTPException(422, "infrastructure endpoint must use an approved HTTP(S) origin")
    if parsed.path in {"", "/"}:
        return raw + "/redfish/v1"
    return raw


def _same_origin_url(base: str, reference: str) -> str:
    target = urljoin(base.rstrip("/") + "/", reference)
    base_p = urlparse(base)
    target_p = urlparse(target)
    if (target_p.scheme, target_p.hostname, target_p.port) != (base_p.scheme, base_p.hostname, base_p.port):
        raise HTTPException(502, "provider returned a cross-origin Redfish reference")
    if target_p.username is not None or target_p.password is not None or target_p.query or target_p.fragment:
        raise HTTPException(502, "provider returned an unsafe Redfish reference")
    return target


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _request_json(method: str, url: str, *, credential: dict[str, Any], body: dict[str, Any] | None = None) -> dict[str, Any]:
    auth = base64.b64encode(f"{credential['username']}:{credential['password']}".encode()).decode()
    headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
    payload = None
    if body is not None:
        payload = canonical_json(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if urlparse(url).scheme == "https":
        try:
            context = ssl.create_default_context(cafile=str(credential["ca_file"]) if credential.get("ca_file") else None)
        except (OSError, ssl.SSLError) as exc:
            raise HTTPException(503, "infrastructure credential CA bundle is invalid") from exc
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise HTTPException(502, "provider response exceeded the bounded JSON limit")
            if not data:
                return {}
            decoded = json.loads(data.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise HTTPException(502, f"provider redirect rejected with HTTP {exc.code}") from exc
        raise HTTPException(502, f"provider request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, f"provider request failed: {type(exc).__name__}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(502, "provider returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise HTTPException(502, "provider returned a non-object JSON response")
    return decoded


def _redfish_system(provider: dict[str, Any], credential: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    base = _endpoint(provider)
    root = _request_json("GET", base, credential=credential)
    systems_ref = root.get("Systems", {}).get("@odata.id") if isinstance(root.get("Systems"), dict) else None
    if not isinstance(systems_ref, str) or not systems_ref:
        raise HTTPException(502, "Redfish service root does not expose Systems")
    systems_url = _same_origin_url(base, systems_ref)
    systems = _request_json("GET", systems_url, credential=credential)
    members = systems.get("Members") or []
    if not isinstance(members, list) or not members:
        raise HTTPException(502, "Redfish Systems collection is empty")
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    requested_id = str(capabilities.get("system_id") or "")
    choices: list[str] = []
    for member in members:
        if isinstance(member, dict) and isinstance(member.get("@odata.id"), str):
            choices.append(member["@odata.id"])
    if requested_id:
        selected = next((item for item in choices if item.rstrip("/").split("/")[-1] == requested_id), None)
        if not selected:
            raise HTTPException(409, "configured Redfish system_id is not present")
    else:
        if len(choices) != 1:
            raise HTTPException(409, "Redfish provider exposes multiple systems; configure capabilities.system_id")
        selected = choices[0]
    system_url = _same_origin_url(base, selected)
    return system_url, _request_json("GET", system_url, credential=credential)


def _redfish_manager(provider: dict[str, Any], credential: dict[str, Any], system_url: str, system: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    links = system.get("Links") if isinstance(system.get("Links"), dict) else {}
    managed_by = links.get("ManagedBy") or []
    if not isinstance(managed_by, list) or not managed_by:
        raise HTTPException(502, "Redfish system does not expose a managing Manager")
    choices = [
        item.get("@odata.id") for item in managed_by
        if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)
    ]
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    requested_id = str(capabilities.get("manager_id") or "")
    if requested_id:
        selected = next((item for item in choices if item.rstrip("/").split("/")[-1] == requested_id), None)
        if not selected:
            raise HTTPException(409, "configured Redfish manager_id is not present")
    else:
        if len(choices) != 1:
            raise HTTPException(409, "Redfish system exposes multiple managers; configure capabilities.manager_id")
        selected = choices[0]
    manager_url = _same_origin_url(system_url, selected)
    return manager_url, _request_json("GET", manager_url, credential=credential)


def _redfish_virtual_media(
    provider: dict[str, Any], credential: dict[str, Any], system_url: str, system: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    manager_url, manager = _redfish_manager(provider, credential, system_url, system)
    media_ref = manager.get("VirtualMedia", {}).get("@odata.id") if isinstance(manager.get("VirtualMedia"), dict) else None
    if not isinstance(media_ref, str) or not media_ref:
        raise HTTPException(502, "Redfish manager does not expose VirtualMedia")
    collection_url = _same_origin_url(manager_url, media_ref)
    collection = _request_json("GET", collection_url, credential=credential)
    members = collection.get("Members") or []
    if not isinstance(members, list) or not members:
        raise HTTPException(502, "Redfish VirtualMedia collection is empty")
    choices = [
        item.get("@odata.id") for item in members
        if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)
    ]
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    requested_id = str(capabilities.get("virtual_media_id") or "")
    if requested_id:
        selected = next((item for item in choices if item.rstrip("/").split("/")[-1] == requested_id), None)
        if not selected:
            raise HTTPException(409, "configured Redfish virtual_media_id is not present")
    else:
        if len(choices) != 1:
            raise HTTPException(409, "Redfish manager exposes multiple virtual media devices; configure capabilities.virtual_media_id")
        selected = choices[0]
    media_url = _same_origin_url(collection_url, selected)
    return media_url, _request_json("GET", media_url, credential=credential)


def _redfish_bios_resources(
    provider: dict[str, Any], credential: dict[str, Any], system_url: str, system: dict[str, Any]
) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
    bios_ref = system.get("Bios", {}).get("@odata.id") if isinstance(system.get("Bios"), dict) else None
    if not isinstance(bios_ref, str) or not bios_ref:
        raise HTTPException(502, "Redfish system does not expose Bios")
    bios_url = _same_origin_url(system_url, bios_ref)
    bios = _request_json("GET", bios_url, credential=credential)
    redfish_settings = bios.get("@Redfish.Settings") if isinstance(bios.get("@Redfish.Settings"), dict) else {}
    settings_object = redfish_settings.get("SettingsObject") if isinstance(redfish_settings.get("SettingsObject"), dict) else {}
    settings_ref = settings_object.get("@odata.id")
    if isinstance(settings_ref, str) and settings_ref:
        settings_url = _same_origin_url(bios_url, settings_ref)
        settings = _request_json("GET", settings_url, credential=credential)
        return bios_url, bios, settings_url, settings
    return bios_url, bios, bios_url, bios


def _redfish_bios(
    provider: dict[str, Any], credential: dict[str, Any], system_url: str, system: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    _, _, settings_url, settings = _redfish_bios_resources(provider, credential, system_url, system)
    return settings_url, settings


def _redfish_secure_boot(system_url: str, system: dict[str, Any], credential: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    secure_ref = system.get("SecureBoot", {}).get("@odata.id") if isinstance(system.get("SecureBoot"), dict) else None
    if not isinstance(secure_ref, str) or not secure_ref:
        raise HTTPException(502, "Redfish system does not expose SecureBoot")
    secure_url = _same_origin_url(system_url, secure_ref)
    secure = _request_json("GET", secure_url, credential=credential)
    if not isinstance(secure.get("SecureBootEnable"), bool):
        raise HTTPException(502, "Redfish SecureBoot resource does not expose boolean SecureBootEnable")
    return secure_url, secure


def _redfish_system_settings_url(system_url: str, system: dict[str, Any]) -> str:
    redfish_settings = system.get("@Redfish.Settings") if isinstance(system.get("@Redfish.Settings"), dict) else {}
    settings_object = redfish_settings.get("SettingsObject") if isinstance(redfish_settings.get("SettingsObject"), dict) else {}
    settings_ref = settings_object.get("@odata.id")
    if isinstance(settings_ref, str) and settings_ref:
        return _same_origin_url(system_url, settings_ref)
    return system_url


def _redfish_boot_options(system_url: str, system: dict[str, Any], credential: dict[str, Any]) -> list[dict[str, Any]]:
    boot = system.get("Boot") if isinstance(system.get("Boot"), dict) else {}
    selection = str(boot.get("BootOrderPropertySelection") or "")
    if selection and selection != "BootOrder":
        raise HTTPException(409, f"Redfish system uses unsupported persistent boot-order property {selection!r}")
    order = boot.get("BootOrder")
    if not isinstance(order, list):
        raise HTTPException(502, "Redfish system does not expose Boot.BootOrder")
    if any(not isinstance(item, str) or not BOOT_ORDER_REF_RE.fullmatch(item) for item in order):
        raise HTTPException(502, "Redfish system returned unsafe BootOrder references")
    boot_options = boot.get("BootOptions") if isinstance(boot.get("BootOptions"), dict) else {}
    collection_ref = boot_options.get("@odata.id")
    if not isinstance(collection_ref, str) or not collection_ref:
        raise HTTPException(502, "Redfish system does not expose Boot.BootOptions")
    collection_url = _same_origin_url(system_url, collection_ref)
    collection = _request_json("GET", collection_url, credential=credential)
    members = collection.get("Members") or []
    if not isinstance(members, list) or not members or len(members) > 128:
        raise HTTPException(502, "Redfish BootOptions collection is empty or unbounded")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for member in members:
        ref = member.get("@odata.id") if isinstance(member, dict) else None
        if not isinstance(ref, str) or not ref:
            raise HTTPException(502, "Redfish BootOptions collection contains an invalid member")
        option_url = _same_origin_url(collection_url, ref)
        option = _request_json("GET", option_url, credential=credential)
        option_ref = str(option.get("BootOptionReference") or "")
        if not BOOT_ORDER_REF_RE.fullmatch(option_ref) or option_ref in seen:
            raise HTTPException(502, "Redfish BootOptions contain unsafe or duplicate BootOptionReference values")
        seen.add(option_ref)
        enabled = option.get("BootOptionEnabled")
        if not isinstance(enabled, bool):
            raise HTTPException(502, "Redfish BootOption does not expose boolean BootOptionEnabled")
        result.append({
            "reference": option_ref,
            "enabled": enabled,
            "display_name": str(option.get("DisplayName") or option.get("Name") or "")[:240],
        })
    return sorted(result, key=lambda item: item["reference"])


def _require_platform_activation_ready(system: dict[str, Any], activation: str) -> None:
    if activation == "reboot" and str(system.get("PowerState") or "").lower() != "on":
        raise HTTPException(409, "Redfish reboot-activated platform mutation requires the system to be powered on")


def _redfish_reset(system_url: str, system: dict[str, Any], credential: dict[str, Any], reset_type: str) -> None:
    if reset_type not in PLATFORM_RESET_TYPES:
        raise HTTPException(422, "unsupported Redfish platform reset type")
    actions = system.get("Actions") if isinstance(system.get("Actions"), dict) else {}
    reset = actions.get("#ComputerSystem.Reset") if isinstance(actions.get("#ComputerSystem.Reset"), dict) else {}
    target = reset.get("target")
    if not isinstance(target, str) or not target:
        raise HTTPException(502, "Redfish system does not expose ComputerSystem.Reset action")
    _request_json("POST", _same_origin_url(system_url, target), credential=credential, body={"ResetType": reset_type})


def _redfish_firmware(
    provider: dict[str, Any], credential: dict[str, Any], component_id: str
) -> tuple[str, str, dict[str, Any]]:
    base = _endpoint(provider)
    root = _request_json("GET", base, credential=credential)
    update_ref = root.get("UpdateService", {}).get("@odata.id") if isinstance(root.get("UpdateService"), dict) else None
    if not isinstance(update_ref, str) or not update_ref:
        raise HTTPException(502, "Redfish service root does not expose UpdateService")
    update_url = _same_origin_url(base, update_ref)
    update = _request_json("GET", update_url, credential=credential)
    if update.get("ServiceEnabled") is False:
        raise HTTPException(409, "Redfish UpdateService is disabled")
    actions = update.get("Actions") if isinstance(update.get("Actions"), dict) else {}
    simple = actions.get("#UpdateService.SimpleUpdate") if isinstance(actions.get("#UpdateService.SimpleUpdate"), dict) else {}
    action_ref = simple.get("target")
    if not isinstance(action_ref, str) or not action_ref:
        raise HTTPException(502, "Redfish UpdateService does not expose SimpleUpdate")
    action_url = _same_origin_url(update_url, action_ref)
    inventory_ref = update.get("FirmwareInventory", {}).get("@odata.id") if isinstance(update.get("FirmwareInventory"), dict) else None
    if not isinstance(inventory_ref, str) or not inventory_ref:
        raise HTTPException(502, "Redfish UpdateService does not expose FirmwareInventory")
    inventory_url = _same_origin_url(update_url, inventory_ref)
    inventory = _request_json("GET", inventory_url, credential=credential)
    members = inventory.get("Members") or []
    if not isinstance(members, list) or not members:
        raise HTTPException(502, "Redfish FirmwareInventory collection is empty")
    matches = [
        item.get("@odata.id") for item in members
        if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)
        and item["@odata.id"].rstrip("/").split("/")[-1] == component_id
    ]
    if not matches:
        raise HTTPException(409, "configured Redfish firmware component_id is not present")
    if len(matches) != 1:
        raise HTTPException(502, "Redfish FirmwareInventory contains duplicate component identifiers")
    component_url = _same_origin_url(inventory_url, matches[0])
    component = _request_json("GET", component_url, credential=credential)
    if str(component.get("Id") or "") not in {"", component_id}:
        raise HTTPException(502, "Redfish firmware component Id does not match its inventory reference")
    if component.get("Updateable") is False:
        raise HTTPException(409, "Redfish firmware component is not updateable")
    return action_url, component_url, component


def _safe_firmware_snapshot(component: dict[str, Any]) -> dict[str, Any]:
    status = component.get("Status") if isinstance(component.get("Status"), dict) else {}
    return {
        "resource_id": str(component.get("Id") or "")[:160],
        "name": str(component.get("Name") or "")[:240],
        "software_id": str(component.get("SoftwareId") or "")[:160],
        "version": str(component.get("Version") or "")[:160],
        "updateable": bool(component.get("Updateable")) if "Updateable" in component else None,
        "health": str(status.get("Health") or "")[:80],
        "state": str(status.get("State") or "")[:80],
    }


def _redfish_storage_member_urls(base_url: str, collection: dict[str, Any], *, label: str, limit: int = 64) -> list[str]:
    members = collection.get("Members") or []
    if not isinstance(members, list):
        raise HTTPException(502, f"Redfish {label} collection has invalid Members")
    if len(members) > limit:
        raise HTTPException(502, f"Redfish {label} collection exceeds bounded member limit")
    urls: list[str] = []
    for item in members:
        ref = item.get("@odata.id") if isinstance(item, dict) else None
        if not isinstance(ref, str) or not ref:
            raise HTTPException(502, f"Redfish {label} collection contains an invalid member reference")
        urls.append(_same_origin_url(base_url, ref))
    return urls


def _safe_drive_snapshot(drive: dict[str, Any]) -> dict[str, Any]:
    status = drive.get("Status") if isinstance(drive.get("Status"), dict) else {}
    capacity = drive.get("CapacityBytes")
    return {
        "id": str(drive.get("Id") or "")[:160],
        "name": str(drive.get("Name") or "")[:240],
        "serial_number": str(drive.get("SerialNumber") or "")[:160],
        "part_number": str(drive.get("PartNumber") or "")[:160],
        "model": str(drive.get("Model") or "")[:160],
        "media_type": str(drive.get("MediaType") or "")[:80],
        "protocol": str(drive.get("Protocol") or "")[:80],
        "capacity_bytes": int(capacity) if isinstance(capacity, int) and not isinstance(capacity, bool) and capacity >= 0 else None,
        "health": str(status.get("Health") or "")[:80],
        "state": str(status.get("State") or "")[:80],
    }


def _safe_volume_snapshot(volume: dict[str, Any]) -> dict[str, Any]:
    status = volume.get("Status") if isinstance(volume.get("Status"), dict) else {}
    links = volume.get("Links") if isinstance(volume.get("Links"), dict) else {}
    raw_drives = links.get("Drives") or []
    drive_ids: list[str] = []
    if isinstance(raw_drives, list):
        for item in raw_drives[:64]:
            ref = item.get("@odata.id") if isinstance(item, dict) else None
            if isinstance(ref, str) and ref:
                drive_ids.append(ref.rstrip("/").split("/")[-1][:160])
    capacity = volume.get("CapacityBytes")
    return {
        "id": str(volume.get("Id") or "")[:160],
        "name": str(volume.get("Name") or "")[:240],
        "raid_type": str(volume.get("RAIDType") or "")[:80],
        "capacity_bytes": int(capacity) if isinstance(capacity, int) and not isinstance(capacity, bool) and capacity >= 0 else None,
        "drive_ids": sorted(set(drive_ids)),
        "health": str(status.get("Health") or "")[:80],
        "state": str(status.get("State") or "")[:80],
    }


def _storage_request_allowed(provider: dict[str, Any], desired: dict[str, Any], operation: str) -> None:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    raw = capabilities.get("storage_controller_allowlist")
    if not isinstance(raw, dict) or not raw or len(raw) > 32:
        raise HTTPException(422, "Redfish storage runtime requires capabilities.storage_controller_allowlist")
    if any(not STORAGE_ID_RE.fullmatch(str(key)) for key in raw):
        raise HTTPException(422, "Redfish storage controller allowlist contains unsafe controller IDs")
    policy = raw.get(desired["controller_id"])
    if not isinstance(policy, dict):
        raise HTTPException(422, "Redfish storage controller is not allowlisted by provider capabilities")
    allowed_fields = {"drive_ids", "raid_types", "volume_names", "allow_volume_delete"}
    if set(policy) - allowed_fields:
        raise HTTPException(422, "Redfish storage controller allowlist contains unsupported policy fields")
    if operation == "storage.volume.delete":
        if policy.get("allow_volume_delete") is not True:
            raise HTTPException(422, "Redfish storage volume deletion is disabled by provider capabilities")
        return
    raw_drives = policy.get("drive_ids")
    raw_raid = policy.get("raid_types")
    raw_names = policy.get("volume_names")
    if not isinstance(raw_drives, list) or not raw_drives or len(raw_drives) > 128:
        raise HTTPException(422, "Redfish storage drive allowlist is missing or invalid")
    if not isinstance(raw_raid, list) or not raw_raid or len(raw_raid) > len(RAID_TYPES):
        raise HTTPException(422, "Redfish storage RAID allowlist is missing or invalid")
    if not isinstance(raw_names, list) or not raw_names or len(raw_names) > 128:
        raise HTTPException(422, "Redfish storage volume-name allowlist is missing or invalid")
    allowed_drives = {str(item) for item in raw_drives if STORAGE_ID_RE.fullmatch(str(item))}
    allowed_raid = {str(item).upper() for item in raw_raid if str(item).upper() in RAID_TYPES}
    allowed_names = {str(item) for item in raw_names if VOLUME_NAME_RE.fullmatch(str(item))}
    if len(allowed_drives) != len(raw_drives) or len(allowed_raid) != len(raw_raid) or len(allowed_names) != len(raw_names):
        raise HTTPException(422, "Redfish storage controller allowlist contains unsafe entries")
    denied = sorted(set(desired["drive_ids"]) - allowed_drives)
    if denied:
        raise HTTPException(422, "Redfish storage drive is not allowlisted: " + ", ".join(denied))
    if desired["raid_type"] not in allowed_raid:
        raise HTTPException(422, "Redfish RAID type is not allowlisted by provider capabilities")
    if desired["volume_name"] not in allowed_names:
        raise HTTPException(422, "Redfish storage volume name is not allowlisted by provider capabilities")


def _redfish_storage(
    provider: dict[str, Any], credential: dict[str, Any], system_url: str, system: dict[str, Any], desired: dict[str, Any], operation: str
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    storage_ref = system.get("Storage", {}).get("@odata.id") if isinstance(system.get("Storage"), dict) else None
    if not isinstance(storage_ref, str) or not storage_ref:
        raise HTTPException(502, "Redfish system does not expose Storage")
    storage_collection_url = _same_origin_url(system_url, storage_ref)
    storage_collection = _request_json("GET", storage_collection_url, credential=credential)
    controller_urls = _redfish_storage_member_urls(storage_collection_url, storage_collection, label="Storage")
    requested_controller = desired["controller_id"]
    matches = [url for url in controller_urls if url.rstrip("/").split("/")[-1] == requested_controller]
    if not matches:
        raise HTTPException(409, "configured Redfish storage controller_id is not present")
    if len(matches) != 1:
        raise HTTPException(502, "Redfish Storage collection contains duplicate controller identifiers")
    controller_url = matches[0]
    controller = _request_json("GET", controller_url, credential=credential)
    if str(controller.get("Id") or "") not in {"", requested_controller}:
        raise HTTPException(502, "Redfish storage controller Id does not match its collection reference")

    raw_drive_refs = controller.get("Drives") or []
    if not isinstance(raw_drive_refs, list) or len(raw_drive_refs) > 128:
        raise HTTPException(502, "Redfish storage controller has invalid or excessive drive references")
    drive_urls: dict[str, str] = {}
    drive_snapshots: list[dict[str, Any]] = []
    for item in raw_drive_refs:
        ref = item.get("@odata.id") if isinstance(item, dict) else None
        if not isinstance(ref, str) or not ref:
            raise HTTPException(502, "Redfish storage controller contains an invalid drive reference")
        drive_url = _same_origin_url(controller_url, ref)
        drive = _request_json("GET", drive_url, credential=credential)
        drive_id = str(drive.get("Id") or drive_url.rstrip("/").split("/")[-1])
        if not STORAGE_ID_RE.fullmatch(drive_id) or drive_id in drive_urls:
            raise HTTPException(502, "Redfish physical drive identity is missing, unsafe or duplicated")
        drive_urls[drive_id] = drive_url
        snap = _safe_drive_snapshot({**drive, "Id": drive_id})
        drive_snapshots.append(snap)

    volumes_ref = controller.get("Volumes", {}).get("@odata.id") if isinstance(controller.get("Volumes"), dict) else None
    if not isinstance(volumes_ref, str) or not volumes_ref:
        raise HTTPException(502, "Redfish storage controller does not expose Volumes")
    volumes_url = _same_origin_url(controller_url, volumes_ref)
    volume_collection = _request_json("GET", volumes_url, credential=credential)
    volume_urls: dict[str, str] = {}
    volume_snapshots: list[dict[str, Any]] = []
    for volume_url in _redfish_storage_member_urls(volumes_url, volume_collection, label="Volumes"):
        volume = _request_json("GET", volume_url, credential=credential)
        volume_id = str(volume.get("Id") or volume_url.rstrip("/").split("/")[-1])
        if not STORAGE_ID_RE.fullmatch(volume_id) or volume_id in volume_urls:
            raise HTTPException(502, "Redfish volume identity is missing, unsafe or duplicated")
        volume_urls[volume_id] = volume_url
        volume_snapshots.append(_safe_volume_snapshot({**volume, "Id": volume_id}))

    current = {
        "controller_id": requested_controller,
        "controller_name": str(controller.get("Name") or "")[:240],
        "drives": sorted(drive_snapshots, key=lambda item: item["id"]),
        "volumes": sorted(volume_snapshots, key=lambda item: item["id"]),
    }
    resource = {"volumes_url": volumes_url, "drive_urls": drive_urls, "volume_urls": volume_urls}

    if operation == "storage.volume.apply":
        snapshots = {item["id"]: item for item in current["drives"]}
        missing = sorted(set(desired["drive_ids"]) - set(snapshots))
        if missing:
            raise HTTPException(409, "Redfish requested physical drive is not present: " + ", ".join(missing))
        desired_serials: list[str] = []
        for drive_id in desired["drive_ids"]:
            drive = snapshots[drive_id]
            serial_number = str(drive.get("serial_number") or "")
            if not serial_number:
                raise HTTPException(409, f"Redfish physical drive {drive_id} has no stable SerialNumber; refusing ambiguous RAID mutation")
            desired_serials.append(serial_number)
            if str(drive.get("health") or "OK") not in {"OK", ""} or str(drive.get("state") or "Enabled") not in {"Enabled", ""}:
                raise HTTPException(409, f"Redfish physical drive {drive_id} is not healthy/available for RAID mutation")
        if len(set(desired_serials)) != len(desired_serials):
            raise HTTPException(409, "Redfish requested physical drives do not have unique stable SerialNumber identities")
        same_name = [item for item in current["volumes"] if item.get("name") == desired["volume_name"]]
        if len(same_name) > 1:
            raise HTTPException(409, "Redfish storage contains duplicate volume names; refusing ambiguous desired-state mutation")
        exact_existing_id = ""
        if same_name:
            item = same_name[0]
            exact = item.get("raid_type") == desired["raid_type"] and sorted(item.get("drive_ids") or []) == desired["drive_ids"]
            if not exact:
                raise HTTPException(409, "Redfish volume name already exists with different RAID/drives; delete it through a separate destructive ChangeSet first")
            exact_existing_id = str(item.get("id") or "")
        desired_drive_set = set(desired["drive_ids"])
        conflicting = [
            str(item.get("id") or item.get("name") or "unknown")
            for item in current["volumes"]
            if str(item.get("id") or "") != exact_existing_id and desired_drive_set.intersection(set(item.get("drive_ids") or []))
        ]
        if conflicting:
            raise HTTPException(409, "Redfish requested physical drive is already bound to another volume: " + ", ".join(sorted(conflicting)))
    return volumes_url, resource, current


def _safe_bios_snapshot(bios: dict[str, Any], desired_attributes: dict[str, Any]) -> dict[str, Any]:
    attributes = bios.get("Attributes") if isinstance(bios.get("Attributes"), dict) else {}
    observed: dict[str, Any] = {}
    for name in sorted(desired_attributes):
        value = attributes.get(name)
        if isinstance(value, (str, int, bool)) or value is None:
            observed[name] = value
        else:
            observed[name] = None
    return {
        "resource_id": str(bios.get("Id") or "")[:160],
        "name": str(bios.get("Name") or "")[:240],
        "attributes": observed,
        "attribute_count": len(observed),
    }


def _safe_virtual_media_snapshot(media: dict[str, Any]) -> dict[str, Any]:
    raw_image = str(media.get("Image") or "")
    safe_image = ""
    if raw_image:
        parsed = urlparse(raw_image)
        if parsed.scheme in {"https", "http"} and parsed.hostname and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment:
            safe_image = raw_image[:1000]
    media_types = media.get("MediaTypes") or []
    if not isinstance(media_types, list):
        media_types = []
    return {
        "resource_id": str(media.get("Id") or "")[:160],
        "name": str(media.get("Name") or "")[:240],
        "inserted": bool(media.get("Inserted")),
        "write_protected": bool(media.get("WriteProtected")),
        "image_present": bool(raw_image),
        "image_url": safe_image,
        "image_sha256": hashlib.sha256(raw_image.encode()).hexdigest() if raw_image else "",
        "media_types": [str(item)[:80] for item in media_types[:16]],
        "connected_via": str(media.get("ConnectedVia") or "")[:80],
    }


def _bios_attributes_allowed(provider: dict[str, Any], desired_attributes: dict[str, Any]) -> None:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    raw_names = capabilities.get("bios_attribute_allowlist") or []
    if not isinstance(raw_names, list) or not raw_names or len(raw_names) > 128:
        raise HTTPException(422, "Redfish bios.apply requires capabilities.bios_attribute_allowlist")
    allowed = {str(item) for item in raw_names if BIOS_ATTRIBUTE_RE.fullmatch(str(item))}
    if len(allowed) != len(raw_names):
        raise HTTPException(422, "Redfish BIOS attribute allowlist contains unsafe entries")
    denied = sorted(set(desired_attributes) - allowed)
    if denied:
        raise HTTPException(422, "Redfish BIOS attribute is not allowlisted by provider capabilities: " + ", ".join(denied))


def _firmware_request_allowed(provider: dict[str, Any], desired: dict[str, Any]) -> None:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    raw_hosts = capabilities.get("firmware_image_hosts") or []
    if not isinstance(raw_hosts, list) or not raw_hosts or len(raw_hosts) > 64:
        raise HTTPException(422, "Redfish firmware.apply requires capabilities.firmware_image_hosts")
    allowed_hosts = {str(item).strip().lower() for item in raw_hosts if str(item).strip()}
    if len(allowed_hosts) != len(raw_hosts):
        raise HTTPException(422, "Redfish firmware image host allowlist contains invalid entries")
    image_host = str(urlparse(desired["image_url"]).hostname or "").lower()
    if image_host not in allowed_hosts:
        raise HTTPException(422, "Redfish firmware image host is not allowlisted by provider capabilities")

    raw_components = capabilities.get("firmware_component_allowlist") or []
    if not isinstance(raw_components, list) or not raw_components or len(raw_components) > 128:
        raise HTTPException(422, "Redfish firmware.apply requires capabilities.firmware_component_allowlist")
    allowed_components = {str(item) for item in raw_components if FIRMWARE_COMPONENT_RE.fullmatch(str(item))}
    if len(allowed_components) != len(raw_components):
        raise HTTPException(422, "Redfish firmware component allowlist contains unsafe entries")
    if desired["component_id"] not in allowed_components:
        raise HTTPException(422, "Redfish firmware component is not allowlisted by provider capabilities")


def _virtual_media_image_allowed(provider: dict[str, Any], image_url: str) -> None:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    raw_hosts = capabilities.get("virtual_media_image_hosts") or []
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise HTTPException(422, "Redfish virtual media requires capabilities.virtual_media_image_hosts allowlist")
    allowed = {str(item).strip().lower() for item in raw_hosts if str(item).strip()}
    host = str(urlparse(image_url).hostname or "").lower()
    if not host or host not in allowed:
        raise HTTPException(422, "Redfish virtual media image host is not allowlisted by provider capabilities")


def _secure_boot_policy(provider: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    policy = capabilities.get("secure_boot")
    if not isinstance(policy, dict) or set(policy) - {"activation", "reset_type"}:
        raise HTTPException(422, "Redfish secure boot requires a bounded capabilities.secure_boot policy")
    activation = str(policy.get("activation") or "").lower()
    if activation != "reboot" or desired.get("activation") != "reboot":
        raise HTTPException(422, "Redfish secure boot activation must be reboot in both intent and provider capability")
    reset_type = str(policy.get("reset_type") or "")
    if reset_type not in PLATFORM_RESET_TYPES:
        raise HTTPException(422, "Redfish secure boot requires a fixed supported reset_type")
    return {"activation": activation, "reset_type": reset_type}


def _hardware_feature_policy(provider: dict[str, Any], operation: str, desired: dict[str, Any]) -> dict[str, Any]:
    feature = operation.split(".", 1)[0]
    if feature not in PLATFORM_FEATURES:
        raise HTTPException(422, "unsupported Redfish platform feature")
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    feature_map = capabilities.get("hardware_feature_map")
    if not isinstance(feature_map, dict):
        raise HTTPException(422, "Redfish platform feature runtime requires capabilities.hardware_feature_map")
    policy = feature_map.get(feature)
    allowed_keys = {"attribute", "enabled_value", "disabled_value", "activation", "reset_type"}
    if not isinstance(policy, dict) or set(policy) - allowed_keys:
        raise HTTPException(422, f"Redfish {feature} capability mapping is missing or contains unsupported fields")
    attribute = str(policy.get("attribute") or "")
    if not BIOS_ATTRIBUTE_RE.fullmatch(attribute):
        raise HTTPException(422, f"Redfish {feature} capability attribute is unsafe")
    raw_allowlist = capabilities.get("bios_attribute_allowlist")
    if not isinstance(raw_allowlist, list) or attribute not in {str(item) for item in raw_allowlist}:
        raise HTTPException(422, f"Redfish {feature} capability attribute must also be BIOS-allowlisted")
    for key in ("enabled_value", "disabled_value"):
        value = policy.get(key)
        if not isinstance(value, (str, int, bool)) or (isinstance(value, str) and (not value or len(value) > 256 or any(ord(ch) < 32 for ch in value))):
            raise HTTPException(422, f"Redfish {feature} capability {key} must be a bounded scalar")
    if policy.get("enabled_value") == policy.get("disabled_value"):
        raise HTTPException(422, f"Redfish {feature} enabled and disabled capability values must differ")
    activation = str(policy.get("activation") or "").lower()
    if activation not in PLATFORM_ACTIVATIONS or desired.get("activation") != activation:
        raise HTTPException(422, f"Redfish {feature} desired activation does not match provider capability")
    reset_type = str(policy.get("reset_type") or "")
    if activation == "reboot" and reset_type not in PLATFORM_RESET_TYPES:
        raise HTTPException(422, f"Redfish {feature} reboot activation requires a fixed supported reset_type")
    if activation == "immediate" and reset_type:
        raise HTTPException(422, f"Redfish {feature} immediate activation must not configure reset_type")
    target_value = policy["enabled_value"] if desired["enabled"] else policy["disabled_value"]
    return {
        "feature": feature, "attribute": attribute, "target_value": target_value,
        "enabled_value": policy["enabled_value"], "disabled_value": policy["disabled_value"],
        "activation": activation, "reset_type": reset_type,
    }


def _boot_order_policy(provider: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    capabilities = provider.get("capabilities") if isinstance(provider.get("capabilities"), dict) else {}
    policy = capabilities.get("boot_order")
    allowed_keys = {"allowlist", "activation", "reset_type"}
    if not isinstance(policy, dict) or set(policy) - allowed_keys:
        raise HTTPException(422, "Redfish boot-order runtime requires a bounded capabilities.boot_order policy")
    raw_allowlist = policy.get("allowlist")
    if not isinstance(raw_allowlist, list) or not raw_allowlist or len(raw_allowlist) > 64:
        raise HTTPException(422, "Redfish boot-order runtime requires a non-empty exact allowlist")
    allowed = [str(item) for item in raw_allowlist]
    if any(not BOOT_ORDER_REF_RE.fullmatch(item) for item in allowed) or len(set(allowed)) != len(allowed):
        raise HTTPException(422, "Redfish boot-order allowlist contains unsafe or duplicate references")
    denied = [item for item in desired["order"] if item not in set(allowed)]
    if denied:
        raise HTTPException(422, "Redfish boot option is not allowlisted by provider capabilities: " + ", ".join(denied))
    activation = str(policy.get("activation") or "").lower()
    if activation not in PLATFORM_ACTIVATIONS or desired.get("activation") != activation:
        raise HTTPException(422, "Redfish boot-order desired activation does not match provider capability")
    reset_type = str(policy.get("reset_type") or "")
    if activation == "reboot" and reset_type not in PLATFORM_RESET_TYPES:
        raise HTTPException(422, "Redfish boot-order reboot activation requires a fixed supported reset_type")
    if activation == "immediate" and reset_type:
        raise HTTPException(422, "Redfish boot-order immediate activation must not configure reset_type")
    return {"allowlist": allowed, "activation": activation, "reset_type": reset_type}


def _safe_secure_boot_snapshot(system: dict[str, Any], secure: dict[str, Any]) -> dict[str, Any]:
    enabled = secure.get("SecureBootEnable")
    current_boot = str(secure.get("SecureBootCurrentBoot") or "")
    if not isinstance(enabled, bool):
        raise HTTPException(502, "Redfish SecureBootEnable is not boolean")
    if current_boot not in {"Enabled", "Disabled"}:
        raise HTTPException(409, "Redfish SecureBootCurrentBoot is unavailable or unsupported for active verification")
    return {
        "enabled": enabled,
        "active_enabled": current_boot == "Enabled",
        "mode": str(secure.get("SecureBootMode") or "")[:80],
        "current_boot": current_boot,
        "last_reset_time": str(system.get("LastResetTime") or "")[:120],
        "boot_progress_time": str((system.get("BootProgress") or {}).get("LastStateTime") or "")[:120] if isinstance(system.get("BootProgress"), dict) else "",
    }


def _safe_feature_snapshot(
    system: dict[str, Any], active_bios: dict[str, Any], settings_bios: dict[str, Any],
    attribute: str, enabled_value: Any, disabled_value: Any,
) -> dict[str, Any]:
    active_attributes = active_bios.get("Attributes") if isinstance(active_bios.get("Attributes"), dict) else {}
    pending_attributes = settings_bios.get("Attributes") if isinstance(settings_bios.get("Attributes"), dict) else {}
    active_value = active_attributes.get(attribute)
    pending_value = pending_attributes.get(attribute)
    if active_value not in {enabled_value, disabled_value}:
        raise HTTPException(409, f"Redfish BIOS attribute {attribute} has an unmapped active value")
    if pending_value is not None and pending_value not in {enabled_value, disabled_value}:
        raise HTTPException(409, f"Redfish BIOS attribute {attribute} has an unmapped pending value")
    return {
        "attribute": attribute,
        "active_value": active_value,
        "pending_value": pending_value,
        "enabled": active_value == enabled_value,
        "pending_enabled": None if pending_value is None else pending_value == enabled_value,
        "last_reset_time": str(system.get("LastResetTime") or "")[:120],
        "boot_progress_time": str((system.get("BootProgress") or {}).get("LastStateTime") or "")[:120] if isinstance(system.get("BootProgress"), dict) else "",
    }


def _safe_boot_order_snapshot(system: dict[str, Any], options: list[dict[str, Any]]) -> dict[str, Any]:
    boot = system.get("Boot") if isinstance(system.get("Boot"), dict) else {}
    order = boot.get("BootOrder") if isinstance(boot.get("BootOrder"), list) else []
    return {
        "order": [str(item) for item in order],
        "order_property_selection": str(boot.get("BootOrderPropertySelection") or "BootOrder")[:80],
        "options": options,
        "last_reset_time": str(system.get("LastResetTime") or "")[:120],
        "boot_progress_time": str((system.get("BootProgress") or {}).get("LastStateTime") or "")[:120] if isinstance(system.get("BootProgress"), dict) else "",
    }


def _safe_system_snapshot(system: dict[str, Any]) -> dict[str, Any]:
    status = system.get("Status") if isinstance(system.get("Status"), dict) else {}
    boot = system.get("Boot") if isinstance(system.get("Boot"), dict) else {}
    return {
        "resource_id": str(system.get("Id") or "")[:160],
        "name": str(system.get("Name") or "")[:240],
        "manufacturer": str(system.get("Manufacturer") or "")[:160],
        "model": str(system.get("Model") or "")[:160],
        "serial_number": str(system.get("SerialNumber") or "")[:160],
        "power_state": str(system.get("PowerState") or "")[:80],
        "last_reset_time": str(system.get("LastResetTime") or "")[:120],
        "boot_progress": str((system.get("BootProgress") or {}).get("LastState") or "")[:120] if isinstance(system.get("BootProgress"), dict) else "",
        "boot_progress_time": str((system.get("BootProgress") or {}).get("LastStateTime") or "")[:120] if isinstance(system.get("BootProgress"), dict) else "",
        "health": str(status.get("Health") or "")[:80],
        "state": str(status.get("State") or "")[:80],
        "boot_target": str(boot.get("BootSourceOverrideTarget") or "")[:80],
        "boot_enabled": str(boot.get("BootSourceOverrideEnabled") or "")[:80],
        "boot_mode": str(boot.get("BootSourceOverrideMode") or "")[:80],
    }


def _desired_diff(operation: str, current: dict[str, Any], desired: dict[str, Any]) -> list[dict[str, Any]]:
    if operation == "inventory.refresh":
        return []
    if operation == "power.set":
        desired_state = desired["state"]
        normalized_current = str(current.get("power_state") or "").lower()
        target_current = {"on": "on", "force-off": "off", "graceful-shutdown": "off"}.get(desired_state)
        return [] if target_current and normalized_current == target_current else [{"field": "power_state", "from": current.get("power_state"), "to": desired_state}]
    if operation == "virtual-media.eject":
        return [] if not current.get("inserted") and not current.get("image_present") else [{"field": "virtual_media", "from": "inserted", "to": "ejected"}]
    if operation == "secure-boot.apply":
        if current.get("enabled") is desired["enabled"] and current.get("active_enabled") is desired["enabled"]:
            return []
        return [{
            "field": "secure_boot.enabled",
            "from": {"next_boot": current.get("enabled"), "active": current.get("active_enabled")},
            "to": {"next_boot": desired["enabled"], "active_after_reboot": desired["enabled"]},
            "activation": desired["activation"],
        }]
    if operation in {"sriov.apply", "iommu.apply"}:
        feature = operation.split(".", 1)[0]
        return [] if current.get("enabled") is desired["enabled"] else [{
            "field": f"platform.{feature}.enabled", "from": current.get("enabled"), "to": desired["enabled"],
            "activation": desired["activation"],
        }]
    if operation == "boot-order.apply":
        return [] if current.get("order") == desired["order"] else [{
            "field": "boot.order", "from": current.get("order") or [], "to": desired["order"],
            "activation": desired["activation"],
        }]
    if operation == "bios.apply":
        current_attributes = current.get("attributes") if isinstance(current.get("attributes"), dict) else {}
        return [
            {"field": f"bios.{name}", "from": current_attributes.get(name), "to": value}
            for name, value in desired["attributes"].items()
            if current_attributes.get(name) != value
        ]
    if operation == "firmware.apply":
        return [] if str(current.get("version") or "") == desired["expected_version"] else [{
            "field": f"firmware.{desired['component_id']}.version",
            "from": current.get("version") or "",
            "to": desired["expected_version"],
        }]
    if operation == "storage.volume.apply":
        matches = [item for item in current.get("volumes") or [] if item.get("name") == desired["volume_name"]]
        if matches:
            item = matches[0]
            if item.get("raid_type") == desired["raid_type"] and sorted(item.get("drive_ids") or []) == desired["drive_ids"]:
                return []
            return [{
                "field": f"storage.volume.{desired['volume_name']}",
                "from": {"id": item.get("id"), "raid_type": item.get("raid_type"), "drive_ids": item.get("drive_ids")},
                "to": {"raid_type": desired["raid_type"], "drive_ids": desired["drive_ids"]},
            }]
        return [{
            "field": f"storage.volume.{desired['volume_name']}",
            "from": None,
            "to": {"raid_type": desired["raid_type"], "drive_ids": desired["drive_ids"]},
        }]
    if operation == "storage.volume.delete":
        matches = [item for item in current.get("volumes") or [] if item.get("id") == desired["volume_id"]]
        return [] if not matches else [{
            "field": f"storage.volume.{desired['volume_id']}",
            "from": {"name": matches[0].get("name"), "raid_type": matches[0].get("raid_type"), "drive_ids": matches[0].get("drive_ids")},
            "to": None,
        }]
    if operation == "virtual-media.insert":
        desired_hash = hashlib.sha256(desired["image_url"].encode()).hexdigest()
        changes: list[dict[str, Any]] = []
        if current.get("image_sha256") != desired_hash:
            changes.append({"field": "image_sha256", "from": current.get("image_sha256") or "", "to": desired_hash})
        if current.get("inserted") is not True:
            changes.append({"field": "inserted", "from": bool(current.get("inserted")), "to": True})
        if current.get("write_protected") is not True:
            changes.append({"field": "write_protected", "from": bool(current.get("write_protected")), "to": True})
        return changes
    desired_boot = {
        "boot_target": BOOT_TARGETS[desired["target"]],
        "boot_enabled": BOOT_ENABLED[desired["enabled"]],
    }
    if desired.get("mode"):
        desired_boot["boot_mode"] = BOOT_MODES[desired["mode"]]
    return [
        {"field": field, "from": current.get(field), "to": value}
        for field, value in desired_boot.items()
        if str(current.get(field) or "") != str(value)
    ]


def _load_runtime_context(typed: dict[str, Any]) -> tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    kind, operation = _operation(typed)
    provider = _provider_target(typed)
    desired = _validate_desired_state(kind, operation, typed.get("desired_state") or {})
    if operation == "virtual-media.insert":
        _virtual_media_image_allowed(provider, desired["image_url"])
    if operation == "secure-boot.apply":
        _secure_boot_policy(provider, desired)
    if operation in {"sriov.apply", "iommu.apply"}:
        _hardware_feature_policy(provider, operation, desired)
    if operation == "boot-order.apply":
        _boot_order_policy(provider, desired)
    if operation == "bios.apply":
        _bios_attributes_allowed(provider, desired["attributes"])
    if operation == "firmware.apply":
        _firmware_request_allowed(provider, desired)
    if operation.startswith("storage.volume."):
        _storage_request_allowed(provider, desired, operation)
    if kind == "network-switch":
        _switch_endpoint(provider)
        _switch_policy(provider, desired, operation)
    if kind == "proxmox":
        proxmox_runtime.validate_provider(provider, desired, operation)
    credential_ref = str(provider.get("credential_ref") or "")
    if kind == "host-network":
        credential = {}
    elif kind == "ipmi":
        credential = _ipmi_credential_profile(credential_ref)
    elif kind == "pxe":
        credential = _pxe_credential_profile(credential_ref)
    elif kind == "network-switch":
        credential = _switch_credential_profile(credential_ref)
    elif kind == "proxmox":
        credential = proxmox_runtime._credential(provider)
    else:
        credential = _credential_profile(credential_ref)
    return kind, operation, provider, desired, credential


def _host_network_interface_names() -> list[dict[str, Any]]:
    """Read host network interfaces via /sys/class/net — no arbitrary SSH/script surface."""
    SYS_NET = Path("/sys/class/net")
    interfaces: list[dict[str, Any]] = []
    try:
        if not SYS_NET.is_dir():
            return interfaces
        entries = sorted(SYS_NET.iterdir())
    except OSError:
        return interfaces
    for entry in entries:
        if not entry.is_dir() or entry.name == "lo":
            continue
        try:
            if entry.is_symlink():
                continue
            addr_path = entry / "address"
            oper_path = entry / "operstate"
            mtu_path = entry / "mtu"
            if not addr_path.exists() or not oper_path.exists() or not mtu_path.exists():
                continue
            mac = addr_path.read_text(encoding="utf-8").strip().lower()
            state = oper_path.read_text(encoding="utf-8").strip().lower()
            mtu_val = mtu_path.read_text(encoding="utf-8").strip()
            if not PXE_MAC_RE.fullmatch(mac):
                continue
            if state not in {"up", "down", "unknown"}:
                state = "unknown"
            mtu_int = int(mtu_val) if mtu_val.isdigit() else 1500
            interfaces.append({"name": entry.name, "mac": mac, "state": state, "mtu": mtu_int})
        except (OSError, ValueError):
            continue
    return interfaces


def _host_network_bond_info() -> list[dict[str, Any]]:
    """Read bond master info from /sys/class/net/bond*/bonding."""
    SYS_NET = Path("/sys/class/net")
    bonds: list[dict[str, Any]] = []
    try:
        if not SYS_NET.is_dir():
            return bonds
        for entry in sorted(SYS_NET.iterdir()):
            if not entry.name.startswith("bond") or not entry.is_dir():
                continue
            bond_dir = entry / "bonding"
            if not bond_dir.is_dir():
                continue
            try:
                mode_path = bond_dir / "mode"
                slaves_path = bond_dir / "slaves"
                mii_path = bond_dir / "miimon"
                lacp_path = bond_dir / "lacp_rate"
                mode = mode_path.read_text(encoding="utf-8").strip().split(None, 1)[0] if mode_path.exists() else ""
                slaves_str = slaves_path.read_text(encoding="utf-8").strip() if slaves_path.exists() else ""
                slaves_list = [s.strip() for s in slaves_str.split() if s.strip()] if slaves_str else []
                miimon = int(mii_path.read_text(encoding="utf-8").strip()) if mii_path.exists() else 0
                lacp = lacp_path.read_text(encoding="utf-8").strip() if lacp_path.exists() else ""
                bonds.append({
                    "name": entry.name, "mode": mode, "slaves": slaves_list,
                    "miimon": miimon, "lacp_rate": lacp,
                })
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return bonds


def _host_network_vlan_info() -> list[dict[str, Any]]:
    """Read VLAN interfaces from /proc/net/vlan/config."""
    vlan_path = Path("/proc/net/vlan/config")
    vlans: list[dict[str, Any]] = []
    try:
        if not vlan_path.exists():
            return vlans
        for line in vlan_path.read_text(encoding="utf-8").strip().splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2] == "|":
                # VLAN-ID | interface-name | parent-interface
                vlan_id = parts[0]
                parent = parts[1]
                vlans.append({"vlan_id": int(vlan_id), "parent": parent, "interface": f"{parent}.{vlan_id}"})
    except (OSError, ValueError):
        pass
    return vlans


def _host_network_address_info() -> dict[str, list[dict[str, Any]]]:
    """Read local addresses from kernel interface tables without shelling out."""
    interfaces: dict[str, list[dict[str, Any]]] = {}
    try:
        import ctypes
        import fcntl
        import struct
    except ImportError:
        return interfaces
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buf = ctypes.create_string_buffer(4096)
            ifconf = struct.pack("iP", len(buf), ctypes.addressof(buf))
            result = fcntl.ioctl(sock.fileno(), 0x8912, ifconf)
            byte_count = struct.unpack("iP", result)[0]
            for index in range(0, min(byte_count, len(buf)), 40):
                record = buf.raw[index:index + 40]
                ifname = record[:16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                address = socket.inet_ntoa(record[20:24])
                if ifname and address != "0.0.0.0":
                    interfaces.setdefault(ifname, []).append({"address": address, "family": "inet"})
        finally:
            sock.close()
    except (OSError, ValueError, struct.error):
        pass
    try:
        inet6_path = Path("/proc/net/if_inet6")
        if inet6_path.exists():
            for line in inet6_path.read_text(encoding="utf-8").strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 6 and len(parts[0]) == 32:
                    address = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(parts[0]))
                    interfaces.setdefault(parts[5], []).append({"address": address, "family": "inet6"})
    except (OSError, ValueError):
        pass
    return interfaces


def _host_network_current(provider: dict[str, Any], credential: dict[str, Any], operation: str, desired: dict[str, Any] | None = None) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Read host network state from local /sys and /proc files — no SSH/scripts."""
    if operation == "network.discover":
        interfaces = _host_network_interface_names()
        bonds = _host_network_bond_info()
        vlans = _host_network_vlan_info()
        raw_addrs = _host_network_address_info()
        addrs = raw_addrs if isinstance(raw_addrs, dict) else {}
        for iface in interfaces:
            iface["addresses"] = addrs.get(iface["name"], [])
        current = {"interfaces": interfaces, "bonds": bonds, "vlans": vlans}
        return "local", {}, current
    iface_name = str(desired.get("interface") or "") if desired else ""
    interfaces = _host_network_interface_names()
    iface = next((i for i in interfaces if i["name"] == iface_name), None)
    if not iface and iface_name:
        iface = {"name": iface_name, "mac": "", "state": "unknown", "mtu": 1500, "addresses": []}
    raw_addrs = _host_network_address_info()
    addrs = raw_addrs if isinstance(raw_addrs, dict) else {}
    if iface:
        iface["addresses"] = addrs.get(iface["name"], [])
    bonds = _host_network_bond_info()
    bond = next((b for b in bonds if b["name"] == iface_name), None)
    vlans = _host_network_vlan_info()
    vlan = next((v for v in vlans if v["interface"] == iface_name), None)
    current = {"interface": iface, "bond": bond, "vlan": vlan, "interfaces": interfaces, "bonds": bonds, "vlans": vlans}
    return "local", {}, current


def _desired_host_network_diff(current: dict[str, Any], desired: dict[str, Any], operation: str) -> list[dict[str, Any]]:
    if operation == "network.discover":
        return []
    if operation == "interface.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        changes: list[dict[str, Any]] = []
        if "state" in desired and iface.get("state") != desired["state"]:
            changes.append({"field": "host.interface.state", "from": iface.get("state"), "to": desired["state"]})
        if "mtu" in desired and iface.get("mtu") != desired["mtu"]:
            changes.append({"field": "host.interface.mtu", "from": iface.get("mtu"), "to": desired["mtu"]})
        if "mac" in desired and iface.get("mac") != desired["mac"]:
            changes.append({"field": "host.interface.mac", "from": iface.get("mac"), "to": desired["mac"]})
        return changes
    if operation == "interface.bond":
        bond = current.get("bond") if isinstance(current.get("bond"), dict) else {}
        changes = []
        if bond.get("mode") != desired["mode"]:
            changes.append({"field": f"bond.{desired['bond_interface']}.mode", "from": bond.get("mode"), "to": desired["mode"]})
        if sorted(bond.get("slaves") or []) != sorted(desired["slaves"]):
            changes.append({"field": f"bond.{desired['bond_interface']}.slaves", "from": bond.get("slaves") or [], "to": desired["slaves"]})
        return changes
    if operation == "vlan.configure":
        vlan = current.get("vlan") if isinstance(current.get("vlan"), dict) else {}
        return [] if vlan and vlan.get("vlan_id") == desired["vlan_id"] else [{"field": f"vlan.{desired['interface']}.id", "from": vlan.get("vlan_id") if vlan else None, "to": desired["vlan_id"]}]
    if operation == "mtu.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        return [] if iface.get("mtu") == desired["mtu"] else [{"field": f"mtu.{desired['interface']}", "from": iface.get("mtu"), "to": desired["mtu"]}]
    if operation == "address.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        addrs = iface.get("addresses") or []
        current_addresses = [a.get("address") for a in addrs]
        changes = []
        if desired["address"] not in current_addresses:
            changes.append({"field": "host.address.address", "from": current_addresses, "to": desired["address"]})
        if "prefix" in desired:
            changes.append({"field": "host.address.prefix", "from": None, "to": desired["prefix"]})
        if "gateway" in desired:
            changes.append({"field": "host.address.gateway", "from": None, "to": desired["gateway"]})
        return changes
    return []


def _apply_host_network(operation: str, resource_url: str, resource: dict[str, Any], desired: dict[str, Any], credential: dict[str, Any]) -> None:
    """Apply host network configuration via typed netlink/pyroute2 calls — no arbitrary scripts."""
    import pyroute2  # type: ignore[import-untyped]
    ip = pyroute2.IPRoute()
    try:
        if operation == "interface.configure":
            idx = ip.link_lookup(ifname=desired["interface"])
            if not idx:
                raise HTTPException(409, f"host-network interface {desired['interface']} not found")
            kwargs: dict[str, Any] = {}
            if "state" in desired:
                kwargs["state"] = desired["state"]
            if "mtu" in desired:
                kwargs["mtu"] = desired["mtu"]
            if kwargs:
                ip.link("set", index=idx[0], **kwargs)
        elif operation == "interface.bond":
            # Create bond if not exists
            idx = ip.link_lookup(ifname=desired["bond_interface"])
            if not idx:
                ip.link("add", ifname=desired["bond_interface"], kind="bond")
                idx = ip.link_lookup(ifname=desired["bond_interface"])
            if not idx:
                raise HTTPException(502, "host-network bond interface could not be created")
            # Set bond mode via sysfs
            bond_dir = Path("/sys/class/net") / desired["bond_interface"] / "bonding"
            if bond_dir.is_dir():
                mode_path = bond_dir / "mode"
                if mode_path.exists():
                    mode_map = {
                        "802.3ad": "4", "active-backup": "1", "balance-tlb": "5",
                        "balance-alb": "6", "balance-rr": "0", "balance-xor": "2", "broadcast": "3",
                    }
                    mode_val = mode_map.get(desired["mode"])
                    if mode_val:
                        mode_path.write_text(mode_val, encoding="utf-8")
                if "miimon" in desired:
                    miimon_path = bond_dir / "miimon"
                    if miimon_path.exists():
                        miimon_path.write_text(str(desired["miimon"]), encoding="utf-8")
                if "lacp_rate" in desired:
                    lacp_path = bond_dir / "lacp_rate"
                    if lacp_path.exists():
                        lacp_path.write_text("1" if desired["lacp_rate"] == "fast" else "0", encoding="utf-8")
            # Enslave slaves
            for slave in desired["slaves"]:
                slave_idx = ip.link_lookup(ifname=slave)
                if slave_idx:
                    ip.link("set", index=slave_idx[0], master=idx[0])
            ip.link("set", index=idx[0], state="up")
        elif operation == "vlan.configure":
            vlan_name = f"{desired['interface']}.{desired['vlan_id']}"
            idx = ip.link_lookup(ifname=vlan_name)
            if not idx:
                parent_idx = ip.link_lookup(ifname=desired["interface"])
                if not parent_idx:
                    raise HTTPException(409, f"host-network parent interface {desired['interface']} not found")
                ip.link("add", ifname=vlan_name, kind="vlan", vlan_id=desired["vlan_id"])
        elif operation == "mtu.configure":
            idx = ip.link_lookup(ifname=desired["interface"])
            if not idx:
                raise HTTPException(409, f"host-network interface {desired['interface']} not found")
            ip.link("set", index=idx[0], mtu=desired["mtu"])
        elif operation == "address.configure":
            idx = ip.link_lookup(ifname=desired["interface"])
            if not idx:
                raise HTTPException(409, f"host-network interface {desired['interface']} not found")
            prefix = desired.get("prefix", 24)
            import socket as _socket
            import struct as _struct
            try:
                addr_bytes = _socket.inet_pton(_socket.AF_INET, desired["address"])
            except OSError:
                addr_bytes = _socket.inet_pton(_socket.AF_INET6, desired["address"])
            ip.addr("add", index=idx[0], address=desired["address"], mask=prefix)
            if "gateway" in desired:
                try:
                    _socket.inet_pton(_socket.AF_INET, desired["gateway"])
                    ip.route("add", dst="0.0.0.0/0", gateway=desired["gateway"])
                except OSError:
                    ip.route("add", dst="::/0", gateway=desired["gateway"])
    finally:
        ip.close()


def _host_network_verify(operation: str, current: dict[str, Any], desired: dict[str, Any]) -> bool:
    if operation == "interface.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        for key, expected in desired.items():
            if key == "interface":
                continue
            if iface.get(key) != expected and iface.get(key) != str(expected):
                return False
        return True
    if operation == "interface.bond":
        bond = current.get("bond") if isinstance(current.get("bond"), dict) else {}
        if bond.get("mode") != desired["mode"]:
            return False
        if sorted(bond.get("slaves") or []) != sorted(desired["slaves"]):
            return False
        return True
    if operation == "vlan.configure":
        vlan = current.get("vlan") if isinstance(current.get("vlan"), dict) else {}
        return vlan is not None and vlan.get("vlan_id") == desired["vlan_id"]
    if operation == "mtu.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        return iface.get("mtu") == desired["mtu"]
    if operation == "address.configure":
        iface = current.get("interface") if isinstance(current.get("interface"), dict) else {}
        return any(a.get("address") == desired["address"] for a in iface.get("addresses") or [])
    if operation == "network.discover":
        return len(current.get("interfaces") or []) > 0
    return False


def _redfish_current(
    provider: dict[str, Any], credential: dict[str, Any], operation: str, desired: dict[str, Any] | None = None
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if operation == "firmware.apply":
        component_id = str(desired.get("component_id") or "") if isinstance(desired, dict) else ""
        action_url, component_url, component = _redfish_firmware(provider, credential, component_id)
        return action_url, {"component_url": component_url}, _safe_firmware_snapshot(component)
    system_url, system = _redfish_system(provider, credential)
    if operation.startswith("virtual-media."):
        media_url, media = _redfish_virtual_media(provider, credential, system_url, system)
        return media_url, media, _safe_virtual_media_snapshot(media)
    if operation == "secure-boot.apply":
        if not isinstance(desired, dict):
            raise HTTPException(422, "Redfish secure boot runtime requires desired state")
        policy = _secure_boot_policy(provider, desired)
        _require_platform_activation_ready(system, policy["activation"])
        secure_url, secure = _redfish_secure_boot(system_url, system, credential)
        resource = {"system_url": system_url, "system": system, "reset_type": policy["reset_type"]}
        return secure_url, resource, _safe_secure_boot_snapshot(system, secure)
    if operation in {"sriov.apply", "iommu.apply"}:
        if not isinstance(desired, dict):
            raise HTTPException(422, "Redfish platform feature runtime requires desired state")
        policy = _hardware_feature_policy(provider, operation, desired)
        _require_platform_activation_ready(system, policy["activation"])
        _, active_bios, settings_url, settings_bios = _redfish_bios_resources(provider, credential, system_url, system)
        current = _safe_feature_snapshot(
            system, active_bios, settings_bios, policy["attribute"],
            policy["enabled_value"], policy["disabled_value"],
        )
        resource = {
            "system_url": system_url, "system": system, "settings_url": settings_url,
            "attribute": policy["attribute"], "target_value": policy["target_value"],
            "activation": policy["activation"], "reset_type": policy["reset_type"],
        }
        return settings_url, resource, current
    if operation == "boot-order.apply":
        if not isinstance(desired, dict):
            raise HTTPException(422, "Redfish boot-order runtime requires desired state")
        policy = _boot_order_policy(provider, desired)
        _require_platform_activation_ready(system, policy["activation"])
        options = _redfish_boot_options(system_url, system, credential)
        option_map = {item["reference"]: item for item in options}
        missing = [item for item in desired["order"] if item not in option_map]
        if missing:
            raise HTTPException(409, "Redfish requested boot option is not present: " + ", ".join(missing))
        disabled = [item for item in desired["order"] if option_map[item]["enabled"] is not True]
        if disabled:
            raise HTTPException(409, "Redfish requested boot option is disabled: " + ", ".join(disabled))
        settings_url = _redfish_system_settings_url(system_url, system)
        resource = {
            "system_url": system_url, "system": system, "settings_url": settings_url,
            "activation": policy["activation"], "reset_type": policy["reset_type"],
        }
        return settings_url, resource, _safe_boot_order_snapshot(system, options)
    if operation == "bios.apply":
        bios_url, bios = _redfish_bios(provider, credential, system_url, system)
        requested = desired.get("attributes") if isinstance(desired, dict) and isinstance(desired.get("attributes"), dict) else {}
        return bios_url, bios, _safe_bios_snapshot(bios, requested)
    if operation.startswith("storage.volume."):
        if not isinstance(desired, dict):
            raise HTTPException(422, "Redfish storage runtime requires desired state")
        return _redfish_storage(provider, credential, system_url, system, desired, operation)
    return system_url, system, _safe_system_snapshot(system)


def preview(changeset_plan: dict[str, Any]) -> dict[str, Any]:
    typed = _typed_plan(changeset_plan)
    kind, operation, provider, desired, credential = _load_runtime_context(typed)
    if kind == "redfish":
        if operation in {"bios.apply", "firmware.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "boot-order.apply"} or operation.startswith("storage.volume."):
            _, _, current = _redfish_current(provider, credential, operation, desired)
        else:
            _, _, current = _redfish_current(provider, credential, operation)
    elif kind == "ipmi":
        _, _, current = _ipmi_current(provider, credential, operation)
    elif kind == "pxe":
        server = _pxe_server_target(typed)
        supply = _pxe_artifact_supply(typed, desired)
        _pxe_callback_token(credential, desired["callback_ref"], desired["callback_token_sha256"])
        _pxe_unattended_profile(credential, desired["unattended_profile_ref"])
        current = _pxe_preview_current(typed, provider, credential, server)
        current["boot_provider"]["provider_kind"] = str(_pxe_boot_provider_target(typed, server).get("kind") or "")
    elif kind == "host-network":
        _, _, current = _host_network_current(provider, credential, operation, desired)
    elif kind == "network-switch":
        _, _, current = _switch_current(provider, credential, operation, desired)
    elif kind == "proxmox":
        current, _ = proxmox_runtime.current(provider, desired, operation, credential)
    else:
        raise HTTPException(422, "trusted runtime preview is not available for this infrastructure provider")
    diff = _pxe_desired_diff(current, desired, server, supply) if kind == "pxe" else _desired_host_network_diff(current, desired, operation) if kind == "host-network" else _switch_diff(operation, current, desired) if kind == "network-switch" else proxmox_runtime.diff(operation, current, desired) if kind == "proxmox" else _desired_diff(operation, current, desired)
    return {
        "kind": "InfrastructureRuntimePreview",
        "provider_kind": kind,
        "operation": operation,
        "typed_plan_hash": typed["plan_hash"],
        "current": current,
        "current_hash": sha256_hex(current),
        "desired_state": desired,
        "diff": diff,
        "active_probe": True,
        "credential_material_returned": False,
        "secret_output_suppressed": True,
        "arbitrary_cli": False,
        "arbitrary_shell": False,
    }


def _verify_ticket(ticket: dict[str, Any], signature: str, *, consume: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    if not EXECUTION_KEY:
        raise HTTPException(503, "execution signing key not configured")
    expected = hmac.new(EXECUTION_KEY.encode(), canonical_json(ticket).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "invalid execution ticket signature")
    now = int(time.time())
    if int(ticket.get("expires_at") or 0) < now:
        raise HTTPException(409, "execution ticket expired")
    if int(ticket.get("issued_at") or 0) > now + 30:
        raise HTTPException(409, "execution ticket issued_at is in the future")
    plan = ticket.get("plan")
    if not isinstance(plan, dict) or sha256_hex(plan) != str(ticket.get("plan_hash") or ""):
        raise HTTPException(409, "execution ticket plan hash mismatch")
    preconditions = ticket.get("preconditions") or {}
    if not isinstance(preconditions, dict) or preconditions.get("executor") != "infrastructure-provider-worker":
        raise HTTPException(422, "execution ticket is not bound to infrastructure-provider-worker")
    if consume:
        with _USED_LOCK:
            if signature in _USED_TICKETS:
                raise HTTPException(409, "execution ticket has already been used")
            _USED_TICKETS.add(signature)
    return plan, preconditions


def _apply_redfish(operation: str, resource_url: str, resource: dict[str, Any], desired: dict[str, Any], credential: dict[str, Any]) -> None:
    if operation == "inventory.refresh":
        return
    if operation == "power.set":
        actions = resource.get("Actions") if isinstance(resource.get("Actions"), dict) else {}
        reset = actions.get("#ComputerSystem.Reset") if isinstance(actions.get("#ComputerSystem.Reset"), dict) else {}
        target = reset.get("target")
        if not isinstance(target, str) or not target:
            raise HTTPException(502, "Redfish system does not expose ComputerSystem.Reset action")
        _request_json("POST", _same_origin_url(resource_url, target), credential=credential, body={"ResetType": POWER_RESET_TYPES[desired["state"]]})
        return
    if operation == "secure-boot.apply":
        _request_json("PATCH", resource_url, credential=credential, body={"SecureBootEnable": desired["enabled"]})
        _redfish_reset(str(resource.get("system_url") or ""), resource.get("system") or {}, credential, str(resource.get("reset_type") or ""))
        return
    if operation in {"sriov.apply", "iommu.apply"}:
        settings_url = str(resource.get("settings_url") or "")
        attribute = str(resource.get("attribute") or "")
        if not settings_url or not BIOS_ATTRIBUTE_RE.fullmatch(attribute):
            raise HTTPException(502, "Redfish platform feature runtime lost its exact BIOS settings target")
        _request_json("PATCH", settings_url, credential=credential, body={"Attributes": {attribute: resource.get("target_value")}})
        if resource.get("activation") == "reboot":
            _redfish_reset(str(resource.get("system_url") or ""), resource.get("system") or {}, credential, str(resource.get("reset_type") or ""))
        return
    if operation == "boot-order.apply":
        settings_url = str(resource.get("settings_url") or "")
        if not settings_url:
            raise HTTPException(502, "Redfish boot-order runtime lost its exact ComputerSystem settings target")
        _request_json("PATCH", settings_url, credential=credential, body={"Boot": {"BootOrder": desired["order"]}})
        if resource.get("activation") == "reboot":
            _redfish_reset(str(resource.get("system_url") or ""), resource.get("system") or {}, credential, str(resource.get("reset_type") or ""))
        return
    if operation == "bios.apply":
        _request_json("PATCH", resource_url, credential=credential, body={"Attributes": desired["attributes"]})
        return
    if operation == "firmware.apply":
        component_url = resource.get("component_url")
        if not isinstance(component_url, str) or not component_url:
            raise HTTPException(502, "Redfish firmware runtime lost its exact component target")
        _request_json(
            "POST", resource_url, credential=credential,
            body={"ImageURI": desired["image_url"], "Targets": [component_url]},
        )
        return
    if operation == "storage.volume.apply":
        drive_urls = resource.get("drive_urls") if isinstance(resource.get("drive_urls"), dict) else {}
        if any(drive_id not in drive_urls for drive_id in desired["drive_ids"]):
            raise HTTPException(409, "Redfish storage runtime lost an exact physical-drive target")
        body = {
            "Name": desired["volume_name"],
            "RAIDType": desired["raid_type"],
            "Links": {"Drives": [{"@odata.id": drive_urls[drive_id]} for drive_id in desired["drive_ids"]]},
        }
        _request_json("POST", resource_url, credential=credential, body=body)
        return
    if operation == "storage.volume.delete":
        volume_urls = resource.get("volume_urls") if isinstance(resource.get("volume_urls"), dict) else {}
        volume_url = volume_urls.get(desired["volume_id"])
        if not volume_url:
            return
        _request_json("DELETE", volume_url, credential=credential)
        return
    if operation in {"virtual-media.insert", "virtual-media.eject"}:
        actions = resource.get("Actions") if isinstance(resource.get("Actions"), dict) else {}
        action_name = "#VirtualMedia.InsertMedia" if operation == "virtual-media.insert" else "#VirtualMedia.EjectMedia"
        action = actions.get(action_name) if isinstance(actions.get(action_name), dict) else {}
        target = action.get("target")
        if not isinstance(target, str) or not target:
            raise HTTPException(502, f"Redfish virtual media does not expose {action_name} action")
        body = {"Image": desired["image_url"], "Inserted": True, "WriteProtected": True} if operation == "virtual-media.insert" else {}
        _request_json("POST", _same_origin_url(resource_url, target), credential=credential, body=body)
        return
    boot: dict[str, Any] = {
        "BootSourceOverrideTarget": BOOT_TARGETS[desired["target"]],
        "BootSourceOverrideEnabled": BOOT_ENABLED[desired["enabled"]],
    }
    if desired.get("mode"):
        boot["BootSourceOverrideMode"] = BOOT_MODES[desired["mode"]]
    _request_json("PATCH", resource_url, credential=credential, body={"Boot": boot})


def _verification_matches(
    operation: str, current: dict[str, Any], desired: dict[str, Any], *, before: dict[str, Any] | None = None
) -> bool:
    if operation == "inventory.refresh":
        return bool(current.get("resource_id") or current.get("serial_number") or current.get("model"))
    if operation == "power.set":
        state = desired["state"]
        if state in {"restart", "graceful-restart", "power-cycle"}:
            if before is None or str(current.get("power_state") or "").lower() != "on":
                return False
            markers = ("last_reset_time", "boot_progress_time")
            return any(current.get(marker) and current.get(marker) != before.get(marker) for marker in markers)
        expected = "on" if state == "on" else "off"
        return str(current.get("power_state") or "").lower() == expected
    if operation == "secure-boot.apply":
        return current.get("enabled") is desired["enabled"] and current.get("active_enabled") is desired["enabled"]
    if operation in {"sriov.apply", "iommu.apply"}:
        return current.get("enabled") is desired["enabled"]
    if operation == "boot-order.apply":
        return current.get("order") == desired["order"]
    if operation == "bios.apply":
        current_attributes = current.get("attributes") if isinstance(current.get("attributes"), dict) else {}
        return all(current_attributes.get(name) == value for name, value in desired["attributes"].items())
    if operation == "firmware.apply":
        return str(current.get("version") or "") == desired["expected_version"]
    if operation == "storage.volume.apply":
        matches = [item for item in current.get("volumes") or [] if item.get("name") == desired["volume_name"]]
        return len(matches) == 1 and matches[0].get("raid_type") == desired["raid_type"] and sorted(matches[0].get("drive_ids") or []) == desired["drive_ids"]
    if operation == "storage.volume.delete":
        return not any(item.get("id") == desired["volume_id"] for item in current.get("volumes") or [])
    if operation == "virtual-media.eject":
        return current.get("inserted") is False and current.get("image_present") is False
    if operation == "virtual-media.insert":
        desired_hash = hashlib.sha256(desired["image_url"].encode()).hexdigest()
        return current.get("inserted") is True and current.get("write_protected") is True and current.get("image_sha256") == desired_hash
    expected = {
        "boot_target": BOOT_TARGETS[desired["target"]],
        "boot_enabled": BOOT_ENABLED[desired["enabled"]],
    }
    if desired.get("mode"):
        expected["boot_mode"] = BOOT_MODES[desired["mode"]]
    return all(str(current.get(key) or "") == str(value) for key, value in expected.items())


def execute(ticket: dict[str, Any], signature: str) -> dict[str, Any]:
    if not EXECUTION_ENABLED:
        raise HTTPException(503, "infrastructure provider execution is disabled")
    changeset_plan, preconditions = _verify_ticket(ticket, signature, consume=True)
    typed = _typed_plan(changeset_plan)
    if str(preconditions.get("typed_plan_hash") or "") != str(typed.get("plan_hash") or ""):
        raise HTTPException(409, "execution ticket typed plan hash mismatch")
    kind, operation, provider, desired, credential = _load_runtime_context(typed)
    runtime_preview = typed.get("runtime_preview")
    if not isinstance(runtime_preview, dict) or runtime_preview.get("provider_kind") != kind or runtime_preview.get("operation") != operation:
        raise HTTPException(409, "approved infrastructure plan has no trusted runtime preview binding")
    if kind == "pxe":
        return _execute_pxe(typed, provider, desired, credential, runtime_preview)
    if kind == "redfish":
        if operation in {"bios.apply", "firmware.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "boot-order.apply"} or operation.startswith("storage.volume."):
            resource_url, resource, before = _redfish_current(provider, credential, operation, desired)
        else:
            resource_url, resource, before = _redfish_current(provider, credential, operation)
    elif kind == "ipmi":
        resource_url, resource, before = _ipmi_current(provider, credential, operation)
    elif kind == "host-network":
        resource_url, resource, before = _host_network_current(provider, credential, operation, desired)
    elif kind == "network-switch":
        resource_url, resource, before = _switch_current(provider, credential, operation, desired)
    elif kind == "proxmox":
        before, _ = proxmox_runtime.current(provider, desired, operation, credential)
        resource_url, resource = "", {}
    elif kind in {"vmware-workstation", "vmware", "openstack", "aws", "azure", "gcp"}:
        raise HTTPException(501, f"trusted {kind} runtime is not implemented; provider remains CONTRACT_ONLY")
    else:
        raise HTTPException(422, "trusted infrastructure runtime is unavailable for this provider kind")
    if sha256_hex(before) != str(runtime_preview.get("current_hash") or ""):
        raise HTTPException(409, "infrastructure state drifted after deterministic preview; re-plan and re-approve")
    if kind == "proxmox":
        proxmox_runtime.enforce_current_policy(provider, before, desired, operation)
    mutation_applied = bool(_desired_host_network_diff(before, desired, operation) if kind == "host-network" else _switch_diff(operation, before, desired) if kind == "network-switch" else proxmox_runtime.diff(operation, before, desired) if kind == "proxmox" else _desired_diff(operation, before, desired))
    if mutation_applied:
        if kind == "redfish":
            _apply_redfish(operation, resource_url, resource, desired, credential)
        elif kind == "host-network":
            _apply_host_network(operation, resource_url, resource, desired, credential)
        elif kind == "network-switch":
            _apply_switch(operation, provider, resource_url, resource, desired, credential)
        elif kind == "proxmox":
            proxmox_runtime.apply(provider, desired, operation, credential)
        else:
            _apply_ipmi(operation, provider, desired, credential)

    after = before
    verified = False
    platform_operation = operation in {"secure-boot.apply", "sriov.apply", "iommu.apply", "boot-order.apply"}
    if operation == "firmware.apply":
        attempts = max(1, FIRMWARE_VERIFY_ATTEMPTS)
        delay_seconds = max(0.0, FIRMWARE_VERIFY_DELAY_SECONDS)
    elif platform_operation and desired.get("activation") == "reboot":
        attempts = max(1, PLATFORM_VERIFY_ATTEMPTS)
        delay_seconds = max(0.0, PLATFORM_VERIFY_DELAY_SECONDS)
    else:
        attempts = max(1, VERIFY_ATTEMPTS)
        delay_seconds = max(0.0, VERIFY_DELAY_SECONDS)
    last_probe_error = ""
    for attempt in range(attempts):
        try:
            if kind == "redfish":
                if operation in {"bios.apply", "firmware.apply", "secure-boot.apply", "sriov.apply", "iommu.apply", "boot-order.apply"} or operation.startswith("storage.volume."):
                    _, _, after = _redfish_current(provider, credential, operation, desired)
                else:
                    _, _, after = _redfish_current(provider, credential, operation)
            elif kind == "host-network":
                _, _, after = _host_network_current(provider, credential, operation, desired)
            elif kind == "network-switch":
                _, _, after = _switch_current(provider, credential, operation, desired)
            elif kind == "proxmox":
                after, _ = proxmox_runtime.current(provider, desired, operation, credential)
            else:
                _, _, after = _ipmi_current(provider, credential, operation)
            last_probe_error = ""
        except HTTPException as exc:
            if platform_operation and desired.get("activation") == "reboot" and exc.status_code in {502, 503}:
                last_probe_error = f"HTTP {exc.status_code}"
                if attempt + 1 < attempts:
                    time.sleep(delay_seconds)
                    continue
            raise
        matches = _host_network_verify(operation, after, desired) if kind == "host-network" else _switch_verify(operation, after, desired) if kind == "network-switch" else proxmox_runtime.verify(after, desired, operation) if kind == "proxmox" else _verification_matches(operation, after, desired, before=before)
        if matches:
            verified = True
            break
        if attempt + 1 < attempts:
            time.sleep(delay_seconds)
    status = "PASS" if verified else "FAIL"
    observed_at = int(time.time())
    checks = [
        {
            "id": "provider-state-drift",
            "status": "PASS",
            "summary": "Provider state matched the exact approved runtime preview before execution",
            "evidence": {"provider_id": provider["id"], "before_hash": sha256_hex(before)},
        },
        {
            "id": f"{kind}-active-verify",
            "status": status,
            "summary": f"{kind.upper()} active verification matched the approved desired state" if verified else f"{kind.upper()} active verification did not converge to the approved desired state",
            "evidence": {"operation": operation, "observed": after},
        },
    ]
    return {
        "state": "SUCCEEDED" if verified else "FAILED",
        "provider_kind": kind,
        "operation": operation,
        "typed_plan_hash": typed["plan_hash"],
        "verification": {
            "checks": checks,
            "evidence": {
                "provider_id": provider["id"],
                "provider_kind": kind,
                "operation": operation,
                "arbitrary_cli": False,
                "arbitrary_shell": False,
                "raw_credentials_returned": False,
                "mutation_applied": mutation_applied,
                "stdout_returned": False,
                "stderr_returned": False,
                "last_probe_error": last_probe_error,
            },
            "observed_at": observed_at,
        },
    }
