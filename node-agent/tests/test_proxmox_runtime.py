from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest
from fastapi import HTTPException

from hermes_node_agent import proxmox_runtime as runtime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VERSION = "pve-8.2"
IMPLEMENTATION_VERSION = "pve-vm-runtime-v1"
OPERATIONS = {"vm.create", "vm.clone", "vm.update", "vm.delete", "vm.power",
              "network.attach", "snapshot.create", "snapshot.restore"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _credential_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                     ref: str = "cred_vm001") -> tuple[Path, str]:
    """Create a credential directory under *tmp_path* and point
    ``RUNTIME.CREDENTIAL_ROOT`` at it.  Returns ``(directory, ref)``."""
    directory = tmp_path / ref
    directory.mkdir()
    (directory / "token-id").write_text("hermes@pam!vm")
    (directory / "token-secret").write_text("test-token")
    (directory / "profile.json").write_text(json.dumps({
        "version": 1,
        "type": "proxmox-api-token",
        "token_id_file": "token-id",
        "token_secret_file": "token-secret",
    }))
    monkeypatch.setattr(runtime, "CREDENTIAL_ROOT", tmp_path)
    return directory, ref


def _provider(**overrides: object) -> dict:
    """Return a minimal valid provider dictionary."""
    provider = {
        "kind": "proxmox",
        "status": "configured",
        "endpoint": "https://pve.example.test:8006/api2/json",
        "credential_ref": "cred_vm001",
        "api_version": API_VERSION,
        "implementation_version": IMPLEMENTATION_VERSION,
        "capabilities": {
            "profile": IMPLEMENTATION_VERSION,
            "node_allowlist": ["node-a", "node-b"],
            "storage_allowlist": ["local-zfs"],
            "bridge_allowlist": ["vmbr0"],
            "template_allowlist": [],
            "vm_id_min": 100,
            "vm_id_max": 9999,
            "max_cpu_cores": 64,
            "max_memory_mib": 524288,
            "max_disk_gib": 8192,
            "max_nics": 4,
            "max_snapshots": 8,
            "action_allowlist": list(OPERATIONS),
            "allow_vm_delete": True,
            "allow_snapshot_restore": True,
        },
    }
    provider.update(**overrides)
    return provider


def _current_state(**overrides: object) -> dict:
    """Return a minimal current-state dict for a running VM."""
    state = {
        "present": True,
        "node": "node-a",
        "vm_id": 100,
        "qemu": True,
        "power_state": "running",
        "cpu_cores": 4,
        "memory_mib": 8192,
        "onboot": True,
        "disk": {"storage": "local-zfs", "size_gib": 64},
        "networks": {"net0": "vmbr0"},
        "snapshots": ["snap1", "snap2"],
    }
    state.update(**overrides)
    return state


# ===================================================================
# 1. Module-level constants
# ===================================================================

def test_module_constants() -> None:
    assert runtime.API_VERSION == API_VERSION
    assert runtime.IMPLEMENTATION_VERSION == IMPLEMENTATION_VERSION
    assert runtime.OPERATIONS == OPERATIONS
    assert hasattr(runtime, "RUNTIME_ENABLED")
    assert hasattr(runtime, "CREDENTIAL_ROOT")


def test_operations_membership() -> None:
    for op in OPERATIONS:
        assert op in runtime.OPERATIONS


# ===================================================================
# 2. validate_desired()
# ===================================================================


class TestValidateDesired:

    # -- vm.create -----------------------------------------------------------

    def test_vm_create_valid(self) -> None:
        result = runtime.validate_desired("vm.create", {
            "vm_id": 100, "node": "node-a", "name": "my-vm",
            "cpu_cores": 4, "memory_mib": 4096,
            "storage": "local-zfs", "disk_gib": 64,
        })
        assert result["vm_id"] == 100
        assert result["node"] == "node-a"
        assert result["name"] == "my-vm"
        assert result["cpu_cores"] == 4
        assert result["memory_mib"] == 4096
        assert result["storage"] == "local-zfs"
        assert result["disk_gib"] == 64
        assert "bridge" not in result

    def test_vm_create_with_bridge(self) -> None:
        result = runtime.validate_desired("vm.create", {
            "vm_id": 100, "node": "node-a", "name": "my-vm",
            "cpu_cores": 4, "memory_mib": 4096,
            "storage": "local-zfs", "disk_gib": 64, "bridge": "vmbr0",
        })
        assert result["bridge"] == "vmbr0"

    def test_vm_create_missing_required(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "node-a", "name": "my-vm",
            })

    def test_vm_create_extra_field(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "node-a", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 4096,
                "storage": "local-zfs", "disk_gib": 64,
                "extra": "bad",
            })

    def test_vm_create_vm_id_below_min(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_VM_ID"):
            runtime.validate_desired("vm.create", {
                "vm_id": 50, "node": "node-a", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 4096,
                "storage": "local-zfs", "disk_gib": 64,
            })

    def test_vm_create_cpu_cores_below_min(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_CPU_CORES"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "node-a", "name": "my-vm",
                "cpu_cores": 0, "memory_mib": 4096,
                "storage": "local-zfs", "disk_gib": 64,
            })

    def test_vm_create_memory_mib_above_max(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_MEMORY_MIB"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "node-a", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 2_000_000,
                "storage": "local-zfs", "disk_gib": 64,
            })

    def test_vm_create_vm_id_bool_rejected(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_VM_ID"):
            runtime.validate_desired("vm.create", {
                "vm_id": True, "node": "node-a", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 4096,
                "storage": "local-zfs", "disk_gib": 64,
            })

    # -- vm.clone ------------------------------------------------------------

    def test_vm_clone_valid(self) -> None:
        result = runtime.validate_desired("vm.clone", {
            "source_vm_id": 100, "source_node": "node-a",
            "target_vm_id": 200, "target_node": "node-b",
            "storage": "local-zfs", "name": "clone-vm",
        })
        assert result["source_vm_id"] == 100
        assert result["target_vm_id"] == 200
        assert result["target_node"] == "node-b"
        assert result["name"] == "clone-vm"

    def test_vm_clone_wrong_set(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.clone", {
                "source_vm_id": 100, "source_node": "node-a",
                "target_vm_id": 200, "target_node": "node-b",
                "storage": "local-zfs", "name": "clone-vm",
                "extra": "bad",
            })

    def test_vm_clone_missing_field(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.clone", {
                "source_vm_id": 100, "source_node": "node-a",
                "target_vm_id": 200, "target_node": "node-b",
                "name": "clone-vm",
            })

    # -- vm.update -----------------------------------------------------------

    def test_vm_update_valid(self) -> None:
        result = runtime.validate_desired("vm.update", {
            "vm_id": 100, "node": "node-a", "cpu_cores": 8,
        })
        assert result["vm_id"] == 100
        assert result["node"] == "node-a"
        assert result["cpu_cores"] == 8

    def test_vm_update_only_required_is_error(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.update", {
                "vm_id": 100, "node": "node-a",
            })

    def test_vm_update_all_optionals(self) -> None:
        result = runtime.validate_desired("vm.update", {
            "vm_id": 100, "node": "node-a",
            "cpu_cores": 4, "memory_mib": 4096, "onboot": True,
        })
        assert result["onboot"] is True

    def test_vm_update_onboot_not_bool(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_ONBOOT"):
            runtime.validate_desired("vm.update", {
                "vm_id": 100, "node": "node-a", "onboot": "yes",
            })

    def test_vm_update_extra_field(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.update", {
                "vm_id": 100, "node": "node-a", "cpu_cores": 4,
                "name": "bad",
            })

    # -- vm.delete -----------------------------------------------------------

    def test_vm_delete_valid(self) -> None:
        result = runtime.validate_desired("vm.delete", {
            "vm_id": 100, "node": "node-a", "confirm_vm_id": 100,
        })
        assert result["vm_id"] == 100
        assert result["node"] == "node-a"

    def test_vm_delete_confirmation_mismatch(self) -> None:
        with pytest.raises(HTTPException, match="CONFIRMATION_REQUIRED"):
            runtime.validate_desired("vm.delete", {
                "vm_id": 100, "node": "node-a", "confirm_vm_id": 999,
            })

    def test_vm_delete_missing_confirm(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.delete", {
                "vm_id": 100, "node": "node-a",
            })

    # -- vm.power ------------------------------------------------------------

    def test_vm_power_target_running(self) -> None:
        result = runtime.validate_desired("vm.power", {
            "vm_id": 100, "node": "node-a", "target_state": "running",
        })
        assert result["target_state"] == "running"

    def test_vm_power_target_stopped(self) -> None:
        result = runtime.validate_desired("vm.power", {
            "vm_id": 100, "node": "node-a", "target_state": "stopped",
        })
        assert result["target_state"] == "stopped"

    def test_vm_power_invalid_state(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_TARGET_STATE"):
            runtime.validate_desired("vm.power", {
                "vm_id": 100, "node": "node-a", "target_state": "reboot",
            })

    def test_vm_power_missing_field(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.power", {
                "vm_id": 100, "node": "node-a",
            })

    # -- network.attach ------------------------------------------------------

    def test_network_attach_valid(self) -> None:
        result = runtime.validate_desired("network.attach", {
            "vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr1",
        })
        assert result["slot"] == "net0"
        assert result["bridge"] == "vmbr1"

    def test_network_attach_invalid_slot(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_SLOT"):
            runtime.validate_desired("network.attach", {
                "vm_id": 100, "node": "node-a", "slot": "net8", "bridge": "vmbr1",
            })

    def test_network_attach_missing_field(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("network.attach", {
                "vm_id": 100, "node": "node-a", "bridge": "vmbr1",
            })

    # -- snapshot.create -----------------------------------------------------

    def test_snapshot_create_valid(self) -> None:
        result = runtime.validate_desired("snapshot.create", {
            "vm_id": 100, "node": "node-a", "snapshot": "pre-upgrade",
        })
        assert result["snapshot"] == "pre-upgrade"

    def test_snapshot_create_invalid_snapshot_name(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_SNAPSHOT"):
            runtime.validate_desired("snapshot.create", {
                "vm_id": 100, "node": "node-a", "snapshot": "snap with spaces",
            })

    # -- snapshot.restore ----------------------------------------------------

    def test_snapshot_restore_valid(self) -> None:
        result = runtime.validate_desired("snapshot.restore", {
            "vm_id": 100, "node": "node-a", "snapshot": "pre-upgrade",
            "confirm_vm_id": 100, "confirm_snapshot": "pre-upgrade",
        })
        assert result["snapshot"] == "pre-upgrade"

    def test_snapshot_restore_confirmation_mismatch_vm_id(self) -> None:
        with pytest.raises(HTTPException, match="CONFIRMATION_REQUIRED"):
            runtime.validate_desired("snapshot.restore", {
                "vm_id": 100, "node": "node-a", "snapshot": "pre-upgrade",
                "confirm_vm_id": 999, "confirm_snapshot": "pre-upgrade",
            })

    def test_snapshot_restore_confirmation_mismatch_snapshot(self) -> None:
        with pytest.raises(HTTPException, match="CONFIRMATION_REQUIRED"):
            runtime.validate_desired("snapshot.restore", {
                "vm_id": 100, "node": "node-a", "snapshot": "pre-upgrade",
                "confirm_vm_id": 100, "confirm_snapshot": "other-snap",
            })

    # -- invalid operation ---------------------------------------------------

    def test_unknown_operation(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.unknown", {})

    def test_non_dict_desired(self) -> None:
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_desired("vm.create", "not-a-dict")  # type: ignore[arg-type]

    # -- identifier validation (used by several operations) ------------------

    def test_invalid_node_name(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_NODE"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 4096,
                "storage": "local-zfs", "disk_gib": 64,
            })

    def test_invalid_storage_name(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_STORAGE"):
            runtime.validate_desired("vm.create", {
                "vm_id": 100, "node": "node-a", "name": "my-vm",
                "cpu_cores": 4, "memory_mib": 4096,
                "storage": "", "disk_gib": 64,
            })


# ===================================================================
# 3. validate_provider()
# ===================================================================


class TestValidateProvider:

    def test_validate_provider_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", False)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(), {}, "vm.create")

    def test_validate_provider_wrong_kind(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(kind="vmware"), {}, "vm.create")

    def test_validate_provider_wrong_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(status="discovered"), {}, "vm.create")

    def test_validate_provider_bad_endpoint_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(endpoint="http://pve.example.test:8006/api2/json"), {}, "vm.create")

    def test_validate_provider_bad_endpoint_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(endpoint="https://pve.example.test:443/api2/json"), {}, "vm.create")

    def test_validate_provider_bad_endpoint_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(endpoint="https://pve.example.test:8006/wrong"), {}, "vm.create")

    def test_validate_provider_bad_pins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(api_version="pve-7.4"), {}, "vm.create")

    def test_validate_provider_bad_implementation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(implementation_version="pve-vm-runtime-v2"), {}, "vm.create")

    def test_validate_provider_missing_action(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["action_allowlist"] = ["vm.create", "vm.delete"]
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(_provider(capabilities=caps), {"vm_id": 100, "node": "node-a", "target_state": "stopped"}, "vm.power")

    def test_validate_provider_node_not_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["node_allowlist"] = ["node-a"]
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"vm_id": 100, "node": "node-unknown", "target_state": "stopped"},
                "vm.power",
            )

    def test_validate_provider_storage_not_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["storage_allowlist"] = ["local-zfs"]
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"vm_id": 100, "node": "node-a", "name": "vm", "cpu_cores": 2,
                 "memory_mib": 2048, "storage": "nfs-export", "disk_gib": 32},
                "vm.create",
            )

    def test_validate_provider_bridge_not_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["bridge_allowlist"] = ["vmbr0"]
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr99"},
                "network.attach",
            )

    def test_validate_provider_vm_id_out_of_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(),
                {"vm_id": 99999, "node": "node-a", "target_state": "stopped"},
                "vm.power",
            )

    def test_validate_provider_exceeds_max_cpu_cores(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(),
                {"vm_id": 100, "node": "node-a", "cpu_cores": 128, "memory_mib": 4096,
                 "name": "vm", "storage": "local-zfs", "disk_gib": 32},
                "vm.create",
            )

    def test_validate_provider_vm_delete_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["allow_vm_delete"] = False
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100},
                "vm.delete",
            )

    def test_validate_provider_snapshot_restore_not_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["allow_snapshot_restore"] = False
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"vm_id": 100, "node": "node-a", "snapshot": "snap",
                 "confirm_vm_id": 100, "confirm_snapshot": "snap"},
                "snapshot.restore",
            )

    def test_validate_provider_template_not_in_allowlist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        caps = dict(_provider()["capabilities"])
        caps["template_allowlist"] = [{"node": "node-a", "vm_id": 888}]
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime.validate_provider(
                _provider(capabilities=caps),
                {"source_vm_id": 100, "source_node": "node-a",
                 "target_vm_id": 200, "target_node": "node-b",
                 "storage": "local-zfs", "name": "clone"},
                "vm.clone",
            )

    def test_validate_provider_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        result = runtime.validate_provider(
            _provider(),
            {"vm_id": 100, "node": "node-a", "target_state": "stopped"},
            "vm.power",
        )
        assert "nodes" in result
        assert "node-a" in result["nodes"]


# ===================================================================
# 4. diff()
# ===================================================================


class TestDiff:

    # -- vm.create -----------------------------------------------------------

    def test_diff_vm_create_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "name": "new-vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64}
        result = runtime.diff("vm.create", state, desired)
        assert result == [{"field": "vm.presence", "from": "absent", "to": "present"}]

    def test_diff_vm_create_present_idempotent(self) -> None:
        state = _current_state(cpu_cores=4, memory_mib=4096,
                               disk={"storage": "local-zfs", "size_gib": 64},
                               networks={"net0": "vmbr0"})
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64, "bridge": "vmbr0"}
        result = runtime.diff("vm.create", state, desired)
        assert result == []

    def test_diff_vm_create_mismatch(self) -> None:
        state = _current_state(cpu_cores=2, memory_mib=4096,
                               disk={"storage": "local-zfs", "size_gib": 32},
                               networks={"net0": "vmbr0"})
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64, "bridge": "vmbr0"}
        result = runtime.diff("vm.create", state, desired)
        fields = {r["field"] for r in result}
        assert "cpu_cores" in fields
        assert "boot_disk" in fields

    # -- vm.clone ------------------------------------------------------------

    def test_diff_vm_clone_absent(self) -> None:
        state = {"present": False, "node": "node-b", "vm_id": 200, "qemu": True}
        desired = {"source_vm_id": 100, "source_node": "node-a",
                   "target_vm_id": 200, "target_node": "node-b",
                   "storage": "local-zfs", "name": "clone"}
        result = runtime.diff("vm.clone", state, desired)
        assert result == [{"field": "vm.presence", "from": "absent", "to": "present"}]

    def test_diff_vm_clone_present_idempotent(self) -> None:
        state = _current_state(vm_id=200, node="node-b")
        desired = {"source_vm_id": 100, "source_node": "node-a",
                   "target_vm_id": 200, "target_node": "node-b",
                   "storage": "local-zfs", "name": "clone"}
        result = runtime.diff("vm.clone", state, desired)
        assert result == []

    # -- vm.delete -----------------------------------------------------------

    def test_diff_vm_delete_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}
        result = runtime.diff("vm.delete", state, desired)
        assert result == []

    def test_diff_vm_delete_present(self) -> None:
        state = _current_state()
        desired = {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}
        result = runtime.diff("vm.delete", state, desired)
        assert result == [{"field": "vm.presence", "from": "present", "to": "absent"}]

    # -- vm.power ------------------------------------------------------------

    def test_diff_vm_power_already_matching(self) -> None:
        state = _current_state(power_state="running")
        desired = {"vm_id": 100, "node": "node-a", "target_state": "running"}
        result = runtime.diff("vm.power", state, desired)
        assert result == []

    def test_diff_vm_power_needs_change(self) -> None:
        state = _current_state(power_state="running")
        desired = {"vm_id": 100, "node": "node-a", "target_state": "stopped"}
        result = runtime.diff("vm.power", state, desired)
        assert result == [{"field": "power_state", "from": "running", "to": "stopped"}]

    def test_diff_vm_power_vm_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "target_state": "running"}
        result = runtime.diff("vm.power", state, desired)
        assert result == [{"field": "vm.presence", "from": "absent", "to": "required"}]

    # -- vm.update -----------------------------------------------------------

    def test_diff_vm_update_idempotent(self) -> None:
        state = _current_state(cpu_cores=4, memory_mib=8192, onboot=True)
        desired = {"vm_id": 100, "node": "node-a", "cpu_cores": 4, "memory_mib": 8192, "onboot": True}
        result = runtime.diff("vm.update", state, desired)
        assert result == []

    def test_diff_vm_update_cpu_cores_differs(self) -> None:
        state = _current_state(cpu_cores=2, memory_mib=8192, onboot=True)
        desired = {"vm_id": 100, "node": "node-a", "cpu_cores": 4, "memory_mib": 8192, "onboot": True}
        result = runtime.diff("vm.update", state, desired)
        assert result == [{"field": "cpu_cores", "from": 2, "to": 4}]

    def test_diff_vm_update_onboot_differs(self) -> None:
        state = _current_state(cpu_cores=4, memory_mib=8192, onboot=True)
        desired = {"vm_id": 100, "node": "node-a", "onboot": False}
        result = runtime.diff("vm.update", state, desired)
        assert result == [{"field": "onboot", "from": True, "to": False}]

    def test_diff_vm_update_vm_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "cpu_cores": 4}
        result = runtime.diff("vm.update", state, desired)
        assert result == [{"field": "vm.presence", "from": "absent", "to": "required"}]

    # -- network.attach ------------------------------------------------------

    def test_diff_network_attach_idempotent(self) -> None:
        state = _current_state(networks={"net0": "vmbr0", "net1": "vmbr1"})
        desired = {"vm_id": 100, "node": "node-a", "slot": "net1", "bridge": "vmbr1"}
        result = runtime.diff("network.attach", state, desired)
        assert result == []

    def test_diff_network_attach_needs_change(self) -> None:
        state = _current_state(networks={"net0": "vmbr0"})
        desired = {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr1"}
        result = runtime.diff("network.attach", state, desired)
        assert result == [{"field": "net0", "from": "vmbr0", "to": "vmbr1"}]

    def test_diff_network_attach_vm_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr1"}
        result = runtime.diff("network.attach", state, desired)
        assert result == [{"field": "vm.presence", "from": "absent", "to": "required"}]

    # -- snapshot.create -----------------------------------------------------

    def test_diff_snapshot_create_absent(self) -> None:
        state = _current_state(snapshots=["snap1"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap-new"}
        result = runtime.diff("snapshot.create", state, desired)
        assert result == [{"field": "snapshot", "from": "absent", "to": "snap-new"}]

    def test_diff_snapshot_create_present(self) -> None:
        state = _current_state(snapshots=["snap1", "snap2"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap1"}
        result = runtime.diff("snapshot.create", state, desired)
        assert result == []

    # -- snapshot.restore ----------------------------------------------------

    def test_diff_snapshot_restore_not_present(self) -> None:
        state = _current_state(snapshots=["snap1"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap-other",
                   "confirm_vm_id": 100, "confirm_snapshot": "snap-other"}
        result = runtime.diff("snapshot.restore", state, desired)
        assert result == []

    def test_diff_snapshot_restore_present(self) -> None:
        state = _current_state(snapshots=["snap1", "snap2"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap1",
                   "confirm_vm_id": 100, "confirm_snapshot": "snap1"}
        result = runtime.diff("snapshot.restore", state, desired)
        assert result == [{"field": "snapshot.restore", "from": "current", "to": "snap1"}]


# ===================================================================
# 5. verify()
# ===================================================================


class TestVerify:

    # -- vm.create -----------------------------------------------------------

    def test_verify_vm_create_success(self) -> None:
        state = _current_state(present=True, cpu_cores=4, memory_mib=4096,
                               disk={"storage": "local-zfs", "size_gib": 64},
                               networks={"net0": "vmbr0"})
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64, "bridge": "vmbr0"}
        assert runtime.verify(state, desired, "vm.create") is True

    def test_verify_vm_create_failure_not_present(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64}
        assert runtime.verify(state, desired, "vm.create") is False

    def test_verify_vm_create_failure_wrong_cpu(self) -> None:
        state = _current_state(present=True, cpu_cores=2, memory_mib=4096,
                               disk={"storage": "local-zfs", "size_gib": 64})
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64}
        assert runtime.verify(state, desired, "vm.create") is False

    def test_verify_vm_create_failure_wrong_disk(self) -> None:
        state = _current_state(present=True, cpu_cores=4, memory_mib=4096,
                               disk={"storage": "local-zfs", "size_gib": 32})
        desired = {"vm_id": 100, "node": "node-a", "name": "vm",
                   "cpu_cores": 4, "memory_mib": 4096,
                   "storage": "local-zfs", "disk_gib": 64}
        assert runtime.verify(state, desired, "vm.create") is False

    # -- vm.clone ------------------------------------------------------------

    def test_verify_vm_clone_success(self) -> None:
        state = _current_state(present=True, vm_id=200)
        desired = {"source_vm_id": 100, "source_node": "node-a",
                   "target_vm_id": 200, "target_node": "node-b",
                   "storage": "local-zfs", "name": "clone"}
        assert runtime.verify(state, desired, "vm.clone") is True

    def test_verify_vm_clone_failure(self) -> None:
        state = {"present": False, "node": "node-b", "vm_id": 200, "qemu": True}
        desired = {"source_vm_id": 100, "source_node": "node-a",
                   "target_vm_id": 200, "target_node": "node-b",
                   "storage": "local-zfs", "name": "clone"}
        assert runtime.verify(state, desired, "vm.clone") is False

    # -- vm.delete -----------------------------------------------------------

    def test_verify_vm_delete_success(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}
        assert runtime.verify(state, desired, "vm.delete") is True

    def test_verify_vm_delete_failure(self) -> None:
        state = _current_state(present=True)
        desired = {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}
        assert runtime.verify(state, desired, "vm.delete") is False

    # -- vm.power ------------------------------------------------------------

    def test_verify_vm_power_success(self) -> None:
        state = _current_state(power_state="stopped")
        desired = {"vm_id": 100, "node": "node-a", "target_state": "stopped"}
        assert runtime.verify(state, desired, "vm.power") is True

    def test_verify_vm_power_failure(self) -> None:
        state = _current_state(power_state="running")
        desired = {"vm_id": 100, "node": "node-a", "target_state": "stopped"}
        assert runtime.verify(state, desired, "vm.power") is False

    def test_verify_vm_power_vm_absent(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        desired = {"vm_id": 100, "node": "node-a", "target_state": "running"}
        assert runtime.verify(state, desired, "vm.power") is False

    # -- vm.update -----------------------------------------------------------

    def test_verify_vm_update_success(self) -> None:
        state = _current_state(cpu_cores=8, memory_mib=16384, onboot=False)
        desired = {"vm_id": 100, "node": "node-a", "cpu_cores": 8, "memory_mib": 16384, "onboot": False}
        assert runtime.verify(state, desired, "vm.update") is True

    def test_verify_vm_update_failure(self) -> None:
        state = _current_state(cpu_cores=4, memory_mib=8192, onboot=True)
        desired = {"vm_id": 100, "node": "node-a", "cpu_cores": 8, "memory_mib": 8192}
        assert runtime.verify(state, desired, "vm.update") is False

    # -- network.attach ------------------------------------------------------

    def test_verify_network_attach_success(self) -> None:
        state = _current_state(networks={"net0": "vmbr0", "net2": "vmbr2"})
        desired = {"vm_id": 100, "node": "node-a", "slot": "net2", "bridge": "vmbr2"}
        assert runtime.verify(state, desired, "network.attach") is True

    def test_verify_network_attach_failure(self) -> None:
        state = _current_state(networks={"net0": "vmbr0"})
        desired = {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr1"}
        assert runtime.verify(state, desired, "network.attach") is False

    # -- snapshot.create -----------------------------------------------------

    def test_verify_snapshot_create_success(self) -> None:
        state = _current_state(snapshots=["snap1", "snap2", "snap3"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap2"}
        assert runtime.verify(state, desired, "snapshot.create") is True

    def test_verify_snapshot_create_failure(self) -> None:
        state = _current_state(snapshots=["snap1"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap-unknown"}
        assert runtime.verify(state, desired, "snapshot.create") is False

    # -- snapshot.restore ----------------------------------------------------

    def test_verify_snapshot_restore_success(self) -> None:
        state = _current_state(snapshots=["snap1", "snap2"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap1",
                   "confirm_vm_id": 100, "confirm_snapshot": "snap1"}
        assert runtime.verify(state, desired, "snapshot.restore") is True

    def test_verify_snapshot_restore_failure(self) -> None:
        state = _current_state(snapshots=["snap1"])
        desired = {"vm_id": 100, "node": "node-a", "snapshot": "snap-other",
                   "confirm_vm_id": 100, "confirm_snapshot": "snap-other"}
        assert runtime.verify(state, desired, "snapshot.restore") is False


# ===================================================================
# 6. ensure_mutation_precondition()
# ===================================================================


class TestEnsureMutationPrecondition:

    def test_vm_delete_vm_stopped_ok(self) -> None:
        state = _current_state(power_state="stopped")
        runtime.ensure_mutation_precondition("vm.delete", state, {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}, {"max_nics": 4, "max_snapshots": 8})
        # no exception raised

    def test_vm_delete_vm_running_raises(self) -> None:
        state = _current_state(power_state="running")
        with pytest.raises(HTTPException, match="VM_MUST_BE_STOPPED"):
            runtime.ensure_mutation_precondition("vm.delete", state, {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}, {"max_nics": 4, "max_snapshots": 8})

    def test_snapshot_restore_vm_stopped_ok(self) -> None:
        state = _current_state(power_state="stopped")
        runtime.ensure_mutation_precondition(
            "snapshot.restore", state,
            {"vm_id": 100, "node": "node-a", "snapshot": "snap1",
             "confirm_vm_id": 100, "confirm_snapshot": "snap1"},
            {"max_nics": 4, "max_snapshots": 8},
        )
        # no exception raised

    def test_snapshot_restore_vm_running_raises(self) -> None:
        state = _current_state(power_state="running")
        with pytest.raises(HTTPException, match="VM_MUST_BE_STOPPED"):
            runtime.ensure_mutation_precondition(
                "snapshot.restore", state,
                {"vm_id": 100, "node": "node-a", "snapshot": "snap1",
                 "confirm_vm_id": 100, "confirm_snapshot": "snap1"},
                {"max_nics": 4, "max_snapshots": 8},
            )

    def test_vm_delete_vm_absent_skips_stopped_check(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        runtime.ensure_mutation_precondition("vm.delete", state, {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100}, {"max_nics": 4, "max_snapshots": 8})
        # no exception raised

    def test_network_attach_nic_limit_reached(self) -> None:
        state = _current_state(present=True, power_state="running",
                               networks={"net0": "vmbr0", "net1": "vmbr1", "net2": "vmbr2", "net3": "vmbr3"})
        with pytest.raises(HTTPException, match="NIC_LIMIT_REACHED"):
            runtime.ensure_mutation_precondition(
                "network.attach", state,
                {"vm_id": 100, "node": "node-a", "slot": "net4", "bridge": "vmbr4"},
                {"max_nics": 4, "max_snapshots": 8},
            )

    def test_network_attach_replacing_existing_slot_ok(self) -> None:
        state = _current_state(present=True, power_state="running",
                               networks={"net0": "vmbr0", "net1": "vmbr1", "net2": "vmbr2", "net3": "vmbr3"})
        # Replacing net0 — already at limit but slot exists, so no NIC_LIMIT
        runtime.ensure_mutation_precondition(
            "network.attach", state,
            {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr9"},
            {"max_nics": 4, "max_snapshots": 8},
        )
        # no exception raised

    def test_network_attach_vm_absent_skips_nic_check(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        runtime.ensure_mutation_precondition(
            "network.attach", state,
            {"vm_id": 100, "node": "node-a", "slot": "net0", "bridge": "vmbr1"},
            {"max_nics": 4, "max_snapshots": 8},
        )
        # no exception raised

    def test_snapshot_create_limit_reached(self) -> None:
        state = _current_state(present=True, power_state="running",
                               snapshots=[f"s{i}" for i in range(8)])
        with pytest.raises(HTTPException, match="SNAPSHOT_LIMIT_REACHED"):
            runtime.ensure_mutation_precondition(
                "snapshot.create", state,
                {"vm_id": 100, "node": "node-a", "snapshot": "new-snap"},
                {"max_nics": 4, "max_snapshots": 8},
            )

    def test_snapshot_create_below_limit_ok(self) -> None:
        state = _current_state(present=True, power_state="running",
                               snapshots=["s1", "s2"])
        runtime.ensure_mutation_precondition(
            "snapshot.create", state,
            {"vm_id": 100, "node": "node-a", "snapshot": "new-snap"},
            {"max_nics": 4, "max_snapshots": 8},
        )
        # no exception raised

    def test_snapshot_create_vm_absent_skips(self) -> None:
        state = {"present": False, "node": "node-a", "vm_id": 100, "qemu": True}
        runtime.ensure_mutation_precondition(
            "snapshot.create", state,
            {"vm_id": 100, "node": "node-a", "snapshot": "new-snap"},
            {"max_nics": 4, "max_snapshots": 8},
        )
        # no exception raised


# ===================================================================
# 7. Transport via monkeypatched urllib.request
# ===================================================================


class TestTransport:

    def test_request_rejects_non_json_and_never_uses_proxy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that _request() rejects non-JSON responses and that the
        opener is built with ProxyHandler (no proxy) and _NoRedirect."""

        class Response:
            headers = {"Content-Type": "text/plain"}

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: object) -> bool:
                return False

            def read(self, amount: int) -> bytes:
                return b"not-json"

        seen: list = []

        class Opener:
            def open(self, request: object, timeout: object = None) -> Response:
                return Response()

        def fake_build_opener(*handlers: object) -> Opener:
            seen.extend(handlers)
            return Opener()

        monkeypatch.setattr(runtime.urllib.request, "build_opener", fake_build_opener)
        with pytest.raises(HTTPException, match="UPSTREAM_SCHEMA_INVALID"):
            runtime._request("https://provider.example.test/api", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "hidden", "ca_file": None}, [0])
        assert any(isinstance(h, runtime.urllib.request.ProxyHandler) for h in seen)
        assert any(isinstance(h, runtime._NoRedirect) for h in seen)

    def test_request_http_error_404_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """allow_not_found=True returns None on HTTP 404."""

        def fake_open(*args: object, **kwargs: object) -> object:
            class FakeHTTPError(urllib.error.HTTPError):
                def __init__(self) -> None:
                    pass
            exc = FakeHTTPError()
            exc.code = 404
            raise exc

        # We need to make build_opener return an opener that raises HTTPError(404)
        class Opener:
            def open(self, request: object, timeout: object = None) -> object:
                raise urllib.error.HTTPError(
                    "http://example.test", 404, "Not Found", {}, None,
                )

        def fake_build_opener(*handlers: object) -> Opener:
            return Opener()

        monkeypatch.setattr(runtime.urllib.request, "build_opener", fake_build_opener)
        # monkeypatch ssl too to avoid CA file issues
        result = runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                                  {"authorization": "tok", "ca_file": None}, [0], allow_not_found=True)
        assert result is None

    def test_request_http_error_401_raises_auth_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Opener:
            def open(self, request: object, timeout: object = None) -> object:
                raise urllib.error.HTTPError(
                    "http://example.test", 401, "Unauthorized", {}, None,
                )

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())
        with pytest.raises(HTTPException, match="AUTH_FAILED"):
            runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "tok", "ca_file": None}, [0])

    def test_request_http_error_403_raises_auth_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Opener:
            def open(self, request: object, timeout: object = None) -> object:
                raise urllib.error.HTTPError(
                    "http://example.test", 403, "Forbidden", {}, None,
                )

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())
        with pytest.raises(HTTPException, match="AUTH_FAILED"):
            runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "tok", "ca_file": None}, [0])

    def test_request_http_redirect_raises_upstream_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """300-range codes produce UPSTREAM_UNAVAILABLE."""

        class Opener:
            def open(self, request: object, timeout: object = None) -> object:
                raise urllib.error.HTTPError(
                    "http://example.test", 302, "Found", {}, None,
                )

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())
        with pytest.raises(HTTPException, match="UPSTREAM_UNAVAILABLE"):
            runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "tok", "ca_file": None}, [0])

    def test_request_oserror_raises_upstream_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Opener:
            def open(self, request: object, timeout: object = None) -> object:
                raise OSError("connection refused")

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())
        with pytest.raises(HTTPException, match="UPSTREAM_UNAVAILABLE"):
            runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "tok", "ca_file": None}, [0])

    def test_request_max_requests_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "MAX_REQUESTS", 1)
        requests = [0]  # shared mutable list so both calls share the counter

        class Response:
            headers = {"Content-Type": "application/json"}

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: object) -> bool:
                return False

            def read(self, amount: int) -> bytes:
                return b'{"data": "ok"}'

        class Opener:
            def open(self, request: object, timeout: object = None) -> Response:
                return Response()

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())
        # First call consumes the only slot (requests[0] goes 0 -> 1)
        runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                         {"authorization": "tok", "ca_file": None}, requests)
        # Second call sees requests[0] == MAX_REQUESTS, should fail
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime._request("https://provider.example.test", "GET", "/nodes/n1/qemu/100/config",
                             {"authorization": "tok", "ca_file": None}, requests)

    def test_request_body_size_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "MAX_REQUEST_BODY_BYTES", 10)
        with pytest.raises(HTTPException, match="POLICY_DENIED"):
            runtime._request("https://provider.example.test", "POST", "/nodes/n1/qemu",
                             {"authorization": "tok", "ca_file": None}, [0],
                             body={"very_long_key": "x" * 100})


# ===================================================================
# 8. current() -- integration-style via mocked transport
# ===================================================================


class TestCurrent:

    def test_current_vm_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _credential_root(tmp_path, monkeypatch)
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)

        class Opener:
            idx = 0
            responses = [
                None,  # 404 -> VM absent
            ]

            def open(self, request: object, timeout: object = None) -> object:
                self.idx += 1
                raise urllib.error.HTTPError(
                    "http://example.test", 404, "Not Found", {}, None,
                )

        monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *h: Opener())

        state, cred = runtime.current(
            _provider(),
            {"vm_id": 100, "node": "node-a", "target_state": "stopped"},
            "vm.power",
        )
        assert state["present"] is False
        assert state["vm_id"] == 100
        assert state["node"] == "node-a"


# ===================================================================
# 9. enforce_current_policy()
# ===================================================================


class TestEnforceCurrentPolicy:

    def test_enforce_current_policy_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        state = _current_state(power_state="stopped")
        # Should not raise
        runtime.enforce_current_policy(
            _provider(), state,
            {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100},
            "vm.delete",
        )

    def test_enforce_current_policy_vm_running(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(runtime, "RUNTIME_ENABLED", True)
        state = _current_state(power_state="running")
        with pytest.raises(HTTPException, match="VM_MUST_BE_STOPPED"):
            runtime.enforce_current_policy(
                _provider(), state,
                {"vm_id": 100, "node": "node-a", "confirm_vm_id": 100},
                "vm.delete",
            )


# ===================================================================
# 10. _int() helper
# ===================================================================


class TestIntHelper:

    def test_int_valid(self) -> None:
        assert runtime._int(42, low=0, high=100, field="test") == 42

    def test_int_below_low(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_TEST"):
            runtime._int(-1, low=0, high=100, field="test")

    def test_int_above_high(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_TEST"):
            runtime._int(200, low=0, high=100, field="test")

    def test_int_not_int(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_TEST"):
            runtime._int("42", low=0, high=100, field="test")

    def test_int_bool_rejected(self) -> None:
        with pytest.raises(HTTPException, match="INVALID_TEST"):
            runtime._int(True, low=0, high=100, field="test")