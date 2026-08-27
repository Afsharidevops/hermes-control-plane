# Proxmox VM Runtime Validation

## Purpose and evidence boundary

This is an operator-only runbook for validating the narrow, disabled-by-default Proxmox QEMU mutation runtime on a **disposable** Proxmox target. It is not an authorization to use production workloads, and it does not establish LIVE evidence by itself.

Do not claim a real-provider result until an operator has run this procedure at the exact pushed candidate SHA and retained sanitized evidence tied to that SHA. Automated tests and CI use mocks only. No action in this runtime performs automatic rollback; remediation or cleanup always requires a new governed action.

## Scope

The runtime is pinned to:

- API version: `pve-8.2`
- implementation version: `pve-vm-runtime-v1`

Only QEMU VMs are supported. LXC mutation is unsupported. The only permitted actions are:

- `vm.create`
- `vm.clone`
- `vm.update`
- `vm.delete`
- `vm.power`
- `network.attach`
- `snapshot.create`
- `snapshot.restore`

`vm.delete` and `snapshot.restore` are CRITICAL and require two distinct approvals. The other six actions are HIGH and require approval. Capacity-backed Cluster Factory lifecycle remains out of scope: do not use this runtime to allocate servers, create/destroy/scale clusters, clone capacity-backed templates, or perform provider recreation/DR.

## Preconditions

1. Start from a clean checkout at the exact candidate SHA. Record `git rev-parse HEAD` in the evidence bundle.
2. Use an isolated Proxmox node, one disposable QEMU template, an unused VM-ID range, a dedicated test storage, and a dedicated test bridge. Do not include production nodes, storage, bridges, templates, or VM IDs in any allowlist.
3. Create a least-privilege Proxmox API token limited to the selected node, test VM IDs, storage, bridge, template, and the fixed QEMU actions required for this run. Do not use a root token.
4. Mount the token only into the Node Agent's worker credential root as `<credential-ref>/profile.json`. Protect the mount read-only; never place the token in a plan, UI field, environment dump, logs, audit evidence, or this runbook.
5. Register a dedicated provider using only the exact endpoint `https://<host>:8006/api2/json`, the required pins, and a narrow capability snapshot:
   - `profile: pve-vm-runtime-v1`
   - exact `node_allowlist`, `storage_allowlist`, `bridge_allowlist`, and `{node, vm_id}` template allowlist
   - tight VM-ID, CPU, memory, disk, NIC, and snapshot bounds
   - only the action currently being tested in `action_allowlist`
   - `allow_vm_delete` and `allow_snapshot_restore` false unless individually exercising those actions
6. Enable both gates only in the isolated validation deployment:
   - `HERMES_INFRASTRUCTURE_EXECUTION_ENABLED=true`
   - `HERMES_PROXMOX_VM_RUNTIME_ENABLED=true`

Keep all other environments disabled. Confirm Node Agent health advertises `proxmox-vm-runtime-v1` only after both feature gates are enabled.

## Controlled action validation

For every action below, create an intent, inspect the typed plan and sanitized active preview, request the required approval(s), authorize once, execute once, and retain only sanitized ChangeSet/job/verification identifiers and hashes. Confirm the final verification is PASS before proceeding. Do not collect raw PVE bodies, URLs, headers, task tokens, profile paths, or credentials.

1. **`vm.create`** — create one new QEMU VM with the smallest permitted CPU, memory, disk, test storage, and optional test bridge. Re-plan the identical state to confirm idempotency/no-op behavior.
2. **`vm.clone`** — full-clone the allowlisted disposable template into a new allowlisted test VM ID and storage. Confirm a non-allowlisted source template is rejected before worker contact.
3. **`vm.update`** — change only allowed CPU, memory, and/or `onboot`. Confirm an attempt to submit any QEMU argument, Cloud-Init payload, PCI/USB passthrough, script, arbitrary field, or raw configuration is rejected.
4. **`vm.power`** — start the disposable VM, then gracefully stop it. Confirm each final observed power state matches the approved desired state.
5. **`network.attach`** — attach one permitted `net0`–`net7` slot to the allowlisted test bridge. Confirm caller-provided MAC/IP fields are rejected and not present in evidence.
6. **`snapshot.create`** — create a bounded safe snapshot name. Confirm the final state shows only sanitized snapshot presence.
7. **`snapshot.restore`** — stop the test VM first, enable only `snapshot.restore` and `allow_snapshot_restore=true`, then submit exact VM-ID and snapshot-name confirmations. Obtain two distinct approvals. Confirm restore on a running VM, an incorrect confirmation, or a disabled destructive flag is rejected.
8. **`vm.delete`** — stop the disposable VM first, enable only `vm.delete` and `allow_vm_delete=true`, submit exact VM-ID confirmation, and obtain two distinct approvals. Confirm deletion of a running VM and a mismatched confirmation are rejected. Verify absence after task completion.

## Required negative and safety checks

Run and record sanitized outcomes for each check:

- **Feature gating:** with either feature flag false, Proxmox execution is unavailable.
- **Capability denial:** an operation absent from `action_allowlist`, an unallowlisted node/storage/bridge/template, or an out-of-range resource is rejected before mutation.
- **Drift rejection:** plan a harmless change, alter the target state outside Hermes, then try to execute the original approved plan. It must reject on current-hash drift before any mutation.
- **Replay rejection:** attempt the same execution ticket a second time. It must be rejected without another PVE mutation.
- **Approval enforcement:** verify HIGH actions cannot execute before approval; verify delete/restore remain blocked after one approval and execute only after two distinct approvals.
- **Fixed transport:** validate rejected endpoint variants including HTTP, non-8006 ports, alternate paths, query/fragment/userinfo, redirects, and ambient proxy use.
- **Redaction:** inspect response, audit, job, and verification records for absence of credentials, API tokens, raw PVE response bodies, raw request bodies, headers, task tokens, MAC/IP addresses, and arbitrary shell/CLI data.
- **No uncertain auto-retry:** simulate or observe a safe transport ambiguity only in the disposable environment. Confirm the ticket is consumed, the result requires reconciliation, and no mutation is automatically retried or compensated.

## Evidence and cleanup

Retain a sanitized bundle containing the exact candidate SHA, test date, runtime pins, feature-gate state, provider capability snapshot hash, ChangeSet/plan/ticket hashes, approval counts, preview/current hashes, final PASS verification summaries, and negative-test outcomes. Exclude credentials, endpoints, token identifiers, raw PVE payloads, raw task IDs, VM names that identify production, and environment dumps.

After validation, remove all disposable VMs and snapshots through new governed actions, revoke the temporary API token, remove its mounted credential profile, disable both execution gates, and remove the dedicated provider registration. These cleanup steps must also preserve governance and must not be treated as automatic rollback.
