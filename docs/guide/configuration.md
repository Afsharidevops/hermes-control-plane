# Configuration Reference

Copy `.env.example` to `.env`, run `./hermesctl init`, and keep `.env` private. This page covers all declared Compose variables. **Secret** means a value must be generated/stored privately. **Sensitive** means it reveals topology, credential-file location, or trust boundary and should not be published. All other settings still require change control.

## Image, router, and listener settings

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `IMAGE_NAMESPACE`, `VERSION` | Sensitive | Hermes image registry namespace and approved release tag. Pin a reviewed tag. |
| `HERMES_ROUTER_PROVIDER` | Normal | Active upstream: `nine-router` or `omniroute`. |
| `HERMES_ENABLE_BOTH_ROUTERS` | Normal | Starts both router profiles only when explicitly true. |
| `CONTROL_PLANE_BIND_IP`, `CONTROL_PLANE_PORT` | Sensitive | Control Plane listener; retain loopback/private binding. |
| `ROUTER_GATEWAY_BIND_IP`, `ROUTER_GATEWAY_PORT` | Sensitive | Router Gateway listener. |
| `SMART_ROUTER_BIND_IP`, `SMART_ROUTER_PORT` | Sensitive | Smart Router listener. |
| `HERMES_BIND_IP`, `HERMES_API_PORT`, `HERMES_DASHBOARD_PORT` | Sensitive | Optional Hermes agent listeners. |
| `KUBERNETES_BROKER_BIND_IP`, `KUBERNETES_BROKER_PORT` | Sensitive | Kubernetes Broker listener. |
| `CREDENTIAL_SERVICE_BIND_IP`, `CREDENTIAL_SERVICE_PORT` | Sensitive | Credential Service listener; restrict exposure. |

## Hermes service identities and encryption

All values in this table are **Secret**. `hermesctl init` creates valid local defaults where supported. Do not share a main bot token with the separate approval identity.

| Variables | Purpose |
|---|---|
| `HERMES_CONTROL_ADMIN_TOKEN` | Browser/API administrative management identity. |
| `HERMES_BOT_SERVICE_TOKEN` | Hermes Bot-only Kubernetes/Helm planning/execution identity. |
| `HERMES_APPROVAL_BOT_TOKEN`, `HERMES_APPROVAL_HMAC_KEY` | Separate approval decision identity and integrity key. |
| `HERMES_AGENT_TASK_HMAC_KEY` | Signs enrolled agent task envelopes. |
| `HERMES_CREDENTIAL_ADMIN_TOKEN`, `HERMES_CREDENTIAL_SERVICE_TOKEN` | Credential Service operator identity and narrow metadata-sync identity. |
| `HERMES_CREDENTIAL_MASTER_KEY`, `HERMES_CREDENTIAL_MASTER_KEY_VERSION` | Fernet-compatible local credential encryption key and key version. |
| `HERMES_KUBERNETES_BROKER_TOKEN` | Control Plane-to-Broker service authentication. |
| `HERMES_EXECUTION_HMAC_KEY` | Signs/validates constrained execution tickets. |
| `HERMES_PROVIDER_WORKER_TOKEN` | Control Plane-to-Node Agent authentication. |
| `ROUTER_GATEWAY_ADMIN_TOKEN` | Router Gateway management authentication. |
| `SMART_ROUTER_HMAC_SECRET`, `SMART_ROUTER_CLIENT_API_KEY`, `SMART_ROUTER_ADMIN_API_KEY` | Smart Router sessions/signatures, client API, and administration. |
| `SMART_ROUTER_BOOTSTRAP_ADMIN_USER`, `SMART_ROUTER_BOOTSTRAP_ADMIN_PASSWORD` | Initial Smart Router local administrator; username is sensitive, password secret. |

## Provider and infrastructure worker settings

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `HERMES_PROVIDER_EXECUTION_ENABLED` | Gate | Enables existing-host provider executor; default false. |
| `HERMES_PROVIDER_COMMAND_TIMEOUT` | Normal | Maximum provider command duration. |
| `HERMES_PROVIDER_SSH_PROFILE_HOST_PATH` | Sensitive | Read-only host path containing sealed SSH profiles. |
| `HERMES_INFRASTRUCTURE_EXECUTION_ENABLED` | Gate | Enables Node Agent infrastructure mutations; default false. |
| `HERMES_INFRASTRUCTURE_CREDENTIAL_HOST_PATH` | Sensitive | Read-only host path for worker-only infrastructure credentials. |
| `HERMES_INFRASTRUCTURE_ALLOW_HTTP` | Gate | Allows non-TLS infrastructure transport; retain false. |
| `HERMES_INFRASTRUCTURE_REQUEST_TIMEOUT_SECONDS`, `HERMES_INFRASTRUCTURE_IPMI_TIMEOUT_SECONDS` | Normal | Bounded request timeouts. |
| `HERMES_INFRASTRUCTURE_VERIFY_ATTEMPTS`, `HERMES_INFRASTRUCTURE_VERIFY_DELAY_SECONDS` | Normal | General active-verification retry ceiling. |
| `HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_ATTEMPTS`, `HERMES_INFRASTRUCTURE_FIRMWARE_VERIFY_DELAY_SECONDS` | Normal | Firmware verification ceiling. |
| `HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_ATTEMPTS`, `HERMES_INFRASTRUCTURE_PLATFORM_VERIFY_DELAY_SECONDS` | Normal | Platform-change verification ceiling. |

## Proxmox collectors and QEMU runtime

| Variables | Class | Purpose / safety effect |
|---|---|---|
| `HERMES_CAPACITY_COLLECTION_ENABLED` | Gate | Enables read-only capacity collection; default false. |
| `HERMES_CAPACITY_REQUEST_TIMEOUT_SECONDS`, `HERMES_CAPACITY_MAX_RESPONSE_BYTES`, `HERMES_CAPACITY_MAX_REQUESTS`, `HERMES_CAPACITY_WORKER_TIMEOUT_SECONDS` | Normal | Capacity request/response/work limits. |
| `HERMES_VM_INVENTORY_COLLECTION_ENABLED` | Gate | Enables read-only VM identity/power-state collection; default false. |
| `HERMES_VM_INVENTORY_REQUEST_TIMEOUT_SECONDS`, `HERMES_VM_INVENTORY_MAX_RESPONSE_BYTES`, `HERMES_VM_INVENTORY_WORKER_TIMEOUT_SECONDS` | Normal | Inventory bounds. |
| `HERMES_PROXMOX_VM_RUNTIME_ENABLED` | Gate | Enables bounded QEMU mutation runtime; default false. |
| `HERMES_PROXMOX_VM_REQUEST_TIMEOUT_SECONDS`, `HERMES_PROXMOX_VM_MAX_RESPONSE_BYTES`, `HERMES_PROXMOX_VM_MAX_REQUEST_BODY_BYTES`, `HERMES_PROXMOX_VM_MAX_REQUESTS_PER_EXECUTION` | Normal | Transport/request ceilings. |
| `HERMES_PROXMOX_VM_TASK_POLL_ATTEMPTS`, `HERMES_PROXMOX_VM_TASK_POLL_DELAY_SECONDS`, `HERMES_PROXMOX_VM_VERIFY_ATTEMPTS`, `HERMES_PROXMOX_VM_VERIFY_DELAY_SECONDS` | Normal | Task polling and active verification bounds. |

These features are **Integration/local evidence**; see [Infrastructure providers](infrastructure-providers.md).

## Offline provider sources and artifact mirroring

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `HERMES_PROVIDER_FILES_REPO_URL`, `HERMES_PROVIDER_APT_REPO_URL`, `HERMES_PROVIDER_RPM_REPO_URL`, `HERMES_PROVIDER_PYPI_URL` | Sensitive | Explicit offline package/source repositories for provider work. |
| `HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST` | Gate | Comma-separated exact HTTPS source hosts; empty disables network HTTPS fetch. |
| `HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST`, `HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST` | Gate | Exact OCI source/destination registry hosts; empty disables OCI mirroring. |
| `HERMES_ARTIFACT_AUTH_HOST_PATH` | Sensitive | Host root mounted read-only for artifact authentication material. |
| `HERMES_ARTIFACT_HTTPS_AUTHFILE`, `HERMES_ARTIFACT_REPOSITORY_KEYRING`, `HERMES_ARTIFACT_OCI_SOURCE_AUTHFILE`, `HERMES_ARTIFACT_OCI_DESTINATION_AUTHFILE` | Sensitive | Absolute container paths under the dedicated artifact-secret mount. |
| `HERMES_ARTIFACT_MIRROR_MAX_BYTES`, `HERMES_ARTIFACT_MIRROR_TIMEOUT_SECONDS` | Normal | Per-transfer byte and time ceilings. |
| `HERMES_ARTIFACT_REPOSITORY_MAX_EXPANDED_BYTES`, `HERMES_ARTIFACT_REPOSITORY_METADATA_MAX_BYTES` | Normal | Repository snapshot expansion/metadata ceilings. |

## Smart Router policy and model aliases

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `SMART_ROUTER_MODE` | Gate | `observe` records a decision but forwards `SMART_ROUTER_OBSERVE_MODEL`; `route` selects tiers. |
| `SMART_ROUTER_POLICY` | Normal | Routing policy, normally `heuristic`. |
| `SMART_ROUTER_OBSERVE_MODEL` | Normal | Alias/model used in observe mode. |
| `SMART_ROUTER_FAST_MODEL`, `SMART_ROUTER_STANDARD_MODEL`, `SMART_ROUTER_STRONG_MODEL` | Normal | Tier aliases/models. |
| `SMART_ROUTER_CODING_MODEL`, `SMART_ROUTER_VISION_MODEL` | Normal | Coding and vision profile aliases/models. |

## Nine Router upstream

| Variables | Class | Purpose / safety effect |
|---|---|---|
| `NINEROUTER_IMAGE_REPOSITORY`, `NINEROUTER_IMAGE_TAG` | Sensitive | Upstream image selection; pin production images. |
| `NINEROUTER_BIND_IP`, `NINEROUTER_PORT`, `NINEROUTER_PUBLIC_BASE_URL`, `NINEROUTER_PROVISION_HOST` | Sensitive | Listener/public/provision topology. |
| `NINEROUTER_INITIAL_PASSWORD`, `NINEROUTER_JWT_SECRET`, `NINEROUTER_API_KEY_SECRET`, `NINEROUTER_MACHINE_ID_SALT` | Secret | Upstream bootstrap/authentication secrets. |
| `NINEROUTER_REQUIRE_API_KEY`, `NINEROUTER_AUTH_COOKIE_SECURE` | Gate | Require upstream authentication and secure cookies in TLS deployments. |
| `NINEROUTER_AUTO_PROVISION_API_KEY`, `NINEROUTER_MANAGED_API_KEY_NAME` | Normal | Managed Router Gateway runtime key lifecycle. |
| `NINEROUTER_AUTO_PROVISION_COMBOS`, `NINEROUTER_OPENCODE_CATALOG_URL` | Sensitive | Reconcile managed model combinations/catalog source. |
| `NINE_ROUTER_UPSTREAM_API_KEY` | Secret | Managed runtime key; leave lifecycle to `hermesctl`. |

## OmniRoute upstream

| Variables | Class | Purpose / safety effect |
|---|---|---|
| `OMNIROUTE_IMAGE_REPOSITORY`, `OMNIROUTE_IMAGE_TAG` | Sensitive | Upstream image selection. |
| `OMNIROUTE_BIND_IP`, `OMNIROUTE_PORT`, `OMNIROUTE_API_BIND_IP`, `OMNIROUTE_API_PORT`, `OMNIROUTE_PUBLIC_BASE_URL`, `OMNIROUTE_PROVISION_HOST` | Sensitive | Dashboard/API listener and topology. |
| `OMNIROUTE_INITIAL_PASSWORD`, `OMNIROUTE_JWT_SECRET`, `OMNIROUTE_API_KEY_SECRET`, `OMNIROUTE_MANAGEMENT_API_KEY` | Secret | Bootstrap and management credentials. |
| `OMNIROUTE_STORAGE_ENCRYPTION_KEY`, `OMNIROUTE_STORAGE_ENCRYPTION_KEY_VERSION`, `OMNIROUTE_MACHINE_ID_SALT`, `OMNIROUTE_WS_BRIDGE_SECRET` | Secret | Storage/session/device identity secrets. |
| `OMNIROUTE_REQUIRE_API_KEY`, `OMNIROUTE_AUTH_COOKIE_SECURE`, `OMNIROUTE_ALLOW_API_KEY_REVEAL` | Gate | Upstream authentication, TLS cookie, and key-display control. |
| `OMNIROUTE_MEMORY_MB` | Normal | Container memory setting. |
| `OMNIROUTE_AUTO_PROVISION_API_KEY`, `OMNIROUTE_MANAGED_API_KEY_NAME` | Normal | Router Gateway key lifecycle. |
| `OMNIROUTE_UPSTREAM_API_KEY` | Secret | Managed non-management runtime key; do not populate manually. |

## Optional Hermes agent and Telegram

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `HERMES_IMAGE_REPOSITORY`, `HERMES_IMAGE_TAG` | Sensitive | Optional agent image. |
| `HERMES_DASHBOARD`, `HERMES_UID`, `HERMES_GID`, `HERMES_MODEL` | Normal | Agent dashboard, filesystem identity, and Smart Router alias. |
| `TELEGRAM_BOT_TOKEN` | Secret | Telegram transport credential; configure locally through `hermesctl bot telegram`. |
| `TELEGRAM_ALLOWED_USERS`, `HERMES_CONTROL_PLANE_BOT_USERS` | Sensitive | Numeric allowlists; narrow to authorized operators. |

## Global execution and Kubernetes tooling

| Variable | Class | Purpose / safety effect |
|---|---|---|
| `EXECUTION_FEATURES` | Gate | Compatibility/feature expression; keep empty unless a reviewed deployment requires it. |
| `HERMES_EXECUTION_ENABLED` | Gate | Global execution master gate; default false. |
| `HERMES_KUBERNETES_EXECUTION_ENABLED` | Gate | Kubernetes Broker execution gate; default false. |
| `HERMES_KUBERNETES_COMMAND_TIMEOUT` | Normal | Kubernetes command deadline. |
| `HERMES_KUBERNETES_BROKER_UID`, `HERMES_KUBERNETES_BROKER_GID` | Sensitive | Local UID/GID needed to read private imported kubeconfigs. |
| `HERMES_HEALTH_TIMEOUT_SECONDS` | Normal | Control Plane integration health probe timeout. |
| `KUBECTL_V1_33`, `KUBECTL_V1_34`, `KUBECTL_V1_35`, `KUBECTL_V1_36` | Normal | Build-time kubectl patch versions bundled for supported target minors. |
| `KUBECTL_BOOTSTRAP_MINOR` | Normal | Default broker kubectl minor at image build. |
| `HERMES_DYNAMIC_KUBECTL_ENABLED`, `HERMES_KUBECTL_SELECTION_MODE`, `HERMES_KUBECTL_CACHE_TTL_SECONDS` | Normal | Dynamic target-version selection and discovery cache behavior. |

After any environment change, run `docker compose config`, restart only the affected services, verify health, and test read-only behavior before enabling execution. See [Docker deployment](deployment-docker.md) and [Operations runbook](operations-runbook.md).
