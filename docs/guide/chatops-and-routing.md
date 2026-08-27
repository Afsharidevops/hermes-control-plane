# ChatOps and AI Routing

## ChatOps authority model

| Authority | Scope |
|---|---|
| Web UI / Control Plane admin token | Environments, integration/target metadata, credential references, discovery, ChangeSet inspection, and audit. It cannot create, preview, approve, roll back, or execute Kubernetes/Helm mutation ChangeSets. |
| Hermes Bot service identity | Creates/previews permitted Kubernetes and Helm mutation ChangeSets, requests approval, creates rollback plans, and executes an already-approved exact hash. |
| Approval Bot service identity | Approves/rejects HIGH and CRITICAL mutation ChangeSets for the exact current plan hash. |
| Kubernetes Broker | Reads kubeconfig material and accepts only signed execution tickets from Control Plane. |

The main plugin fails closed unless an interactive Telegram session belongs to an allowlisted numeric user. The Approval Bot's service-identity/API boundary is enforced, but **Telegram Approval Bot transport wiring remains a beta.1 integration task**. Do not document it as an active Telegram approval channel.

## Configure Hermes Bot

```bash
./hermesctl init
./hermesctl bot telegram
./hermesctl bot allow <numeric-telegram-user-id>
./hermesctl up
./hermesctl bot check
```

`bot telegram` reads the token through hidden terminal input. `bot allow` updates the Telegram gateway and mutation allowlists. Keep tokens and kubeconfigs out of Telegram. Only the long-running `hermes` service polls Telegram; a Telegram HTTP 409 `getUpdates` conflict indicates an accidental second poller/deployment conflict.

### ChatOps tools

The mounted `control-plane-chatops` plugin exposes:

```text
hcp_list_targets
hcp_get_changeset
hcp_plan_kubernetes
hcp_plan_helm
hcp_request_approval
hcp_execute_changeset
hcp_plan_rollback
```

The plugin has the Hermes Bot token only. It has no broker signing key, kubeconfig, or Approval Bot token. Execution requires a previously approved exact plan hash; it cannot convert a chat message into an arbitrary executor instruction.

## Smart Router

**Runtime-complete:** Smart Router is an authenticated OpenAI-compatible proxy and Operations Center. Its source package reports `0.5.9`; this repository/release context is `0.5.11`. Router Gateway source reports `0.5.11-dev.1`. Treat the deployed image tag and endpoint health as authoritative rather than assuming all internal modules share a version.

### Public endpoints

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness/status. |
| `GET` | `/ready` | Readiness/dependencies. |
| `GET` | `/metrics` | Metrics endpoint; restrict network access. |
| `GET` | `/router/info` | Router identity/capabilities. |
| `GET` | `/router/policy` | Active routing policy information. |
| `GET` | `/dashboard` | Dashboard UI. |
| `GET` | `/dashboard/api/summary` | Summary data. |
| `GET` | `/dashboard/api/traces` | Safe trace summaries. |
| `GET` | `/dashboard/api/traces/{request_id}` | One trace detail subject to access controls. |
| `GET` | `/v1/models` | OpenAI-compatible model list. |
| `POST` | `/v1/chat/completions` | OpenAI-compatible request routing. |
| mounted | `/control` | Operations Center UI/API. |

Use a Smart Router client key for model traffic and a separate admin key/local authenticated administrator for administration. Do not expose the control UI or metrics endpoint publicly without TLS, authentication, and network controls.

### Routing profiles and modes

| Profile | Default behavior |
|---|---|
| `fast` | `combo-fast` target tier. |
| `standard` | `combo-standard` target tier. |
| `strong` | `combo-strong` target tier. |
| `coding` | Strong tier unless separately configured. |
| `vision` | Strong tier unless separately configured. |

`auto` is the neutral automatic-routing alias. When `SMART_ROUTER_ALLOW_TIER_OVERRIDES=true`, `auto-fast`, `auto-standard`, and `auto-strong` are also available.

- `SMART_ROUTER_MODE=observe` (default) calculates/records the route decision but forwards with `SMART_ROUTER_OBSERVE_MODEL`.
- `SMART_ROUTER_MODE=route` applies selected tier/profile/model routing.
- `SMART_ROUTER_POLICY=heuristic` is the default. Calibrated/learned behavior must fall back safely if confidence, artifact compatibility, or policy checks fail.

Routing layers include client identity/authentication, guardrails, rate/token/daily and budget controls, RAG/memory injection, profile/capability/context analysis, sticky sessions, policy and virtual-key limits, provider health/circuit breaking/fallback/retry, and output budget handling.

### Control navigation

| Group | Pages |
|---|---|
| Observe | Overview, Traces, Provider Health, Audit |
| Build | Workflows, Agents, Knowledge Pipelines, Knowledge, Memory, Teams, Prompts, Evaluations, Publish & Monitor |
| Tools | Skills, Plugins, Marketplace |
| Routing | Routing, Router Pipelines, Providers, Model Catalog, Policies, Guardrails, Budgets |
| Access | Users & Keys, Groups, ACLs, Identity |
| System | Execution & Approvals, Onboarding, Docs, System |

The visual Workflow, Agent, Knowledge Pipeline, and Router Pipeline studios support typed ports, valid/invalid connection feedback, keyboard connections, edge inspection/deletion/reconnection, quick-add, undo/redo, pan/zoom/fit, themes, and dirty/saving/saved/failed save status. Graph validation rejects unknown/duplicate IDs, invalid/incompatible ports, self/duplicate connections, and cycles.

### Access control, guardrails, knowledge, and learning

- Roles: `super_admin`, `admin`, `operator`, `analyst`, `approver`, `agent`, `user`, `read_only`.
- Local credentials use scrypt; sessions are HMAC signed/revocable. Virtual API keys use `srk_`, are stored hashed, and are shown once at creation.
- OIDC supports discovery, code flow, state/nonce/JWKS/token validation, group-role mapping, auto-provisioning, and optional local-login disablement. LDAP/SAML/SCIM signals are readiness/foundation, not confirmed production integrations.
- ACL subjects are `user`, `role`, `group`, `team`, `agent`, and `virtual_key`; explicit deny wins. `SMART_ROUTER_ACL_DEFAULT_DENY=true` denies unmatched access. ACL filtering applies to knowledge retrieval/injection.
- Guardrails run in `off`, `audit` (default), or `enforce` mode. They detect injection, likely PII, content/tool risks, and custom rules. PII is a finding and is not always a block reason.
- RAG chunking is 1,800 characters with 220 overlap; modes are `lexical`, `vector`, `hybrid` (default). Hybrid weights are lexical `0.42`, vector `0.48`, rerank `0.10`. Hash embedding fallback is deterministic but is not equivalent to semantic retrieval. Persistent-memory scopes are user, agent, project, organization, and team.
- Learned routing uses privacy-safe request-shape features, not raw request content. It falls back to deterministic routing on low confidence/corrupt/incompatible model state. Training requires at least nine rows, all three tier labels, and two samples per tier.

## Router Gateway

Router Gateway selects `nine-router` or `omniroute`, persists active choice in `/data/router.json`, translates neutral aliases only, and preserves raw streaming response bytes. Explicit upstream model IDs pass through unchanged. An unreachable active provider yields `502`; responses include `x-hermes-router-provider`.

| Method | Route | Authentication |
|---|---|---|
| `GET` | `/health` | Health only. |
| `GET` | `/management/providers` | `ROUTER_GATEWAY_ADMIN_TOKEN`. |
| `PUT` | `/management/router` | `ROUTER_GATEWAY_ADMIN_TOKEN`; body selects provider. |
| all listed verbs | `/v1/{path}` | Routed upstream request; managed credential can replace upstream authorization. |

| Hermes alias | Nine Router | OmniRoute |
|---|---|---|
| `hermes/observe` | `ai` | `auto/best-chat` |
| `hermes/fast` | `combo-fast` | `auto/best-fast` |
| `hermes/standard` | `combo-standard` | `auto/best-chat` |
| `hermes/strong` | `combo-strong` | `auto/best-reasoning` |
| `hermes/coding` | `combo-strong` | `auto/best-coding` |
| `hermes/vision` | `combo-strong` | `auto/best-vision` |

`hermesctl up` provisions/reuses the selected provider's dedicated runtime key through upstream management APIs and stores it only in private local `.env`. `router probe` checks client auth, gateway management, key validity, and a real streamed chat completion without printing credentials.
