# Bot-only beta.1 R5 — Hermes model routing

R5 fixes the provider-authentication failure that occurred before Telegram
ChatOps could call any Control Plane tool.

- Hermes main-model traffic is routed to `http://smart-router:8080/v1`.
- `SMART_ROUTER_CLIENT_API_KEY` is supplied as process `OPENAI_API_KEY`.
- Hermes `config.yaml` is synchronized to provider `custom`, model `auto`,
  Smart Router base URL, and `chat_completions`.
- The Smart Router client key is not persisted into `config.yaml`.
- Existing `config.yaml` is backed up before model changes.
- `./hermesctl router probe` verifies Smart Router client authentication.
- `./hermesctl bot model-sync` repairs persisted Hermes model settings.
- `./hermesctl bot check` uses the non-truncating plugin list.
- Kubernetes/Helm execution remains disabled by default.
