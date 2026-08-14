# Bot-only beta.1 R2

R2 restores the Docker/Compose Kubernetes Broker UID/GID mapping required to
read locally imported kubeconfigs without weakening their `0600` permissions.

`./hermesctl init` now fills:

- `HERMES_KUBERNETES_BROKER_UID`
- `HERMES_KUBERNETES_BROKER_GID`

from the local operator when those values are missing. `./hermesctl doctor`
also checks the mapping.

Kubernetes and Helm mutation remains bot-only.
