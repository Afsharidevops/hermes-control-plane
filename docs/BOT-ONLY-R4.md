# Bot-only beta.1 R4 — single Telegram poller

R4 fixes a Telegram polling conflict introduced by the ChatOps plugin enable
helper.

Previously `docker compose run hermes plugins enable ...` used the Hermes image's
normal s6 entrypoint. That transient container started its own gateway and
Telegram `getUpdates` poller before running the CLI command. The real Hermes
container then connected with the same token, producing Telegram HTTP 409
"terminated by other getUpdates request".

R4 runs administrative Hermes CLI commands with:

`--entrypoint /opt/hermes/.venv/bin/hermes`

and clears Telegram credentials from that one-off CLI container. Therefore only
the long-running `hermes` service owns Telegram polling.

`./hermesctl bot check` also validates plugin discovery/enabled state more
explicitly.
