# Local 0.5.10 stable-candidate evidence

- Source anchor before hardening: `4214f4322eb0e2e348ade53db6bfa172a76d3b45` (`v0.5.10-rc.1`, immutable).
- Target version in this package: `0.5.10`.
- Final local stable source gate: PASS on 2026-08-17 UTC.
- Control Plane tests: 27 PASS.
- Kubernetes Broker tests: 18 PASS.
- Dedicated Telegram approval tests: 2 PASS.
- Full Smart Router regression suite: PASS.
- Stable source security/static deployment gate: PASS.
- Python compile and shell syntax gates: PASS.
- Docker/Helm/kubectl are not installed in this execution environment, so clean runtime installs, published candidate image inspection, live Docker->Kubernetes migration and published-version upgrade/rollback remain external promotion gates.

The official `v0.5.10` tag must not be created from a different source commit than the one that passes those external gates.
