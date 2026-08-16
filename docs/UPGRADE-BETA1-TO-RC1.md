# Upgrade validation: v0.5.10-beta.1 to v0.5.10-rc.1

This document describes the release-candidate upgrade acceptance path. `v0.5.10-beta.1` is immutable release history.

## Required safety state

Keep infrastructure execution disabled before and after the upgrade unless a separate disposable-cluster execution test is intentionally running:

```text
HERMES_EXECUTION_ENABLED=false
HERMES_KUBERNETES_EXECUTION_ENABLED=false
```

## Source and state model

The installation directory contains both release source/configuration and persistent runtime state. Upgrade acceptance therefore tests the new RC source tree against the persistent Docker volumes and preserved `.env` from the Beta.1 installation. Raw kubeconfig material remains in the local `data/kubeconfigs` file boundary and is not copied into the Control Plane database.

## Pre-tag candidate procedure

Before the official RC tag exists, publish temporary multi-architecture candidate images using a tag such as:

```text
0.5.10-rc.1-candidate.<short-git-sha>
```

Then validate:

1. Start a clean isolated installation at `v0.5.10-beta.1` with the published Beta.1 images.
2. Create representative Environment, Integration, Target, and credential-reference metadata.
3. Preserve the Beta.1 `.env` and Docker volumes.
4. Move the source checkout to the validated RC branch/commit.
5. Run `./hermesctl init` so any newly introduced managed secret/identity values are generated while existing generated secrets are preserved. Optional new non-secret settings use Compose defaults unless the operator explicitly adds overrides to `.env`.
6. Run `./hermesctl upgrade <candidate-version>`. The command verifies required published images, backs up the running Control Plane database, updates configured `VERSION`, pulls the candidate images, and restores the previous version if startup fails.
7. Verify the pre-upgrade registry objects still exist, router managed credentials are reused, 9router tier customization is preserved, and execution remains disabled.
8. Verify Kubernetes Broker health and the dynamic kubectl matrix.
9. Switch to OmniRoute and back to 9router and run real completion probes.
10. Confirm a backup exists under `backups/`.

The official `v0.5.10-rc.1` tag must not be created until this candidate upgrade test and the separate fresh-install test pass.
