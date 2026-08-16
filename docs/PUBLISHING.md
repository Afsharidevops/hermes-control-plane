# Publishing

GitHub Actions is the normal image publisher. Local publishing remains a fallback.

## GitHub configuration

Repository variable:

```text
DOCKERHUB_USERNAME=afsharidevops
```

Repository secret:

```text
DOCKERHUB_TOKEN=<Docker Hub PAT with read/write permission>
```

The token value must never be committed.

## Tag policy

- pull request: build only, no push
- `main`: `edge` plus immutable `sha-...`
- prerelease tag such as `v0.5.10-beta.1`: `0.5.10-beta.1` (and `sha-...`)
- stable tag such as `v0.5.10`: `0.5.10`, `sha-...`, and `latest`

`latest` is deliberately not moved by alpha/beta/RC releases.

## Manual fallback

```bash
docker login
IMAGE_NAMESPACE=afsharidevops VERSION=0.5.10-beta.1 ./scripts/push-images.sh
```

The fallback script follows the same rule: only a stable `x.y.z` version also updates `latest`.

## RC candidate validation before the Git tag

Before creating a prerelease Git tag, the RC acceptance process may publish temporary candidate image tags such as:

```text
0.5.10-rc.1-candidate.<short-git-sha>
```

Candidate tags are for fresh-install and upgrade validation only. They must never publish `latest`. After candidate install/upgrade acceptance passes, merge the validated development branch to `main`, re-run validation on the merge commit, then create the official `v0.5.10-rc.1` tag. The tag workflow publishes the final `0.5.10-rc.1` images.

The candidate image set must be inspected for both `linux/amd64` and `linux/arm64` before the RC tag is created.
