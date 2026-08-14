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
