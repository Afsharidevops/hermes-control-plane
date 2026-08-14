# Publishing Hermes Control Plane

## GitHub

Recommended repository name:

```text
Afsharidevops/hermes-control-plane
```

Create locally, commit, then create/push with GitHub CLI:

```bash
cd hermes-control-plane
git init -b main
git add .
git commit -m "feat: bootstrap Hermes Control Plane 0.5.10-alpha.1"
gh auth login
gh repo create Afsharidevops/hermes-control-plane \
  --public \
  --source=. \
  --remote=origin \
  --push \
  --description "Self-hosted AI-assisted DevOps control plane for Kubernetes, Docker, Git, SSH and ChatOps"
```

If the GitHub repository was created in the web UI instead:

```bash
git remote add origin git@github.com:Afsharidevops/hermes-control-plane.git
git push -u origin main
```

## Docker Hub

Project-owned images:

```text
<namespace>/hermes-control-plane-api
<namespace>/hermes-control-plane-router-gateway
<namespace>/hermes-control-plane-smart-router
<namespace>/hermes-control-plane-execution-broker
<namespace>/hermes-control-plane-node-agent
```

Sign in:

```bash
docker login
```

For CI/non-interactive environments, prefer a Docker Hub access token through stdin:

```bash
printf '%s' "$DOCKERHUB_TOKEN" | docker login \
  --username "$DOCKERHUB_USERNAME" \
  --password-stdin
```

Build and push multi-platform images:

```bash
export IMAGE_NAMESPACE=afsharidevops
export VERSION=0.5.10-alpha.1
./scripts/push-images.sh
```

Default platforms are `linux/amd64,linux/arm64`.

Then configure `.env`:

```text
IMAGE_NAMESPACE=afsharidevops
VERSION=0.5.10-alpha.1
```

For a release tag:

```bash
git tag -a v0.5.10-alpha.1 -m "Hermes Control Plane v0.5.10-alpha.1"
git push origin v0.5.10-alpha.1
```


## Repository isolation rule

Do not publish this project to `hermes-smart-router` or `hermes-execution-broker`. Those Docker Hub repositories belong to `hermes-linux-stack`. All Control Plane-owned images use the `hermes-control-plane-` prefix.
