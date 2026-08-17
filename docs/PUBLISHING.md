# Publishing Hermes Control Plane 0.5.10

GitHub Actions is the normal image publisher. Local publishing remains an emergency fallback.

## GitHub configuration

Repository variable:

```text
DOCKERHUB_USERNAME=afsharidevops
```

Repository secret:

```text
DOCKERHUB_TOKEN=<Docker Hub PAT with read/write permission>
```

Never commit the token value.

## Tag policy

- pull request: build only, no push;
- `main`: `edge` plus immutable `sha-...`;
- alpha/beta/RC tag: version tag plus `sha-...`, never `latest`;
- stable `v0.5.10`: `0.5.10`, `sha-...`, and `latest`.

## Stable candidate before the Git tag

The first stable release is accepted from temporary pre-tag images built from the exact candidate commit:

```text
0.5.10-candidate.<short-git-sha>
```

Run the **Build and Publish Docker Images** workflow manually with `candidate_tag` set to that value. Candidate tags never publish `latest`.

Verify all six Hermes image indexes and both supported architectures:

```bash
./scripts/acceptance/candidate-images.sh 0.5.10-candidate.<short-git-sha>
```

Then complete `docs/STABLE-0.5.10-ACCEPTANCE.md`. Only after the exact candidate commit passes clean Compose/Helm, migration, upgrade/rollback and runtime smoke gates should it be merged/fast-forwarded to `main` and tagged `v0.5.10`.

## Official stable publication

After validation CI succeeds on the exact `main` commit:

```bash
git tag -a v0.5.10 -m "Hermes Control Plane 0.5.10"
git push origin v0.5.10
```

The tag workflow must publish all six `0.5.10` multi-architecture images. Verify the tag points at the validated commit and verify the resulting OCI indexes before considering the release complete.

## Manual fallback

```bash
docker login
IMAGE_NAMESPACE=afsharidevops VERSION=0.5.10 ./scripts/push-images.sh
```

Because this is a stable `x.y.z` version, the fallback may also move `latest`. Do not use the fallback until the stable acceptance gates have passed.
