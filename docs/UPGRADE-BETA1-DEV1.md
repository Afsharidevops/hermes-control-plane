# Apply 0.5.10-beta.1-dev.1 to the development branch

This package is a development snapshot. Do not create `v0.5.10-beta.1` until the rest of the beta acceptance scope is implemented and tested.

```bash
cd ~/Downloads/hermes-control-plane
git checkout dev/0.5.10-beta.1
git pull --ff-only origin dev/0.5.10-beta.1

tmp="$(mktemp -d)"
unzip -q ~/Downloads/hermes-control-plane-0.5.10-beta.1-dev.1.zip -d "$tmp"
cp -a "$tmp/hermes-control-plane/." ./
rm -rf "$tmp"

# Preserve your existing .env, then add/generate the new beta secrets.
./hermesctl init
./hermesctl version set 0.5.10-beta.1-dev.1
./scripts/verify.sh

git add -A
git commit -m "feat: add Kubernetes and Helm beta vertical slice"
git push origin dev/0.5.10-beta.1
```

For a local source build:

```bash
./hermesctl up
./hermesctl status
```

Import a kubeconfig only after the Control Plane is running:

```bash
./hermesctl kubeconfig import production ~/.kube/config
./hermesctl kubeconfig list
```

Keep execution disabled while testing discovery and dry-run previews. Enable mutation only in an isolated test cluster after reviewing the generated ChangeSet and broker preview:

```bash
./hermesctl version
```

Do not tag beta.1 from this dev.1 snapshot.
