# Fast upgrade/publish: 0.5.10-alpha.2

This path is intentionally direct-to-`main` for the fastest alpha release. It preserves the existing `.git`, `.env`, and Docker volumes.

The existing remote/local `v0.5.10-alpha.2` tag must first be removed because it was created before the alpha.2 implementation existed.

```bash
cd ~/Downloads/hermes-control-plane

# 1) Remove the premature release tag. Safe if one side is already absent.
git push origin :refs/tags/v0.5.10-alpha.2 || true
git tag -d v0.5.10-alpha.2 2>/dev/null || true

# 2) Overlay the new source package. .git/.env/local volumes are not in the ZIP.
tmp="$(mktemp -d)"
unzip -q ~/Downloads/hermes-control-plane-0.5.10-alpha.2.zip -d "$tmp"
cp -a "$tmp/hermes-control-plane/." ./
rm -rf "$tmp"

# 3) Existing .env overrides Compose defaults, so move it to the new version tag.
sed -i 's/^VERSION=.*/VERSION=0.5.10-alpha.2/' .env

# 4) Verify locally. Control Plane unit tests run if dev dependencies are installed;
#    GitHub validate always runs the full tests + Compose config + Helm lint.
./scripts/verify.sh

# 5) Commit and push alpha.2 source. This automatically publishes :edge + :sha-*.
git add -A
git commit -m "feat: implement 0.5.10-alpha.2 management and safety core"
git push origin main

# 6) Wait for the validation workflow before creating the release tag.
sleep 5
VALIDATE_RUN="$(gh run list --workflow validate.yml --branch main --event push --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$VALIDATE_RUN" --exit-status

# 7) Release. The tag automatically publishes :0.5.10-alpha.2 for all five images.
git tag -a v0.5.10-alpha.2 -m "Hermes Control Plane v0.5.10-alpha.2"
git push origin v0.5.10-alpha.2

# 8) Watch image publishing.
sleep 5
gh run list --workflow publish-images.yml --limit 5
```

After the tag build succeeds, deploy the published images without local builds:

```bash
./hermesctl down
./hermesctl up --pull
./hermesctl status
```

Open:

```text
http://127.0.0.1:8800/ui
```

The SQLite database in the existing Control Plane volume is migrated automatically from alpha.1 to alpha.2 on startup.
