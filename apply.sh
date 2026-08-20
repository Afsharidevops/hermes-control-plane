#!/usr/bin/env bash
set -euo pipefail

DEV4_SHA="d4eb9b7ab2564301c09b8c0d36a2e9d53b843273"
DEV4_TAG="v0.5.11-dev.4"
BRANCH="dev/0.5.11"
SOURCE_DIR="${HERMES_DEV5_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TARGET_DIR="${HERMES_REPO:-${1:-$PWD}}"

[[ -f "$SOURCE_DIR/VERSION" ]] || { echo "Source snapshot is missing VERSION: $SOURCE_DIR" >&2; exit 1; }
[[ "$(cat "$SOURCE_DIR/VERSION")" == "0.5.11-dev.5" ]] || { echo "Source snapshot is not Hermes 0.5.11-dev.5: $SOURCE_DIR" >&2; exit 1; }
[[ -f "$SOURCE_DIR/scripts/acceptance/dev5-source-security-gate.py" ]] || { echo "Source snapshot is missing the dev.5 security gate" >&2; exit 1; }
[[ -f "$SOURCE_DIR/docs/DEV5-SCOPE-CLOSURE.md" ]] || { echo "Source snapshot is missing the dev.5 scope-closure documentation" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to verify the dev.5 source manifest" >&2; exit 1; }
(cd "$SOURCE_DIR" && sha256sum --quiet -c MANIFEST.sha256) || { echo "Dev.5 source manifest verification failed" >&2; exit 1; }

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  echo "Target is not a Git working tree: $TARGET_DIR" >&2
  echo "Set HERMES_REPO=/path/to/hermes-control-plane or pass the repo path as argument 1." >&2
  exit 2
fi

cd "$TARGET_DIR"
current_branch="$(git branch --show-current)"
[[ "$current_branch" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH, got $current_branch" >&2; exit 3; }
git cat-file -e "$DEV4_SHA^{commit}" 2>/dev/null || { echo "Required frozen dev.4 commit is not present: $DEV4_SHA" >&2; exit 4; }
git merge-base --is-ancestor "$DEV4_SHA" HEAD || { echo "Refusing: frozen dev.4 commit is not an ancestor of HEAD" >&2; exit 5; }
[[ "$(git rev-parse "$DEV4_TAG^{commit}")" == "$DEV4_SHA" ]] || { echo "Refusing: $DEV4_TAG no longer peels to frozen dev.4 boundary" >&2; exit 6; }
[[ -z "$(git status --porcelain)" ]] || { echo "Refusing: target working tree is not clean" >&2; exit 7; }

if [[ "$(cd "$SOURCE_DIR" && pwd)" == "$(pwd)" ]]; then
  echo "Source and target are the same directory; dev.5 source is already present." >&2
  exit 0
fi

# Project files only. Never overwrite Git metadata, local secrets, or runtime data.
tar -C "$SOURCE_DIR" \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='data/*' \
  --exclude='release-evidence/*.log' \
  -cf - . | tar -C "$TARGET_DIR" -xf -

chmod +x apply.sh validate.sh push.sh hermesctl scripts/*.sh scripts/acceptance/*.py 2>/dev/null || true

echo "Applied Hermes 0.5.11-dev.5 source on top of frozen dev.4 boundary $DEV4_SHA"
echo "Next: ./validate.sh"
