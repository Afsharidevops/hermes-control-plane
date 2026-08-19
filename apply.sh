#!/usr/bin/env bash
set -euo pipefail

DEV3_SHA="8547c44de4f6e8116d70f2690b50a50c895eba34"
DEV3_TAG="v0.5.11-dev.3"
BRANCH="dev/0.5.11"
SOURCE_DIR="${HERMES_DEV4_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TARGET_DIR="${HERMES_REPO:-${1:-$PWD}}"

[[ -f "$SOURCE_DIR/VERSION" ]] || { echo "Source snapshot is missing VERSION: $SOURCE_DIR" >&2; exit 1; }
[[ "$(cat "$SOURCE_DIR/VERSION")" == "0.5.11-dev.4" ]] || { echo "Source snapshot is not Hermes 0.5.11-dev.4: $SOURCE_DIR" >&2; exit 1; }
[[ -f "$SOURCE_DIR/scripts/acceptance/dev4-source-security-gate.py" ]] || { echo "Source snapshot is missing the dev.4 security gate" >&2; exit 1; }
[[ -f "$SOURCE_DIR/docs/DEV4-OPERATIONS-CENTER.md" ]] || { echo "Source snapshot is missing the dev.4 handoff documentation" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required to verify the dev.4 source manifest" >&2; exit 1; }
(cd "$SOURCE_DIR" && sha256sum --quiet -c MANIFEST.sha256) || { echo "Dev.4 source manifest verification failed" >&2; exit 1; }

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  echo "Target is not a Git working tree: $TARGET_DIR" >&2
  echo "Set HERMES_REPO=/path/to/hermes-control-plane or pass the repo path as argument 1." >&2
  exit 2
fi

cd "$TARGET_DIR"
current_branch="$(git branch --show-current)"
[[ "$current_branch" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH, got $current_branch" >&2; exit 3; }
git cat-file -e "$DEV3_SHA^{commit}" 2>/dev/null || { echo "Required frozen dev.3 commit is not present: $DEV3_SHA" >&2; exit 4; }
git merge-base --is-ancestor "$DEV3_SHA" HEAD || { echo "Refusing: frozen dev.3 commit is not an ancestor of HEAD" >&2; exit 5; }
if git rev-parse "$DEV3_TAG^{commit}" >/dev/null 2>&1; then
  [[ "$(git rev-parse "$DEV3_TAG^{commit}")" == "$DEV3_SHA" ]] || { echo "Refusing: $DEV3_TAG does not peel to frozen dev.3 boundary" >&2; exit 6; }
fi
[[ -z "$(git status --porcelain)" ]] || { echo "Refusing: target working tree is not clean" >&2; exit 7; }

if [[ "$(cd "$SOURCE_DIR" && pwd)" == "$(pwd)" ]]; then
  echo "Source and target are the same directory; dev.4 source is already present." >&2
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

echo "Applied Hermes 0.5.11-dev.4 source on top of frozen dev.3 boundary $DEV3_SHA"
echo "Next: ./validate.sh"
