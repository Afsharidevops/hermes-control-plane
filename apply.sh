#!/usr/bin/env bash
set -euo pipefail

DEV2_SHA="a71b03a54ed2f619d3605c0c08d46de35ad5911c"
BRANCH="dev/0.5.11"
SOURCE_DIR="${HERMES_DEV3_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TARGET_DIR="${HERMES_REPO:-${1:-$PWD}}"

[[ -f "$SOURCE_DIR/VERSION" ]] || { echo "Source snapshot is missing VERSION: $SOURCE_DIR" >&2; exit 1; }
[[ "$(cat "$SOURCE_DIR/VERSION")" == "0.5.11-dev.3" ]] || { echo "Source snapshot is not Hermes 0.5.11-dev.3: $SOURCE_DIR" >&2; exit 1; }
[[ -f "$SOURCE_DIR/scripts/acceptance/dev3-source-security-gate.py" ]] || { echo "Source snapshot is missing the dev.3 security gate" >&2; exit 1; }
[[ -f "$SOURCE_DIR/docs/DEV3-CLUSTER-FACTORY.md" ]] || { echo "Source snapshot is missing the dev.3 handoff documentation" >&2; exit 1; }

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  echo "Target is not a Git working tree: $TARGET_DIR" >&2
  echo "Set HERMES_REPO=/path/to/hermes-control-plane or pass the repo path as argument 1." >&2
  exit 2
fi

cd "$TARGET_DIR"
current_branch="$(git branch --show-current)"
[[ "$current_branch" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH, got $current_branch" >&2; exit 3; }
git cat-file -e "$DEV2_SHA^{commit}" 2>/dev/null || { echo "Required frozen dev.2 commit is not present: $DEV2_SHA" >&2; exit 4; }
git merge-base --is-ancestor "$DEV2_SHA" HEAD || { echo "Refusing: frozen dev.2 commit is not an ancestor of HEAD" >&2; exit 5; }

if [[ "$(cd "$SOURCE_DIR" && pwd)" == "$(pwd)" ]]; then
  echo "Source and target are the same directory; dev.3 source is already present." >&2
  exit 0
fi

# Project files only. Never overwrite Git metadata, local secrets, or runtime data.
tar -C "$SOURCE_DIR" \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='data/*' \
  --exclude='release-evidence/*.log' \
  -cf - . | tar -C "$TARGET_DIR" -xf -

chmod +x apply.sh validate.sh push.sh scripts/*.sh scripts/acceptance/*.py 2>/dev/null || true

echo "Applied Hermes 0.5.11-dev.3 source snapshot to $TARGET_DIR on top of frozen dev.2"
echo "Next: ./validate.sh"
