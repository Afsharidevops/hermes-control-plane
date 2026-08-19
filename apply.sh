#!/usr/bin/env bash
set -euo pipefail

BASE_SHA="1764cad667717ec78156af8f9f3fcc30eb84c1f5"
BRANCH="dev/0.5.11"
SOURCE_DIR="${HERMES_DEV2_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TARGET_DIR="${HERMES_REPO:-${1:-$PWD}}"

[[ -f "$SOURCE_DIR/VERSION" ]] || { echo "Source snapshot is missing VERSION: $SOURCE_DIR" >&2; exit 1; }
[[ "$(cat "$SOURCE_DIR/VERSION")" == "0.5.11-dev.2" ]] || { echo "Source snapshot is not Hermes 0.5.11-dev.2: $SOURCE_DIR" >&2; exit 1; }
[[ -f "$SOURCE_DIR/scripts/acceptance/dev2-source-security-gate.py" ]] || { echo "Source snapshot is missing the dev.2 security gate" >&2; exit 1; }
[[ -f "$SOURCE_DIR/docs/DEV2-TRUST-BOOTSTRAP.md" ]] || { echo "Source snapshot is missing the dev.2 handoff documentation" >&2; exit 1; }

if [[ ! -d "$TARGET_DIR/.git" ]]; then
  echo "Target is not a Git working tree: $TARGET_DIR" >&2
  echo "Set HERMES_REPO=/path/to/hermes-control-plane or pass the repo path as argument 1." >&2
  exit 2
fi

cd "$TARGET_DIR"
current_branch="$(git branch --show-current)"
[[ "$current_branch" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH, got $current_branch" >&2; exit 3; }
git cat-file -e "$BASE_SHA^{commit}" 2>/dev/null || { echo "Required dev.1 baseline commit is not present: $BASE_SHA" >&2; exit 4; }
git merge-base --is-ancestor "$BASE_SHA" HEAD || { echo "Refusing: $BASE_SHA is not an ancestor of HEAD" >&2; exit 5; }

if [[ "$(cd "$SOURCE_DIR" && pwd)" == "$(pwd)" ]]; then
  echo "Source and target are the same directory; dev.2 source is already present." >&2
  exit 0
fi

# Do not overwrite Git metadata or runtime data. The source snapshot is authoritative
# for project files; the known dev.1 commit is verified above and is not recreated.
tar -C "$SOURCE_DIR" \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='data/*' \
  --exclude='release-evidence/*.log' \
  -cf - . | tar -C "$TARGET_DIR" -xf -

chmod +x apply.sh validate.sh push.sh scripts/*.sh scripts/acceptance/*.py 2>/dev/null || true

echo "Applied Hermes 0.5.11-dev.2 source snapshot to $TARGET_DIR"
echo "Next: ./validate.sh"
