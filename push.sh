#!/usr/bin/env bash
set -euo pipefail

DEV2_SHA="a71b03a54ed2f619d3605c0c08d46de35ad5911c"
BRANCH="dev/0.5.11"
TAG="v0.5.11-dev.3"
ROOT="${HERMES_REPO:-$PWD}"
CREATE_COMMIT=0
PUSH_TAG=0
SKIP_VALIDATION=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit) CREATE_COMMIT=1 ;;
    --tag) PUSH_TAG=1 ;;
    --skip-validation) SKIP_VALIDATION=1 ;;
    --repo) shift; ROOT="${1:?--repo requires a path}" ;;
    *) echo "Usage: $0 [--repo PATH] [--commit] [--tag] [--skip-validation]" >&2; exit 2 ;;
  esac
  shift
done

cd "$ROOT"
[[ -d .git ]] || { echo "Not a Git working tree: $ROOT" >&2; exit 3; }
[[ "$(git branch --show-current)" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH" >&2; exit 4; }
git cat-file -e "$DEV2_SHA^{commit}" 2>/dev/null || { echo "Missing frozen dev.2 commit $DEV2_SHA" >&2; exit 5; }
git merge-base --is-ancestor "$DEV2_SHA" HEAD || { echo "Refusing: frozen dev.2 boundary is not an ancestor of HEAD" >&2; exit 6; }
[[ "$(cat VERSION)" == "0.5.11-dev.3" ]] || { echo "VERSION is not 0.5.11-dev.3" >&2; exit 7; }

if [[ "$SKIP_VALIDATION" != "1" ]]; then
  ./validate.sh "$ROOT"
fi

if [[ "$CREATE_COMMIT" == "1" && -n "$(git status --porcelain)" ]]; then
  git add -A
  git commit -m "feat: add 0.5.11-dev.3 cluster factory foundations"
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit the validated dev.3 source or rerun with --commit." >&2
  exit 8
fi

# Keep PR #2 Draft: this script intentionally performs no PR state mutation.
git push origin "$BRANCH"

if [[ "$PUSH_TAG" == "1" ]]; then
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    [[ "$(git rev-list -n1 "$TAG")" == "$(git rev-parse HEAD)" ]] || { echo "$TAG already exists on another commit" >&2; exit 9; }
  else
    git tag -a "$TAG" -m "Hermes 0.5.11-dev.3"
  fi
  git push origin "$TAG"
fi

echo "Source push complete. GitHub Actions owns Hermes image build/publication to Docker Hub."
