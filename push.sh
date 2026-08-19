#!/usr/bin/env bash
set -euo pipefail

BASE_SHA="1764cad667717ec78156af8f9f3fcc30eb84c1f5"
BRANCH="dev/0.5.11"
TAG="v0.5.11-dev.2"
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
git cat-file -e "$BASE_SHA^{commit}" 2>/dev/null || { echo "Missing dev.1 baseline commit $BASE_SHA" >&2; exit 5; }
git merge-base --is-ancestor "$BASE_SHA" HEAD || { echo "Refusing: dev.1 baseline is not an ancestor of HEAD" >&2; exit 6; }
[[ "$(cat VERSION)" == "0.5.11-dev.2" ]] || { echo "VERSION is not 0.5.11-dev.2" >&2; exit 7; }

if [[ "$SKIP_VALIDATION" != "1" ]]; then
  ./validate.sh "$ROOT"
fi

if [[ "$CREATE_COMMIT" == "1" && -n "$(git status --porcelain)" ]]; then
  git add -A
  git commit -m "feat: complete 0.5.11-dev.2 trust and bootstrap foundation"
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit the validated dev.2 source or rerun with --commit." >&2
  exit 8
fi

# Keep PR #2 Draft: this script intentionally performs no PR state change.
git push origin "$BRANCH"

if [[ "$PUSH_TAG" == "1" ]]; then
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    [[ "$(git rev-list -n1 "$TAG")" == "$(git rev-parse HEAD)" ]] || { echo "$TAG already exists on another commit" >&2; exit 9; }
  else
    git tag -a "$TAG" -m "Hermes 0.5.11-dev.2"
  fi
  git push origin "$TAG"
fi

echo "Source push complete. GitHub Actions owns Hermes image build/publication to Docker Hub."
