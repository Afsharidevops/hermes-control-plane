#!/usr/bin/env bash
set -euo pipefail

DEV3_SHA="8547c44de4f6e8116d70f2690b50a50c895eba34"
DEV3_TAG="v0.5.11-dev.3"
BRANCH="dev/0.5.11"
TAG="v0.5.11-dev.4"
ROOT="${HERMES_REPO:-$PWD}"
CREATE_COMMIT=0
PUSH_TAG=0
SKIP_VALIDATION=0
BRANCH_CI_GREEN_SHA="${HERMES_BRANCH_CI_GREEN_SHA:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit) CREATE_COMMIT=1 ;;
    --tag) PUSH_TAG=1 ;;
    --skip-validation) SKIP_VALIDATION=1 ;;
    --branch-ci-green-sha) shift; BRANCH_CI_GREEN_SHA="${1:?--branch-ci-green-sha requires a SHA}" ;;
    --repo) shift; ROOT="${1:?--repo requires a path}" ;;
    *) echo "Usage: $0 [--repo PATH] [--commit] [--tag --branch-ci-green-sha SHA] [--skip-validation]" >&2; exit 2 ;;
  esac
  shift
done

cd "$ROOT"
[[ -d .git ]] || { echo "Not a Git working tree: $ROOT" >&2; exit 3; }
[[ "$(git branch --show-current)" == "$BRANCH" ]] || { echo "Refusing: expected branch $BRANCH" >&2; exit 4; }
git cat-file -e "$DEV3_SHA^{commit}" 2>/dev/null || { echo "Missing frozen dev.3 commit $DEV3_SHA" >&2; exit 5; }
git merge-base --is-ancestor "$DEV3_SHA" HEAD || { echo "Refusing: frozen dev.3 boundary is not an ancestor of HEAD" >&2; exit 6; }
[[ "$(git rev-parse "$DEV3_TAG^{commit}")" == "$DEV3_SHA" ]] || { echo "Refusing: $DEV3_TAG no longer peels to frozen boundary" >&2; exit 7; }
[[ "$(cat VERSION)" == "0.5.11-dev.4" ]] || { echo "VERSION is not 0.5.11-dev.4" >&2; exit 8; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 13; }
sha256sum --quiet -c MANIFEST.sha256 || { echo "Dev.4 source manifest verification failed" >&2; exit 14; }

if [[ "$SKIP_VALIDATION" != "1" ]]; then
  ./validate.sh "$ROOT"
fi

manifest_paths_file="$(mktemp)"
allowed_paths_file="$(mktemp)"
cleanup() { rm -f "$manifest_paths_file" "$allowed_paths_file"; }
trap cleanup EXIT
sed -E 's/^[0-9a-f]{64}  //' MANIFEST.sha256 > "$manifest_paths_file"
{
  cat "$manifest_paths_file"
  printf '%s\n' MANIFEST.sha256
} | LC_ALL=C sort -u > "$allowed_paths_file"

is_allowed_path() {
  local path="$1"
  grep -Fqx -- "$path" "$allowed_paths_file"
}

# Never let the guarded commit path sweep in a local virtualenv, secret, cache,
# runtime artifact, or unrelated operator edit. Only manifest-governed release
# files (plus the manifest itself) may be dirty when --commit is requested.
if [[ "$CREATE_COMMIT" == "1" ]]; then
  unexpected=()
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    if ! is_allowed_path "$path"; then unexpected+=("$path"); fi
  done < <({ git diff --name-only; git diff --cached --name-only; git ls-files --others --exclude-standard; } | LC_ALL=C sort -u)

  if (( ${#unexpected[@]} > 0 )); then
    echo "Refusing to commit: non-release working-tree paths are dirty/untracked:" >&2
    printf '  %s\n' "${unexpected[@]}" >&2
    echo "Resolve or ignore those paths; push.sh will not stage them." >&2
    exit 15
  fi

  while IFS= read -r path; do
    [[ -z "$path" ]] || git add -- "$path"
  done < "$manifest_paths_file"
  git add -- MANIFEST.sha256

  # Defense in depth: the index itself must contain only approved release paths.
  unexpected_staged=()
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    if ! is_allowed_path "$path"; then unexpected_staged+=("$path"); fi
  done < <(git diff --cached --name-only)
  if (( ${#unexpected_staged[@]} > 0 )); then
    git reset --quiet
    echo "Refusing to commit: unexpected staged paths detected:" >&2
    printf '  %s\n' "${unexpected_staged[@]}" >&2
    exit 16
  fi

  if ! git diff --cached --quiet; then
    git commit -m "feat: add 0.5.11-dev.4 operations center foundations"
  fi
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Only ignored local/runtime state may remain before push/tag." >&2
  git status --short >&2
  exit 9
fi

# Keep PR #2 Draft: this script intentionally performs no PR state mutation.
git push origin "$BRANCH"

if [[ "$PUSH_TAG" == "1" ]]; then
  head_sha="$(git rev-parse HEAD)"
  [[ -n "$BRANCH_CI_GREEN_SHA" ]] || { echo "Refusing to tag: provide --branch-ci-green-sha SHA after branch CI succeeds" >&2; exit 10; }
  [[ "$BRANCH_CI_GREEN_SHA" == "$head_sha" ]] || { echo "Refusing to tag: branch CI green SHA $BRANCH_CI_GREEN_SHA does not match HEAD $head_sha" >&2; exit 11; }
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    [[ "$(git rev-list -n1 "$TAG")" == "$head_sha" ]] || { echo "$TAG already exists on another commit" >&2; exit 12; }
  else
    git tag -a "$TAG" -m "Hermes 0.5.11-dev.4"
  fi
  git push origin "$TAG"
fi

echo "Source push complete. GitHub Actions owns Hermes image build/publication to Docker Hub."
