#!/usr/bin/env bash
# Hermes setup wizard
#
# Interactive, menu-driven setup for:
#   - a safe, isolated sandbox (test environment)     -- safe core services only
#   - a normal local install (full stack)             -- router + optional Hermes bot
#
# Safety: the sandbox flow never starts router, Hermes bot, or Telegram profiles,
# never enables execution/collection gates, and never reads or mutates the repo
# root .env. Generated secret material is written only to the sandbox env file
# with mode 0600 and is git-ignored.
#
# Inspect without changing anything:
#   bash scripts/hermes-wizard.sh --flow sandbox --dry-run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRY_RUN=0
FLOW=""
TARGET_DIR=""
PROJECT=""
NO_START=0
ENV_FILE=""

usage() {
  cat <<'USAGE'
Usage: bash scripts/hermes-wizard.sh [options]

Interactive install wizard for Hermes Control Plane.

Options:
  --flow sandbox|install   Skip the flow menu.
  --dir PATH               Sandbox target directory. Created as a git worktree
                           when absent; used as-is when it already contains a
                           checkout.
  --project NAME           Docker Compose project name (sandbox flow).
  --no-start               Prepare configuration only; do not start services.
  --dry-run                Print the commands that would run; change nothing.
  -h, --help               Show this help.

Examples:
  bash scripts/hermes-wizard.sh
  bash scripts/hermes-wizard.sh --flow sandbox --dry-run
  bash scripts/hermes-wizard.sh --flow install
USAGE
}

# Colored status lines (disabled when output is not a terminal or NO_COLOR=1).
if [[ -t 2 ]] && [[ "${NO_COLOR:-}" != 1 ]]; then
  C_INFO=$'\033[1;34m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'
  C_FAIL=$'\033[1;31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
  C_INFO=; C_OK=; C_WARN=; C_FAIL=; C_BOLD=; C_RESET=
fi

info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok() { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "$C_FAIL" "$C_RESET" "$*" >&2; exit 1; }
abort() { printf '%s[ABORT]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

randhex() { openssl rand -hex "${1:-32}"; }

# Print (dry-run) or execute (normal) a command.
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '  $ %s\n' "$*"
  else
    "$@"
  fi
}

# ask_text <label> [default]  -- prints the answer on stdout, prompts on stderr.
ask_text() {
  local label="$1" default="${2:-}" answer
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$label" "$default" >&2
  else
    printf '%s: ' "$label" >&2
  fi
  IFS= read -r answer || true
  printf '%s' "${answer:-$default}"
}

# ask_secret <label>  -- hidden input, never empty; prints the value on stdout.
ask_secret() {
  local label="$1" answer
  while true; do
    printf '%s: ' "$label" >&2
    IFS= read -rs answer || { printf '\n' >&2; abort "no input provided"; }
    printf '\n' >&2
    [[ -n "$answer" ]] && { printf '%s' "$answer"; return 0; }
    warn "A value is required."
  done
}

# ask_yes_no <label> [default y|n]  -- returns 0 on yes.
ask_yes_no() {
  local label="$1" default="${2:-n}" answer suffix
  if [[ "$default" == y ]]; then suffix="Y/n"; else suffix="y/N"; fi
  printf '%s [%s]: ' "$label" "$suffix" >&2
  IFS= read -r answer || true
  answer="${answer:-$default}"
  case "$answer" in
    y | Y | yes | YES) return 0 ;;
    *) return 1 ;;
  esac
}

# menu <title> <default-index> <option...>  -- prints the chosen option on stdout.
menu() {
  local title="$1" default="${2:-1}" answer
  shift 2
  local -a opts=("$@")
  local i=1
  printf '\n%s\n' "$title" >&2
  for opt in "${opts[@]}"; do
    printf '  %d) %s\n' "$i" "$opt" >&2
    i=$((i + 1))
  done
  while true; do
    printf 'Choice [%s]: ' "$default" >&2
    IFS= read -r answer || true
    answer="${answer:-$default}"
    case "$answer" in
      q | Q) abort "installation cancelled" ;;
    esac
    if [[ "$answer" =~ ^[0-9]+$ ]] && ((answer >= 1 && answer <= ${#opts[@]})); then
      printf '%s' "${opts[$((answer - 1))]}"
      return 0
    fi
    warn "Choose a number from 1 to ${#opts[@]}, or q to cancel."
  done
}

# ask_port <label> <default>  -- prints a valid TCP port on stdout.
ask_port() {
  local label="$1" default="$2" value
  while true; do
    value="$(ask_text "$label" "$default")"
    if [[ "$value" =~ ^[0-9]+$ ]] && ((1 <= 10#$value && 10#$value <= 65535)); then
      printf '%s' "$value"
      return 0
    fi
    warn "Enter a numeric port from 1 to 65535."
  done
}

validate_project_name() {
  local name="$1"
  [[ "$name" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail "invalid Compose project name: '$name' (use a-z 0-9 _ -)"
}

preflight() {
  local ok=1 tool
  for tool in git python3 openssl docker; do
    if command -v "$tool" >/dev/null 2>&1; then
      ok "  $tool"
    else
      warn "  $tool (missing)"
      ok=0
    fi
  done
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "  docker compose"
  else
    warn "  docker compose plugin (missing)"
    ok=0
  fi
  if command -v curl >/dev/null 2>&1; then
    ok "  curl"
  else
    warn "  curl (health checks will be skipped)"
  fi
  [[ "$ok" == "1" ]] || fail "install the missing requirements and rerun"
  [[ -f "$ROOT/docker-compose.yml" ]] || fail "docker-compose.yml not found in $ROOT"
  [[ -f "$ROOT/.env.example" ]] || fail ".env.example not found in $ROOT"
}

# file_env_value <file> <key> [default]  -- read one value from an env file.
file_env_value() {
  local file="$1" key="$2" default="${3:-}" v
  [[ -f "$file" ]] || { printf '%s' "$default"; return 0; }
  v="$(grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2-)"
  printf '%s' "${v:-$default}"
}

# env_value <key> [default]  -- read one value from $ENV_FILE.
env_value() {
  file_env_value "$ENV_FILE" "$1" "${2:-}"
}

# set_env <key> <value>  -- in-place edit of $ENV_FILE (same semantics as hermesctl).
set_env() {
  local key="$1" value="$2"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '  $ set_env %s=%s\n' "$key" "$value"
    return 0
  fi
  python3 - "$ENV_FILE" "$key" "$value" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); key = sys.argv[2]; value = sys.argv[3]
lines = p.read_text().splitlines() if p.exists() else []
out = []; found = False
for line in lines:
    if line.startswith(key + '='):
        out.append(f'{key}={value}'); found = True
    else:
        out.append(line)
if not found:
    out.append(f'{key}={value}')
p.write_text('\n'.join(out) + '\n')
PY
}

# Generate all missing secrets into $ENV_FILE using the same key names, sizes,
# and Fernet master-key format as hermesctl init_env.
generate_missing_secrets() {
  local key size entry line
  declare -A current=()
  if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r line; do
      case "$line" in
        '' | \#*) continue ;;
      esac
      key="${line%%=*}"
      current["$key"]="${line#*=}"
    done < "$ENV_FILE"
  fi

  local -a sizes=(
    HERMES_CONTROL_ADMIN_TOKEN:32
    HERMES_BOT_SERVICE_TOKEN:32
    HERMES_APPROVAL_BOT_TOKEN:32
    HERMES_APPROVAL_HMAC_KEY:32
    HERMES_AGENT_TASK_HMAC_KEY:32
    HERMES_CREDENTIAL_ADMIN_TOKEN:32
    HERMES_CREDENTIAL_SERVICE_TOKEN:32
    HERMES_KUBERNETES_BROKER_TOKEN:32
    HERMES_PROVIDER_WORKER_TOKEN:32
    HERMES_EXECUTION_HMAC_KEY:32
    ROUTER_GATEWAY_ADMIN_TOKEN:32
    SMART_ROUTER_HMAC_SECRET:32
    SMART_ROUTER_CLIENT_API_KEY:32
    SMART_ROUTER_ADMIN_API_KEY:32
    SMART_ROUTER_BOOTSTRAP_ADMIN_PASSWORD:18
    NINEROUTER_INITIAL_PASSWORD:18
    NINEROUTER_JWT_SECRET:32
    NINEROUTER_API_KEY_SECRET:32
    NINEROUTER_MACHINE_ID_SALT:32
    OMNIROUTE_INITIAL_PASSWORD:18
    OMNIROUTE_JWT_SECRET:32
    OMNIROUTE_API_KEY_SECRET:32
    OMNIROUTE_MANAGEMENT_API_KEY:32
    OMNIROUTE_STORAGE_ENCRYPTION_KEY:32
    OMNIROUTE_MACHINE_ID_SALT:32
    OMNIROUTE_WS_BRIDGE_SECRET:32
  )
  for entry in "${sizes[@]}"; do
    key="${entry%%:*}"; size="${entry##*:}"
    if [[ -z "${current[$key]:-}" || "${current[$key]}" == "CHANGE_ME" ]]; then
      set_env "$key" "$(randhex "$size")"
    fi
  done

  if [[ -z "${current[HERMES_CREDENTIAL_MASTER_KEY]:-}" || "${current[HERMES_CREDENTIAL_MASTER_KEY]}" == "CHANGE_ME" ]]; then
    set_env HERMES_CREDENTIAL_MASTER_KEY "$(python3 - <<'PYKEY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode('ascii'))
PYKEY
)"
  fi

  if [[ -z "${current[HERMES_KUBERNETES_BROKER_UID]:-}" ]]; then
    set_env HERMES_KUBERNETES_BROKER_UID "$(id -u)"
  fi
  if [[ -z "${current[HERMES_KUBERNETES_BROKER_GID]:-}" ]]; then
    set_env HERMES_KUBERNETES_BROKER_GID "$(id -g)"
  fi
}

# Keep a secret-bearing env file ignored by git via the shared .git/info/exclude
# (never touches the tracked .gitignore).
exclude_secret_from_git() {
  local pattern="$1" gitdir exclude
  gitdir="$(git -C "$ROOT" rev-parse --absolute-git-dir 2>/dev/null)" || return 0
  exclude="$gitdir/info/exclude"
  if [[ ! -f "$exclude" ]] || ! grep -qxF "$pattern" "$exclude" 2>/dev/null; then
    printf '%s\n' "$pattern" >> "$exclude"
  fi
}

backup_env_file() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  [[ -f "$ENV_FILE" ]] || return 0
  local stamp backup
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup="$ENV_FILE.backup-$stamp"
  cp -p "$ENV_FILE" "$backup"
  info "Backed up the existing configuration to $backup"
}

prepare_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    run cp "$ROOT/.env.example" "$ENV_FILE"
    run chmod 600 "$ENV_FILE"
  else
    info "Existing configuration found at $ENV_FILE; secrets and previous choices are preserved."
    backup_env_file
  fi
  generate_missing_secrets
  # Always pin VERSION to this release's default so a copied or stale .env can
  # never pull older image tags (e.g. a carried-over VERSION=0.5.10).
  local version
  version="$(file_env_value "$ROOT/.env.example" VERSION 0.5.11)"
  set_env VERSION "$version"
  ok "Configuration ready (VERSION=$version)."
}

wait_for_health() {
  local port="$1" tries="${2:-60}" i
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not available; skipping health wait"
    return 0
  fi
  info "Waiting for Control Plane health on http://127.0.0.1:${port}/health ..."
  for ((i = 1; i <= tries; i++)); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ok "Control Plane is healthy."
      return 0
    fi
    sleep 2
  done
  warn "Control Plane did not report healthy within $((tries * 2))s"
  return 1
}

print_docs_links() {
  cat <<'DOCS'

  Deployment:
    Self-hosted (Docker Compose)  docs/guide/deployment-docker.md
    Kubernetes (Helm chart)       docs/guide/deployment-kubernetes.md
    Getting started               docs/guide/getting-started.md
DOCS
}

print_sandbox_summary() {
  local workdir="$1" port="$2" project="$3"
  local teardown_line
  if [[ "$workdir" == "$ROOT" ]]; then
    teardown_line="rm -f \"$workdir/.env.sandbox\"   # sandbox env file (secrets)"
  else
    teardown_line="git -C \"$ROOT\" worktree remove \"$workdir\""
  fi
  cat <<EOF

${C_BOLD}Sandbox ready.${C_RESET}
  Worktree/root:   $workdir
  Env file:        $workdir/.env.sandbox (mode 0600, git-ignored)
  Compose project: $project
  Services:        control-plane, credential-service, kubernetes-broker, node-agent
  Execution gates: all disabled

  Control Plane UI   http://127.0.0.1:${port}
  Control Plane API  http://127.0.0.1:${port}/docs
  Credential Service http://127.0.0.1:$(env_value CREDENTIAL_SERVICE_PORT 8789)
  Kubernetes Broker  http://127.0.0.1:$(env_value KUBERNETES_BROKER_PORT 8830)
  Node Agent         http://127.0.0.1:8810

  Teardown:
    docker compose --project-directory "$workdir" --env-file "$workdir/.env.sandbox" -p "$project" down -v --remove-orphans
    $teardown_line
EOF
  print_docs_links
}

print_install_summary() {
  local provider="$1"
  cat <<EOF

${C_BOLD}Install ready.${C_RESET}
  Control Plane UI      http://127.0.0.1:$(env_value CONTROL_PLANE_PORT 8800)
  Control Plane API     http://127.0.0.1:$(env_value CONTROL_PLANE_PORT 8800)/docs
  Credential Service    http://127.0.0.1:$(env_value CREDENTIAL_SERVICE_PORT 8789)
  Kubernetes Broker     http://127.0.0.1:$(env_value KUBERNETES_BROKER_PORT 8830)
  Node Agent            http://127.0.0.1:8810
  Router provider       $provider

  Commands:
    ./hermesctl status        # service status
    ./hermesctl logs          # follow service logs
    ./hermesctl bot status    # Hermes bot state (never prints tokens)
EOF
  print_docs_links
}

flow_sandbox() {
  info "Safe sandbox (isolated test environment)"
  local isolation branch workdir cp_port
  if [[ -n "$TARGET_DIR" ]]; then
    workdir="$TARGET_DIR"
    if [[ ! -d "$workdir" ]]; then
      branch="$(git -C "$ROOT" branch --show-current 2>/dev/null || true)"
      branch="${branch:-main}"
      run git -C "$ROOT" worktree add --detach "$workdir" "$branch"
    fi
  else
    isolation="$(menu "Isolation mode" 1 \
      "New git worktree [recommended]" \
      "Current directory")"
    if [[ "$isolation" == Current* ]]; then
      workdir="$ROOT"
      warn "Using the current directory; isolation is limited to the Compose project name."
    else
      branch="$(git -C "$ROOT" branch --show-current 2>/dev/null || true)"
      branch="${branch:-main}"
      workdir="$(ask_text "Sandbox worktree directory" "$HOME/hermes-sandbox")"
      if [[ ! -d "$workdir" ]]; then
        run git -C "$ROOT" worktree add --detach "$workdir" "$branch"
      elif git -C "$workdir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        info "Using existing worktree $workdir"
      else
        fail "$workdir exists and is not a git worktree"
      fi
    fi
  fi

  if [[ "$DRY_RUN" == "0" ]]; then
    [[ -f "$workdir/docker-compose.yml" ]] || fail "$workdir does not contain docker-compose.yml"
  fi

  ENV_FILE="$workdir/.env.sandbox"
  if [[ -z "$PROJECT" ]]; then
    PROJECT="$(ask_text "Docker Compose project name" "hermes-sandbox")"
  fi
  validate_project_name "$PROJECT"

  prepare_env_file

  # Safety overrides: always enforced in sandbox mode, never user-selectable.
  set_env HERMES_EXECUTION_ENABLED "false"
  set_env HERMES_KUBERNETES_EXECUTION_ENABLED "false"
  set_env HERMES_PROVIDER_EXECUTION_ENABLED "false"
  set_env HERMES_INFRASTRUCTURE_EXECUTION_ENABLED "false"
  set_env HERMES_CAPACITY_COLLECTION_ENABLED "false"
  set_env HERMES_VM_INVENTORY_COLLECTION_ENABLED "false"
  set_env HERMES_PROXMOX_VM_RUNTIME_ENABLED "false"
  set_env HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST ""
  set_env HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST ""
  set_env HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST ""
  set_env COMPOSE_PROJECT_NAME "$PROJECT"
  if [[ "$DRY_RUN" == "0" ]]; then
    exclude_secret_from_git ".env.sandbox"
  fi

  cp_port="$(env_value CONTROL_PLANE_PORT 8800)"
  if ask_yes_no "Keep the default Control Plane port (${cp_port})?" y; then
    :
  else
    cp_port="$(ask_port "Control Plane port" "$cp_port")"
    set_env CONTROL_PLANE_PORT "$cp_port"
  fi

  local -a compose_cmd=(docker compose --project-directory "$workdir" --env-file "$ENV_FILE" -p "$PROJECT")

  if [[ "$NO_START" == "1" || "$DRY_RUN" == "1" ]]; then
    info "Configuration ready (no services started)."
    print_sandbox_summary "$workdir" "$cp_port" "$PROJECT"
    echo "Start it yourself with:"
    printf '  %s up -d control-plane credential-service kubernetes-broker node-agent\n' "${compose_cmd[*]}"
    return 0
  fi

  if ask_yes_no "Start the sandbox now?" y; then
    info "Starting safe core services (no router, no Hermes bot, no Telegram)..."
    run "${compose_cmd[@]}" up -d control-plane credential-service kubernetes-broker node-agent
    wait_for_health "$cp_port"
  else
    info "Nothing was started. Start it later with:"
    printf '  %s up -d control-plane credential-service kubernetes-broker node-agent\n' "${compose_cmd[*]}"
  fi
  print_sandbox_summary "$workdir" "$cp_port" "$PROJECT"
}

flow_install() {
  info "Normal local install (full stack)"
  local provider with_hermes
  provider="$(menu "Router provider" 1 "nine-router [recommended]" "omniroute")"
  if ask_yes_no "Enable the Hermes bot profile? (needs TELEGRAM_BOT_TOKEN later via ./hermesctl bot telegram)" n; then
    with_hermes=1
  else
    with_hermes=0
  fi

  ENV_FILE="$ROOT/.env"
  prepare_env_file

  if [[ "$with_hermes" == "1" ]]; then
    warn "Hermes bot is enabled; do not expose it until TELEGRAM_BOT_TOKEN is configured."
  fi

  local -a compose_cmd=(docker compose --project-directory "$ROOT" --env-file "$ENV_FILE")
  local -a profile_flags=(--profile "$provider")
  [[ "$with_hermes" == "1" ]] && profile_flags+=(--profile hermes)

  if [[ "$NO_START" == "1" || "$DRY_RUN" == "1" ]]; then
    info "Install configuration ready (no services started)."
    echo "Start it yourself with:"
    printf '  %s %s up -d\n' "${compose_cmd[*]}" "${profile_flags[*]}"
    print_install_summary "$provider"
    return 0
  fi

  echo
  ok "About to install and start:"
  printf '  - Router profile:     %s\n' "$provider"
  printf '  - Hermes bot profile: %s\n' "$([[ "$with_hermes" == 1 ]] && printf 'enabled' || printf 'off')"
  if ! ask_yes_no "Start now?" y; then
    info "Nothing was started. Start it later with:"
    printf '  %s %s up -d\n' "${compose_cmd[*]}" "${profile_flags[*]}"
    print_install_summary "$provider"
    return 0
  fi

  info "Starting full stack ($provider profile)..."
  run "${compose_cmd[@]}" "${profile_flags[@]}" up -d
  wait_for_health "$(env_value CONTROL_PLANE_PORT 8800)"
  print_install_summary "$provider"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --flow) FLOW="${2:-}"; shift ;;
      --dir) TARGET_DIR="${2:-}"; shift ;;
      --project) PROJECT="${2:-}"; shift ;;
      --no-start) NO_START=1 ;;
      -h | --help) usage; exit 0 ;;
      *) echo "ERROR: unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
  done

  case "$FLOW" in
    "" ) ;;
    sandbox | install) ;;
    *) echo "ERROR: invalid --flow '$FLOW' (use sandbox or install)" >&2; exit 2 ;;
  esac

  local release
  release="$(file_env_value "$ROOT/.env.example" VERSION 0.5.11)"
  printf '\n%sHermes Control Plane v%s setup wizard%s\n' "$C_BOLD" "$release" "$C_RESET"
  printf '%s\n' '=============================================='
  preflight

  if [[ -z "$FLOW" ]]; then
    local flow_label
    flow_label="$(menu "What do you want to set up?" 1 \
      "Safe sandbox (isolated test environment) [recommended]" \
      "Normal local install (full stack)")"
    case "$flow_label" in
      Normal*) FLOW=install ;;
      *) FLOW=sandbox ;;
    esac
  fi

  case "$FLOW" in
    sandbox) flow_sandbox ;;
    install) flow_install ;;
  esac
}

main "$@"
