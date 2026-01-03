#!/usr/bin/env bash
set -euo pipefail

# Common locations (override by exporting env vars)
export AGW_DEV_ROOT="${AGW_DEV_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export AGW_PR_ROOT="${AGW_PR_ROOT:-$(cd "${AGW_DEV_ROOT}/.." && pwd)/agentgateway-pr}"

# Ports
export AGW_LOCAL_PORT="${AGW_LOCAL_PORT:-18000}"  # agentgateway local mode
export AGW_K8S_PORT="${AGW_K8S_PORT:-8080}"       # port-forwarded Gateway in k8s mode

# Simple logging
log() { printf "\033[1;34m[dev]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[err]\033[0m %s\n" "$*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

# Try to find a "good" way to run tests in the PR worktree.
run_pr_tests() {
  log "Running Rust format/lint/tests in PR worktree: ${AGW_PR_ROOT}"
  pushd "${AGW_PR_ROOT}" >/dev/null

  if command -v cargo >/dev/null 2>&1; then
    # Keep this non-destructive by default; enable formatting explicitly if desired.
    if [[ "${AGW_RUN_FMT:-0}" == "1" ]]; then
      cargo fmt --all
    fi
    cargo clippy --all -- -D warnings
    cargo test --all
  else
    err "cargo not found; install rustup/cargo"
    exit 1
  fi

  popd >/dev/null
}

# If you have a local config file, source it.
load_local_env() {
  if [[ -f "${AGW_DEV_ROOT}/.dev/local.env" ]]; then
    log "Loading ${AGW_DEV_ROOT}/.dev/local.env"
    # shellcheck disable=SC1090
    source "${AGW_DEV_ROOT}/.dev/local.env"
  fi
}

# Curl helpers (non-stream + stream)
smoke_messages() {
  local base="$1"
  log "Smoke: POST ${base}/v1/messages"
  curl -sS "${base}/v1/messages" \
    -H 'content-type: application/json' \
    -d '{"model":"mock","max_tokens":32,"messages":[{"role":"user","content":"ping"}]}' \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}

smoke_messages_stream() {
  local base="$1"
  log "Smoke: POST ${base}/v1/messages (stream)"
  curl -N "${base}/v1/messages" \
    -H 'content-type: application/json' \
    -d '{"model":"mock","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"ping"}]}'
  echo
}

smoke_chat_completions() {
  local base="$1"
  log "Smoke: POST ${base}/v1/chat/completions"
  curl -sS "${base}/v1/chat/completions" \
    -H 'content-type: application/json' \
    -d '{"model":"mock","messages":[{"role":"user","content":"ping"}]}' \
    | (command -v jq >/dev/null 2>&1 && jq . || cat)
}
