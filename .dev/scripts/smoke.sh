#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:8080}"

echo "== /v1/messages =="
curl -sS "${BASE}/v1/messages" -H 'content-type: application/json' \
  -d '{"model":"mock","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}' | jq .

echo "== /v1/chat/completions =="
curl -sS "${BASE}/v1/chat/completions" -H 'content-type: application/json' \
  -d '{"model":"mock","messages":[{"role":"user","content":"ping"}]}' | jq .
