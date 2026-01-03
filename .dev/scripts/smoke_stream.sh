#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:8080}"

echo "== /v1/messages stream (expect SSE) =="
curl -N "${BASE}/v1/messages" \
  -H 'content-type: application/json' \
  -d '{"model":"mock","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"ping"}]}'
echo
