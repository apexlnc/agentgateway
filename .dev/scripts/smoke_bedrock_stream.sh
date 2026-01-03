#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:18081}"

FIXTURE="${2:-basic_text}"

echo "== mock bedrock converse-stream fixture=${FIXTURE} =="
curl -sS -D- "${BASE}/model/mock/converse-stream" \
  -H "x-mock-fixture: ${FIXTURE}" \
  -H 'content-type: application/json' \
  -d '{"inputText":"ping"}' >/dev/null

echo "Sent request (body is binary eventstream). Use logs/agent parsing to validate."
