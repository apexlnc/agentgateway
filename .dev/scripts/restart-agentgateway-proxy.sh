#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-kgateway-system}"

DEPLOY="$(kubectl -n "${NS}" get deploy -l app=agentgateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "${DEPLOY}" ]]; then
  DEPLOY="$(kubectl -n "${NS}" get deploy -o name | grep agentgateway | head -n1 | cut -d/ -f2 || true)"
fi
if [[ -z "${DEPLOY}" ]]; then
  kubectl -n "${NS}" get deploy
  exit 1
fi

kubectl -n "${NS}" rollout restart "deploy/${DEPLOY}"
kubectl -n "${NS}" rollout status "deploy/${DEPLOY}" --timeout=180s || true
echo "OK: restarted ${DEPLOY}"
