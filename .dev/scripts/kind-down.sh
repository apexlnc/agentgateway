#!/usr/bin/env bash
set -euo pipefail
CLUSTER_NAME="${CLUSTER_NAME:-agw-dev}"
kind delete cluster --name "${CLUSTER_NAME}" || true
echo "OK: kind deleted"
