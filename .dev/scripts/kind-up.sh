#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-agw-dev}"
REG_NAME="${REG_NAME:-kind-registry}"
REG_HOST_PORT="${REG_HOST_PORT:-5001}"
# Default to a stable 1.33.x kindest node image.
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.33.4}"

if [ -z "$(docker ps -q -f name=^${REG_NAME}$)" ]; then
  docker run -d --restart=always \
    -p "127.0.0.1:${REG_HOST_PORT}:5000" \
    --name "${REG_NAME}" registry:2
fi

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "OK: kind cluster '${CLUSTER_NAME}' already exists"
else
  kind create cluster --name "${CLUSTER_NAME}" --config "$(dirname "$0")/../kind.yaml" --image "${KIND_NODE_IMAGE}"
fi
docker network connect "kind" "${REG_NAME}" 2>/dev/null || true

kubectl apply -f - <<EOF2
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REG_HOST_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF2

echo "OK: kind '${CLUSTER_NAME}' ready, registry localhost:${REG_HOST_PORT}"
