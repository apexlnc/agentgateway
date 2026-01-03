#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-kgateway-system}"
KGW_VERSION="${KGW_VERSION:-v2.1.2}"
GWAPI_VERSION="${GWAPI_VERSION:-v1.4.0}"

kubectl get ns "${NS}" >/dev/null 2>&1 || kubectl create ns "${NS}"

kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI_VERSION}/standard-install.yaml"

helm upgrade -i --create-namespace --namespace "${NS}" \
  --version "${KGW_VERSION}" \
  kgateway-crds oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds

helm upgrade -i -n "${NS}" \
  kgateway oci://cr.kgateway.dev/kgateway-dev/charts/kgateway \
  --version "${KGW_VERSION}" \
  --set agentgateway.enabled=true

kubectl rollout status deploy/kgateway -n "${NS}" --timeout=240s || true
echo "OK: kgateway installed"
