#!/usr/bin/env bash
set -euo pipefail

AGW_SRC="${AGW_SRC:-../agentgateway-pr}"
IMG="${IMG:-localhost:5001/agentgateway:dev}"

cd "${AGW_SRC}"
export DOCKER_BUILDKIT=1

if [[ ! -f "./Dockerfile" ]]; then
  echo "No Dockerfile in repo root. Add one or adjust build script."
  exit 1
fi

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo dev)}"
GIT_REVISION="${GIT_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

docker build -t "${IMG}" \
  --build-arg VERSION="${VERSION}" \
  --build-arg GIT_REVISION="${GIT_REVISION}" \
  .
docker push "${IMG}"
echo "OK: built+pushed ${IMG}"
