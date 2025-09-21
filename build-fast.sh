#!/bin/bash
set -e

# Optimized Docker build script for development
# This script uses all the performance optimizations for fast incremental builds

# Configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker-registry-cache.nydig-dev.cloud}"
DOCKER_REPO="${DOCKER_REPO:-agentgateway}"
IMAGE_NAME="${IMAGE_NAME:-agentgateway}"
VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
PLATFORM="${PLATFORM:-linux/arm64}"

echo "🚀 Starting optimized Docker build..."
echo "   Registry: $DOCKER_REGISTRY"
echo "   Platform: $PLATFORM"
echo "   Version: $VERSION"

# Enable BuildKit for maximum performance
export DOCKER_BUILDKIT=1
export BUILDKIT_PROGRESS=plain

# Build with all optimizations
DOCKER_BUILD_ARGS="--platform $PLATFORM \
    --build-arg PROFILE=quick-release \
    --cache-from type=registry,ref=$DOCKER_REGISTRY/$DOCKER_REPO/$IMAGE_NAME:buildcache \
    --cache-to type=registry,ref=$DOCKER_REGISTRY/$DOCKER_REPO/$IMAGE_NAME:buildcache,mode=max"

echo "🔧 Build args: $DOCKER_BUILD_ARGS"

# Run the optimized build
make docker-fast \
    DOCKER_REGISTRY="$DOCKER_REGISTRY" \
    DOCKER_BUILD_ARGS="$DOCKER_BUILD_ARGS"

echo "✅ Build complete!"
echo "   Image: $DOCKER_REGISTRY/$DOCKER_REPO/$IMAGE_NAME:$VERSION"