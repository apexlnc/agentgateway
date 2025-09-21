# Image configuration
DOCKER_REGISTRY ?= ghcr.io
DOCKER_REPO ?= agentgateway
IMAGE_NAME ?= agentgateway
VERSION ?= $(shell git describe --tags --always --dirty)
IMAGE_TAG ?= $(VERSION)
IMAGE_FULL_NAME ?= $(DOCKER_REGISTRY)/$(DOCKER_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)
DOCKER_BUILDER ?= docker
DOCKER_BUILD_ARGS ?=
KIND_CLUSTER_NAME ?= agentgateway

# docker
.PHONY: docker
docker:
ifeq ($(OS),Windows_NT)
	$(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) -f Dockerfile.windows -t $(IMAGE_FULL_NAME) .
else
	$(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) -t $(IMAGE_FULL_NAME) . --progress=plain
endif

# docker-fast - optimized for development with dependency caching
.PHONY: docker-fast
docker-fast:
ifeq ($(OS),Windows_NT)
	$(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) -f Dockerfile.windows -t $(IMAGE_FULL_NAME) .
else
	@echo "Setting up optimized Docker build..."
	@if docker buildx inspect fast-builder >/dev/null 2>&1; then \
		echo "Using existing buildx builder: fast-builder"; \
	else \
		echo "Creating buildx builder with registry cache support..."; \
		docker buildx create --name fast-builder --driver docker-container --use >/dev/null 2>&1 || true; \
	fi
	@if docker buildx inspect fast-builder >/dev/null 2>&1; then \
		echo "Building with registry cache support..."; \
		DOCKER_BUILDKIT=1 docker buildx build $(DOCKER_BUILD_ARGS) \
			-f Dockerfile.fast \
			--builder fast-builder \
			--build-arg PROFILE=quick-release \
			--cache-from type=registry,ref=$(DOCKER_REGISTRY)/$(DOCKER_REPO)/$(IMAGE_NAME):buildcache \
			--cache-to type=registry,ref=$(DOCKER_REGISTRY)/$(DOCKER_REPO)/$(IMAGE_NAME):buildcache,mode=max \
			-t $(IMAGE_FULL_NAME) --load . --progress=plain; \
	else \
		echo "Buildx not available, falling back to local cache build..."; \
		DOCKER_BUILDKIT=1 $(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) \
			-f Dockerfile.fast \
			--build-arg PROFILE=quick-release \
			-t $(IMAGE_FULL_NAME) . --progress=plain; \
	fi
endif

# docker-fast-local - optimized build without registry caching (always works)
.PHONY: docker-fast-local
docker-fast-local:
ifeq ($(OS),Windows_NT)
	$(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) -f Dockerfile.windows -t $(IMAGE_FULL_NAME) .
else
	@echo "Building with local optimization (no registry cache)..."
	DOCKER_BUILDKIT=1 $(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) \
		-f Dockerfile.fast \
		--build-arg PROFILE=quick-release \
		-t $(IMAGE_FULL_NAME) . --progress=plain
endif

.PHONY: docker-musl
docker-musl:
	$(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS) -t $(IMAGE_FULL_NAME)-musl --build-arg=BUILDER=musl . --progress=plain

CARGO_BUILD_ARGS ?=
# build
.PHONY: build
build:
	cargo build --release --features ui $(CARGO_BUILD_ARGS)
.PHONY: build-target
build-target:
	cargo build --features ui $(CARGO_BUILD_ARGS) --target $(TARGET) --profile $(PROFILE)

# lint
.PHONY: lint
lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

.PHONY: fix-lint
fix-lint:
	cargo clippy --fix --allow-staged --allow-dirty --workspace
	cargo fmt

# test
.PHONY: test
test:
	cargo test --all-targets

# clean
.PHONY: clean
clean:
	cargo clean

objects := $(wildcard examples/*/config.json)

.PHONY: check-clean-repo
check-clean-repo:
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -Command common/scripts/check_clean_repo.ps1
else
	@common/scripts/check_clean_repo.sh
endif


.PHONY: gen
gen: generate-apis generate-schema fix-lint
	@:

.PHONY: generate-schema
generate-schema:
	@cargo xtask schema

# Code generation for xds apis
.PHONY: generate-apis
generate-apis:
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -Command common/tools/buf.ps1 generate --path crates/agentgateway/proto/resource.proto --path crates/agentgateway/proto/workload.proto
else
	@PATH=./common/tools:$(PATH) buf generate --path crates/agentgateway/proto/resource.proto --path crates/agentgateway/proto/workload.proto
endif

.PHONY: run-validation-deps
run-validation-deps:
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -Command common/scripts/manage-validation-deps.ps1 start
else
	@common/scripts/manage-validation-deps.sh start
endif

.PHONY: stop-validation-deps
stop-validation-deps:
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -Command common/scripts/manage-validation-deps.ps1 stop
else
	@common/scripts/manage-validation-deps.sh stop
endif

CONFIG_FILES := $(wildcard examples/*/config.yaml)
ifeq ($(CI),true)
ifeq ($(OS),Windows_NT)
# On Windows
CONFIG_FILES := $(filter-out examples/mcp-authentication/config.yaml, $(CONFIG_FILES))
endif
endif

.PHONY: validate
validate: run-validation-deps $(CONFIG_FILES) stop-validation-deps

.PHONY: $(CONFIG_FILES)
$(CONFIG_FILES):
	@cargo run -- -f $@ --validate-only
