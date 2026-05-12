.DEFAULT_GOAL := help

# Build-time identity, injected via -ldflags so `stac-proxy --version`
# reports something meaningful instead of "dev/unknown/unknown".
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(BUILD_DATE)

GO       ?= go
PKG       := ./...
BIN       := stac-proxy
IMAGE     ?= ghcr.io/yourorg/stac-proxy
IMAGE_TAG ?= $(VERSION)

##@ Build

.PHONY: build
build: ## Build the binary at ./stac-proxy
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/stac-proxy

.PHONY: install
install: ## go install with ldflags
	$(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/stac-proxy

##@ Quality

.PHONY: test
test: ## Run all unit + integration tests
	$(GO) test $(PKG)

.PHONY: race
race: ## Run tests with the race detector
	$(GO) test -race $(PKG)

.PHONY: cover
cover: ## Generate coverage profile at coverage.out
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic $(PKG)

.PHONY: lint
lint: ## Run golangci-lint over the whole module
	golangci-lint run $(PKG)

.PHONY: vet
vet: ## go vet shortcut
	$(GO) vet $(PKG)

.PHONY: ci
ci: lint race ## What CI runs

##@ Run

.PHONY: validate-config
validate-config: build ## Validate configs/example.yaml + federation-example.yaml
	./$(BIN) --validate --config configs/example.yaml
	./$(BIN) --validate --config configs/federation-example.yaml

.PHONY: run
run: build ## Run with configs/example.yaml
	./$(BIN) --config configs/example.yaml

##@ Container

.PHONY: image
image: ## Build the container image as $(IMAGE):$(IMAGE_TAG)
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(IMAGE_TAG) \
		-t $(IMAGE):latest \
		-f deployments/docker/Dockerfile .

.PHONY: compose-up
compose-up: ## docker compose up -d
	docker compose -f deployments/docker/docker-compose.yaml up -d

.PHONY: compose-down
compose-down: ## docker compose down
	docker compose -f deployments/docker/docker-compose.yaml down

##@ Misc

.PHONY: clean
clean: ## Remove build artefacts
	rm -f $(BIN) coverage.out

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
