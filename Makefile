BINARY    := lnaudit
MODULE    := github.com/NonsoAmadi10/lnaudit
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS   := -s -w -X '$(MODULE)/cmd.Version=$(VERSION)' -X '$(MODULE)/cmd.CommitSHA=$(COMMIT)'
GOFLAGS   := -trimpath
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: all build install clean test test-verbose test-race coverage lint fmt vet check help release

all: check build ## Run all checks and build

build: ## Build the binary
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

install: ## Install to $GOPATH/bin
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" .

clean: ## Remove build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html

## ---------- Testing ----------

test: ## Run tests
	go test ./... -count=1

test-verbose: ## Run tests with verbose output
	go test ./... -count=1 -v

test-race: ## Run tests with race detector
	go test ./... -count=1 -race

coverage: ## Generate coverage report
	go test ./... -count=1 -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out
	@echo "---"
	@echo "To view HTML report: go tool cover -html=coverage.out -o coverage.html && open coverage.html"

## ---------- Code Quality ----------

fmt: ## Format code
	gofmt -s -w .
	goimports -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

check: fmt vet lint test ## Run all quality checks (format, vet, lint, test)

## ---------- Release ----------

release: clean ## Cross-compile for all platforms
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		output=dist/$(BINARY)-$${os}-$${arch}; \
		[ "$$os" = "windows" ] && output=$${output}.exe; \
		echo "Building $$output..."; \
		GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$output . || exit 1; \
	done
	@echo "Release binaries in dist/"

## ---------- Dev Setup ----------

dev-deps: ## Install development tools
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Dev tools installed. Ensure \$$GOPATH/bin is in your PATH."

## ---------- Help ----------

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
