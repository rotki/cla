.PHONY: build build-tool run preview check check-image test test-verbose test-cover lint fmt vet tidy clean docker help

ENV_FILE := .env

ifneq (,$(wildcard $(ENV_FILE)))
  include $(ENV_FILE)
  export
endif

VERSION ?= dev
GIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/rotki/cla/internal/version.Version=$(VERSION) -X github.com/rotki/cla/internal/version.GitSHA=$(GIT_SHA)

build: ## Build the server binary
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o server ./cmd/cla-server

build-tool: ## Build the maintenance tool
	CGO_ENABLED=0 go build -trimpath -o cla-tool ./cmd/cla-tool

run: build ## Build and run with .env
	./server

preview: ## Serve the pages against a fake GitHub
	go test -v -tags preview -run TestPreview -timeout 0 ./internal/web

test: ## Run tests
	go test -race ./...

test-verbose: ## Run tests with verbose output
	go test -race -v ./...

test-cover: ## Run tests with coverage, per package
	go test -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	scripts/coverage.sh coverage.out

lint: ## Run golangci-lint
	golangci-lint run ./...

check: test lint ## Tests, lint, vulns, workflows, typos (CI also runs commit-lint and the image check)
	go vet -tags preview ./internal/web
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
	actionlint
	zizmor --persona auditor .github/workflows/
	typos

fmt: ## Format code
	gofmt -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy go.mod
	go mod tidy

clean: ## Remove build artifacts
	rm -f server cla-tool coverage.out

check-image: ## Build the image and check its build context and contents
	scripts/check-image.sh

docker: ## Build the docker image
	docker build --build-arg VERSION=$(VERSION) --build-arg GIT_SHA=$(GIT_SHA) -t rotki/cla:$(VERSION) .

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
