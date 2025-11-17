.PHONY: help build run test clean docker-build docker-up docker-down migrate-up migrate-down lint format

# Variables
BINARY_NAME=audit-sentinel
DOCKER_COMPOSE=docker-compose
GO_CMD=go
GO_BUILD=$(GO_CMD) build
GO_TEST=$(GO_CMD) test
GO_LINT=golangci-lint
GO_FMT=gofmt

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the application
	$(GO_BUILD) -o bin/$(BINARY_NAME) ./cmd/api

run: ## Run the application locally
	$(GO_CMD) run ./cmd/api

test: ## Run tests
	$(GO_TEST) -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	$(GO_CMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linter
	$(GO_LINT) run ./...

format: ## Format code
	$(GO_FMT) -w .

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

migrate-up: ## Run database migrations up
	$(GO_CMD) run ./cmd/migrate up

migrate-down: ## Run database migrations down
	$(GO_CMD) run ./cmd/migrate down

docker-build: ## Build Docker images
	$(DOCKER_COMPOSE) build

docker-up: ## Start Docker containers
	$(DOCKER_COMPOSE) up -d

docker-down: ## Stop Docker containers
	$(DOCKER_COMPOSE) down

docker-logs: ## View Docker logs
	$(DOCKER_COMPOSE) logs -f

docker-ps: ## List Docker containers
	$(DOCKER_COMPOSE) ps

dev: docker-up ## Start development environment
	@echo "Development environment started!"
	@echo "Backend API: http://localhost:8080"
	@echo "Frontend: http://localhost:3000"
	@echo "Prometheus: http://localhost:9091"

deps: ## Download dependencies
	$(GO_CMD) mod download
	$(GO_CMD) mod tidy

install-tools: ## Install development tools
	$(GO_CMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO_CMD) install github.com/golang-migrate/migrate/v4/cmd/migrate@latest

