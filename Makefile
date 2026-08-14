# Time-Locked Message Capsule - Makefile

.PHONY: all deps build build-prod run test test-short test-coverage bench fmt vet lint clean clean-all setup help

# Variables
BINARY_DIR=bin
SERVER_BINARY=$(BINARY_DIR)/server
DATA_DIR=data

# Default target
all: deps build

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Build the server
build:
	@echo "Building server..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(SERVER_BINARY) ./cmd/server

# Build with optimizations for production
build-prod:
	@echo "Building for production..."
	@mkdir -p $(BINARY_DIR)
	go build -ldflags="-s -w" -o $(SERVER_BINARY) ./cmd/server

# Run the server
run: build
	@echo "Starting server..."
	@mkdir -p $(DATA_DIR)
	./$(SERVER_BINARY)

# Run all tests (requires network access to drand)
test:
	@echo "Running tests..."
	go test -v ./...

# Run only tests that do not need network access
test-short:
	@echo "Running short tests..."
	go test -short ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	go vet ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BINARY_DIR)
	rm -f coverage.out coverage.html

# Clean everything including database
clean-all: clean
	@echo "Cleaning database..."
	rm -rf $(DATA_DIR)

# Setup development environment
setup:
	@echo "Setting up development environment..."
	@mkdir -p $(DATA_DIR)
	@cp .env.example .env 2>/dev/null || true
	@echo "Setup complete! Edit .env if needed."

# Display help
help:
	@echo "Time-Locked Message Capsule - Available Commands:"
	@echo ""
	@echo "  make deps          - Install Go dependencies"
	@echo "  make build         - Build the server"
	@echo "  make build-prod    - Build with production optimizations"
	@echo "  make run           - Build and run the web server"
	@echo "  make test          - Run all tests (needs network)"
	@echo "  make test-short    - Run tests that do not need network"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make bench         - Run benchmarks"
	@echo "  make fmt           - Format code"
	@echo "  make vet           - Vet code"
	@echo "  make lint          - Lint code (requires golangci-lint)"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make clean-all     - Remove build artifacts and database"
	@echo "  make setup         - Setup development environment"
	@echo "  make help          - Display this help message"
