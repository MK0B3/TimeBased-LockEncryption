# Time-Locked Message Capsule - Makefile

.PHONY: all build run test clean deps help

# Variables
BINARY_DIR=bin
SERVER_BINARY=$(BINARY_DIR)/server
DECRYPT_BINARY=$(BINARY_DIR)/decrypt-service
DATA_DIR=data

# Default target
all: deps build

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Build both binaries
build: $(SERVER_BINARY) $(DECRYPT_BINARY)

# Build server
$(SERVER_BINARY):
	@echo "Building server..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(SERVER_BINARY) cmd/server/main.go

# Build decryption service
$(DECRYPT_BINARY):
	@echo "Building decryption service..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(DECRYPT_BINARY) cmd/decrypt-service/main.go

# Build with optimizations for production
build-prod:
	@echo "Building for production..."
	@mkdir -p $(BINARY_DIR)
	go build -ldflags="-s -w" -o $(SERVER_BINARY) cmd/server/main.go
	go build -ldflags="-s -w" -o $(DECRYPT_BINARY) cmd/decrypt-service/main.go

# Run server in development mode
run-server: $(SERVER_BINARY)
	@echo "Starting server..."
	@mkdir -p $(DATA_DIR)
	./$(SERVER_BINARY)

# Run decryption service
run-decrypt: $(DECRYPT_BINARY)
	@echo "Starting decryption service..."
	@mkdir -p $(DATA_DIR)
	./$(DECRYPT_BINARY)

# Run both services (requires GNU parallel or similar)
run-all: build
	@echo "Starting all services..."
	@mkdir -p $(DATA_DIR)
	@echo "Run these in separate terminals:"
	@echo "  make run-server"
	@echo "  make run-decrypt"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
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
	@mkdir -p web/static/css
	@mkdir -p web/static/js
	@mkdir -p web/templates
	@cp .env.example .env 2>/dev/null || true
	@echo "Setup complete! Edit .env if needed."

# Display help
help:
	@echo "Time-Locked Message Capsule - Available Commands:"
	@echo ""
	@echo "  make deps          - Install Go dependencies"
	@echo "  make build         - Build server and decryption service"
	@echo "  make build-prod    - Build with production optimizations"
	@echo "  make run-server    - Run the web server"
	@echo "  make run-decrypt   - Run the decryption service"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make bench         - Run benchmarks"
	@echo "  make fmt           - Format code"
	@echo "  make lint          - Lint code (requires golangci-lint)"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make clean-all     - Remove build artifacts and database"
	@echo "  make setup         - Setup development environment"
	@echo "  make help          - Display this help message"
