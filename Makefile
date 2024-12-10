.PHONY: test test-unit test-integration build clean

# Default target
all: clean build test

# Build the application
build:
	./build.sh

# Run all tests
test: test-unit test-integration

# Run unit tests only (with reduced memory usage)
test-unit:
	GOGC=50 go test -v -short -parallel 1 ./...

# Run integration tests only
test-integration:
	GOGC=50 go test -v -parallel 1 -run 'Integration' ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean -testcache

# Run tests with coverage
test-coverage:
	GOGC=50 go test -v -parallel 1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint the code
lint:
	golangci-lint run

# Security check
security-check:
	gosec ./...
