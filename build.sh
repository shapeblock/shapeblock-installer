#!/bin/bash

CLI_NAME="shapeblock-installer"
VERSION="1.0.0"
BIN_DIR="bin"

# Create bin directory if it doesn't exist
mkdir -p ${BIN_DIR}

# Basic build
go build -o ${BIN_DIR}/${CLI_NAME} main.go

# Cross-compile for different platforms
# For Linux (64-bit)
GOOS=linux GOARCH=amd64 go build -o ${BIN_DIR}/${CLI_NAME}-linux-amd64 main.go

# For macOS (64-bit)
GOOS=darwin GOARCH=amd64 go build -o ${BIN_DIR}/${CLI_NAME}-darwin-amd64 main.go

# Build with version information
go build -ldflags="-X main.Version=${VERSION}" -o ${BIN_DIR}/${CLI_NAME} main.go

# Build with optimizations
go build -ldflags="-s -w" -o ${BIN_DIR}/${CLI_NAME} main.go
