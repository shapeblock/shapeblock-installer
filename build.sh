#!/bin/bash

CLI_NAME="shapeblock-installer"
BIN_DIR="bin"

# Create bin directory if it doesn't exist
mkdir -p ${BIN_DIR}

# Check if GH_TOKEN is set
if [ -z "${GH_TOKEN}" ]; then
    echo "Error: GH_TOKEN environment variable is not set"
    exit 1
fi

# Set version to "latest" by default, override with VERSION env var if set
VERSION=${VERSION:-latest}

# Basic build with version and GitHub token
go build -ldflags="-X main.Version=${VERSION} -X main.githubToken=${GH_TOKEN}" -o ${BIN_DIR}/${CLI_NAME} main.go

# Cross-compile for Linux (64-bit) with version and GitHub token
GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=${VERSION} -X main.githubToken=${GH_TOKEN}" -o ${BIN_DIR}/${CLI_NAME}-linux-amd64 main.go

# Build with optimizations, version and GitHub token
go build -ldflags="-s -w -X main.Version=${VERSION} -X main.githubToken=${GH_TOKEN}" -o ${BIN_DIR}/${CLI_NAME} main.go
