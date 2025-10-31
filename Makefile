ifeq ($(OS),Windows_NT)
	CLEAR_COMMAND = @cls
else
	CLEAR_COMMAND = @clear
endif

# Directory for build artifacts.
BIN_DIR := ./bin

# Path for the main application binary.
TARGET := $(BIN_DIR)/kangaroo

# Path for the key generator CLI binary.
KEY_GEN_TARGET := $(BIN_DIR)/kangaroo-key-gen

# Source path for the main application.
CMD_MAIN := .

# Source path for the key generator CLI.
CMD_KEY_GEN := ./cmd/key_gen/key_gen.go

# All packages to test.
TEST_PACKAGES := ./...

# Additional arguments (e.g., make run ARGS="-v").
ARGS :=

.PHONY: all build run key-gen test test-verbose test-race test-race-verbose clean help _main_build _key_gen_build

all: build

# ==============================================================================
# Build Commands
# ==============================================================================

# build: Build all binaries.
build: _main_build _key_gen_build

# _main_build: Build the main application.
_main_build:
	@echo "=> Building Go application..."
	@go build -o $(TARGET) $(CMD_MAIN)

# _key_gen_build: Build the key generator CLI.
_key_gen_build:
	@echo "=> Building Go key-generator..."
	@go build -o $(KEY_GEN_TARGET) $(CMD_KEY_GEN)

# ==============================================================================
# Run Commands
# ==============================================================================

# run: Build and run the main application.
run:
	@$(CLEAR_COMMAND)
	@echo "=> Running application..."
	@$(TARGET) $(ARGS)

# key-gen: Build and run the key generator CLI.
key-gen:
	@echo "=> Running key generator..."
	@$(KEY_GEN_TARGET) $(ARGS)

# ==============================================================================
# Test Commands
# ==============================================================================

test:
	@echo "=> Running Go tests..."
	@go test $(TEST_PACKAGES)

test-verbose:
	@echo "=> Running Go tests (verbose)..."
	@go test -v $(TEST_PACKAGES)

test-race:
	@echo "=> Running Go tests with race detector..."
	@go test -race $(TEST_PACKAGES)

test-race-verbose:
	@echo "=> Running Go tests with race detector (verbose)..."
	@go test -v -race $(TEST_PACKAGES)

# ==============================================================================
# Cleanup & Help
# ==============================================================================

# clean: Remove all build artifacts (the entire bin directory).
clean:
	@echo "=> Cleaning up..."
	@rm -rf $(BIN_DIR)

help:
	@echo "Available commands:"
	@echo "  build             - Build all binaries"
	@echo "  run               - Build and run the main application"
	@echo "  key-gen           - Build and run the key generator CLI"
	@echo "  test              - Run Go unit tests"
	@echo "  test-verbose      - Run Go unit tests verbosely"
	@echo "  test-race         - Run Go unit tests with the race detector"
	@echo "  test-race-verbose - Run tests with race detector and verbose output"
	@echo "  clean             - Clean up all build artifacts"
	@echo "  help              - Show this help message"