ifeq ($(OS),Windows_NT)
	CLEAR_COMMAND = @cls
else
	CLEAR_COMMAND = @clear
endif

.PHONY: all build run test test-verbose test-race test-race-verbose clean help

all: build

# ==============================================================================
# Go Application Commands
# ==============================================================================

test:
	@echo "=> Running Go tests..."
	@go test -run='^Test' ./...

test-verbose:
	@echo "=> Running Go tests (verbose)..."
	@go test -v -run='^Test' ./...

test-race:
	@echo "=> Running Go tests with race detector..."
	@go test -race -run='^Test' ./...

build:
	@echo "=> Building Go application..."
	@go build -o ./bin/kangaroo .

run: build
	@$(CLEAR_COMMAND)
	./bin/kangaroo $(ARGS)

# ==============================================================================
# Cleanup & Help
# ==============================================================================

clean:
	@echo "=> Cleaning up..."
	@rm -f ./bin/kangaroo

help:
	@echo "Available commands:"
	@echo "  build             - Build the Go application"
	@echo "  run               - Run the Go application"
	@echo "  test              - Run Go unit tests"
	@echo "  test-verbose      - Run Go unit tests verbosely"
	@echo "  test-race         - Run Go unit tests with the race detector"
	@echo "  clean             - Clean up all build artifacts"
	@echo "  help              - Show this help message"