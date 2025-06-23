# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=dehydrated-api-metadata-plugin-openssl

.PHONY: all build clean test deps tidy

all: clean build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

test:
	$(GOTEST) -v ./...

test-integration:
	$(GOTEST) -v -tags=integration ./...

test-all: test test-integration

deps:
	$(GOGET) -v ./...

tidy:
	$(GOMOD) tidy

# Development helpers
.PHONY: lint fmt

lint:
	golangci-lint run

fmt:
	$(GOCMD) fmt ./...

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all            - Clean and build the project"
	@echo "  build          - Build the project"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run unit tests (excludes integration tests)"
	@echo "  test-integration - Run integration tests (requires Netscaler instance)"
	@echo "  test-all       - Run both unit and integration tests"
	@echo "  deps           - Download dependencies"
	@echo "  tidy           - Tidy up dependencies"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo ""
