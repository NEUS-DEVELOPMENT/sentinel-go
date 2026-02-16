# Build configuration
BINARY_NAME=agent
BUILD_DIR=bin
MAIN_FILE=main.go

# Compiler flags for Stealth and Performance
# -s: Omit the symbol table and debug information
# -w: Omit the DWARF symbol table
LDFLAGS=-ldflags="-s -w"

all: build

build:
	@echo "Engineering the static binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_FILE)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

run:
	@go run $(MAIN_FILE)

help:
	@echo "Available commands:"
	@echo "  make build - Create a stripped, static binary"
	@echo "  make clean - Remove build artifacts"
	@echo "  make run   - Run the agent in development mode"
