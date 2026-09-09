# Makefile pour tcpcat

BINARY_NAME=tcpcat
BUILD_DIR=dist
CMD_PATH=./cmd/tcpcat
LDFLAGS=-ldflags="-s -w"

.PHONY: all clean build-all build-linux build-windows build-mac

all: build-all

build-all: build-linux build-windows build-mac-arm build-mac-intel

build-linux:
	@echo "[*] Compiling for Linux (amd64)..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)

build-windows:
	@echo "[*] Compiling for Windows (amd64)..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)

build-mac-arm:
	@echo "[*] Compiling for macOS (Apple Silicon arm64)..."
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-mac-arm64 $(CMD_PATH)

build-mac-intel:
	@echo "[*] Compiling for macOS (Intel amd64)..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-mac-amd64 $(CMD_PATH)

clean:
	@echo "[*] Cleaning build directory..."
	@rm -rf $(BUILD_DIR)