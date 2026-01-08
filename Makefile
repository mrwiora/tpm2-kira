.PHONY: all build clean install uninstall install-mkinitcpio uninstall-mkinitcpio test test-unit test-integration test-all fmt vet pkgbuild help

# Binary name
BINARY_NAME=tpm2-kira
INSTALL_PATH=/usr/local/bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

# Get version from git
GIT_VERSION := $(shell git describe --tags 2>/dev/null)
GIT_DIRTY := $(shell git diff --quiet 2>/dev/null || echo "-dirty")

# Determine version
ifeq ($(GIT_VERSION),)
    VERSION := 0.0.0
else
    VERSION := $(GIT_VERSION)
endif

# Append dirty state if working directory has changes
ifneq ($(GIT_DIRTY),)
    VERSION := $(VERSION)$(GIT_DIRTY)
endif

# Build flags
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

all: build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

## build-optimized: Build with optimizations (alias for build)
build-optimized: build

## clean: Clean build files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf build/

## install: Install binary to system
install: build-optimized
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo cp $(BINARY_NAME) $(INSTALL_PATH)/
	sudo chmod 755 $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Installation complete!"

## uninstall: Remove binary from system
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstallation complete!"

## install-mkinitcpio: Install mkinitcpio hooks for early boot integration
install-mkinitcpio:
	@echo "Installing mkinitcpio hooks..."
	@if [ ! -f "$(BINARY_NAME)" ]; then \
		echo "Error: $(BINARY_NAME) not built. Run 'make build' first."; \
		exit 1; \
	fi
	@if ! command -v $(BINARY_NAME) >/dev/null 2>&1; then \
		echo "Warning: $(BINARY_NAME) not in PATH. Install binary first with 'make install'."; \
	fi
	@if [ ! -d "/etc/initcpio" ]; then \
		echo "Error: mkinitcpio not found. This system may not use mkinitcpio."; \
		exit 1; \
	fi
	sudo mkdir -p /etc/initcpio/hooks /etc/initcpio/install
	sudo cp mkinitcpio/hooks/tpm2-kira /etc/initcpio/hooks/
	sudo cp mkinitcpio/install/tpm2-kira /etc/initcpio/install/
	sudo cp mkinitcpio/hooks/sd-tpm2-kira /etc/initcpio/hooks/
	sudo cp mkinitcpio/install/sd-tpm2-kira /etc/initcpio/install/
	sudo chmod +x /etc/initcpio/hooks/tpm2-kira /etc/initcpio/install/tpm2-kira
	sudo chmod +x /etc/initcpio/hooks/sd-tpm2-kira /etc/initcpio/install/sd-tpm2-kira
	sudo mkdir -p /usr/lib/systemd/system
	@echo "Mkinitcpio hooks installed successfully!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit /etc/mkinitcpio.conf and add the appropriate hook BEFORE encrypt hooks:"
	@echo "   - For traditional initramfs: add 'tpm2-kira' before 'encrypt'"
	@echo "   - For systemd initramfs: add 'sd-tpm2-kira' before 'sd-encrypt'"
	@echo ""
	@echo "   Example HOOKS lines (with encryption):"
	@echo "   HOOKS=(base udev autodetect modconf block keyboard tpm2-kira encrypt filesystems fsck)"
	@echo "   HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)"
	@echo ""
	@echo "2. Seal a TOTP secret (if not already done):"
	@echo "   tpm2-kira seal"
	@echo "   (You will be prompted to enter an optional password securely)"
	@echo ""
	@echo "3. Rebuild initramfs:"
	@echo "   sudo mkinitcpio -P"

## uninstall-mkinitcpio: Remove mkinitcpio hooks
uninstall-mkinitcpio:
	@echo "Uninstalling mkinitcpio hooks..."
	sudo rm -f /etc/initcpio/hooks/tpm2-kira
	sudo rm -f /etc/initcpio/install/tpm2-kira
	sudo rm -f /etc/initcpio/hooks/sd-tpm2-kira
	sudo rm -f /etc/initcpio/install/sd-tpm2-kira
	@echo "Mkinitcpio hooks uninstalled!"
	@echo "Note: You should rebuild your initramfs after removing hooks:"
	@echo "      sudo mkinitcpio -P"

## test: Run unit tests (default)
test: test-unit

## test-unit: Run unit tests only
test-unit:
	@echo "Running unit tests..."
	$(GOTEST) -v -tags=unit ./cmd/...

## test-integration: Run integration tests with software TPM
test-integration:
	@echo "Running integration tests..."
	@echo "Note: Requires swtpm (software TPM) to be installed"
	@echo "Install with: sudo apt-get install swtpm swtpm-tools socat"
	$(GOTEST) -v -tags=integration -timeout 10m ./...

## test-all: Run all tests (unit + integration)
test-all:
	@echo "Running all tests..."
	@echo "Unit tests:"
	$(GOTEST) -v -tags=unit ./cmd/...
	@echo ""
	@echo "Integration tests:"
	@echo "Note: Requires swtpm (software TPM) to be installed"
	$(GOTEST) -v -tags=integration -timeout 10m ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## pkgbuild: Build Arch Linux package
pkgbuild:
	@echo "Building Arch Linux package..."
	@if ! command -v makepkg >/dev/null 2>&1; then \
		echo "Error: makepkg not found. This target requires Arch Linux or an Arch-based distribution."; \
		exit 1; \
	fi
	@echo "Copying PKGBUILD to build directory..."
	@mkdir -p build/aur
	@cp packaging/aur/PKGBUILD build/aur/
	@cd build/aur && makepkg -f
	@echo ""
	@echo "Package built successfully!"
	@echo "Package location: build/aur/"
	@ls -lh build/aur/*.pkg.tar.zst 2>/dev/null || ls -lh build/aur/*.pkg.tar.* 2>/dev/null || true
	@echo ""
	@echo "To install the package, run:"
	@echo "  sudo pacman -U build/aur/tpm2-kira-*.pkg.tar.zst"

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
	@echo ""
	@echo "Test Requirements:"
	@echo "  Unit tests: No special requirements"
	@echo "  Integration tests: Requires swtpm, swtpm-tools, and socat"
	@echo "    Install with: sudo apt-get install swtpm swtpm-tools socat"
	@echo ""
	@echo "Mkinitcpio Integration:"
	@echo "  install-mkinitcpio: Install early boot hooks for Arch Linux"
	@echo "  uninstall-mkinitcpio: Remove early boot hooks"
