.PHONY: all build build-static clean install uninstall install-mkinitcpio uninstall-mkinitcpio deb test test-unit test-integration test-all fuzz fmt vet pkgbuild help

# Binary name
BINARY_NAME=tpm2-kira
INSTALL_PATH=/usr/local/bin

# Go parameters
GOCMD=go
# Every build is static and cgo-free: the same binary is copied into the
# initramfs, which has no libc. With cgo enabled (Go's default wherever a C
# compiler is installed) the net package alone links glibc dynamically.
GOBUILD=CGO_ENABLED=0 $(GOCMD) build
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

## build: Build the binary (static, CGO_ENABLED=0)
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v
	@$(GOCMD) version -m $(BINARY_NAME) | grep -q 'CGO_ENABLED=0' || \
		{ echo "Error: $(BINARY_NAME) was built with cgo"; exit 1; }

## build-static: Alias for build, which is always static
build-static: build

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
	sudo mkdir -p /etc/initcpio/install /etc/initcpio/post
	sudo cp initramfs/mkinitcpio/install/sd-tpm2-kira /etc/initcpio/install/
	sudo chmod +x /etc/initcpio/install/sd-tpm2-kira
	sudo cp initramfs/mkinitcpio/post/sd-tpm2-kira /etc/initcpio/post/
	sudo chmod +x /etc/initcpio/post/sd-tpm2-kira
	sudo mkdir -p /usr/lib/systemd/system
	sudo install -m644 initramfs/systemd/tpm2-kira.service initramfs/systemd/tpm2-kira-cap.service /usr/lib/systemd/system/
	@echo "Mkinitcpio hooks installed successfully!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit /etc/mkinitcpio.conf and add the hook BEFORE sd-encrypt:"
	@echo ""
	@echo "   HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)"
	@echo ""
	@echo "2. Set up and seal (if not already done; see README \"Choosing PCRs\"):"
	@echo "   tpm2-kira setup"
	@echo "   tpm2-kira seal --pcrs 0,7,11u"
	@echo ""
	@echo "3. Rebuild initramfs:"
	@echo "   sudo mkinitcpio -P"

## uninstall-mkinitcpio: Remove mkinitcpio hooks
uninstall-mkinitcpio:
	@echo "Uninstalling mkinitcpio hooks..."
	sudo rm -f /etc/initcpio/install/sd-tpm2-kira
	sudo rm -f /etc/initcpio/post/sd-tpm2-kira
	sudo rm -f /usr/lib/systemd/system/tpm2-kira.service /usr/lib/systemd/system/tpm2-kira-cap.service
	@echo "Mkinitcpio hooks uninstalled!"
	@echo "Note: You should rebuild your initramfs after removing hooks:"
	@echo "      sudo mkinitcpio -P"

## deb: Build the Debian package (version derived from git describe)
deb:
	@command -v dpkg-buildpackage >/dev/null 2>&1 || { \
		echo "Error: dpkg-buildpackage not found. Install dpkg-dev, debhelper and golang-go."; \
		exit 1; \
	}
	@DEB_VERSION=$$(packaging/deb-version.sh); \
	echo "Debian package version: $$DEB_VERSION"; \
	BACKUP=$$(mktemp); \
	cp debian/changelog "$$BACKUP"; \
	sed -i "1s/^tpm2-kira (.*)/tpm2-kira ($$DEB_VERSION)/" debian/changelog; \
	dpkg-buildpackage -us -uc; status=$$?; \
	cp "$$BACKUP" debian/changelog; rm -f "$$BACKUP"; \
	exit $$status

## test: Run unit tests (default)
test: test-unit

## test-unit: Run unit tests only
test-unit:
	@echo "Running unit tests..."
	$(GOTEST) -v -tags=unit ./cmd/...

## fuzz: Fuzz the parsers of untrusted input (FUZZTIME per target, default 30s)
FUZZTIME ?= 30s
fuzz:
	@for t in FuzzUnmarshalSealedBlob FuzzParseYubiKeyStub FuzzEventlogReplay; do \
		echo "Fuzzing $$t for $(FUZZTIME)..."; \
		$(GOTEST) -tags=unit ./cmd -run '^$$' -fuzz "^$$t\$$" -fuzztime $(FUZZTIME) || exit 1; \
	done
	@echo "Fuzzing FuzzDecode for $(FUZZTIME)..."
	$(GOTEST) ./internal/pcsc -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime $(FUZZTIME)

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
