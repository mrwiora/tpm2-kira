.PHONY: all build build-static verify-static clean install uninstall install-mkinitcpio uninstall-mkinitcpio deb test test-unit test-integration test-docker test-docker-all test-pcsc test-all fmt vet pkgbuild help

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
# CGO_ENABLED=0 is not an optimisation, it is the contract. This binary is
# installed and then copied into an initramfs by the mkinitcpio and
# initramfs-tools hooks, where no libc and no dynamic loader can be relied on.
# Left to the default, a machine with a C compiler produces a binary linked
# against libc, because the standard library uses cgo for host lookups and
# internal/pcsc imports net.
build:
	@echo "Building static $(BINARY_NAME) version $(VERSION)..."
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

## build-static: Alias for build, which is already static
build-static: build

## build-optimized: Build with optimizations (alias for build)
build-optimized: build

## verify-static: Assert the built binary needs no shared libraries or loader
verify-static: build
	@if readelf -d $(BINARY_NAME) | grep -q NEEDED; then \
		echo "FAIL: $(BINARY_NAME) links shared libraries:"; \
		readelf -d $(BINARY_NAME) | grep NEEDED; \
		exit 1; \
	fi
	@if readelf -l $(BINARY_NAME) | grep -q "interpreter"; then \
		echo "FAIL: $(BINARY_NAME) needs a dynamic loader, which an initramfs may not have:"; \
		readelf -l $(BINARY_NAME) | grep interpreter; \
		exit 1; \
	fi
	@echo "$(BINARY_NAME) is fully static: no NEEDED entries, no interpreter"

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
	@echo "Mkinitcpio hooks installed successfully!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit /etc/mkinitcpio.conf and add the hook BEFORE sd-encrypt:"
	@echo ""
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
	sudo rm -f /etc/initcpio/install/sd-tpm2-kira
	sudo rm -f /etc/initcpio/post/sd-tpm2-kira
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
	$(GOTEST) -v -tags=unit ./...

## test-docker: Run unit, integration and PC/SC tests in a container
##              BASE=debian:bookworm selects pcsc-lite 1.9.x instead of 2.x
BASE ?= debian:trixie
BASE_TAG = $(subst :,-,$(BASE))
test-docker:
	@echo "Building the test image from $(BASE)..."
	@docker build -q --build-arg BASE=$(BASE) -t tpm2-kira-test:$(BASE_TAG) test/docker
	@echo "Running tests in the container..."
	@docker run --rm \
		-v "$$(go env GOROOT)":/usr/local/go:ro \
		-v "$$(pwd)":/src:ro \
		-v "$$(go env GOMODCACHE)":/go/pkg/mod:ro \
		tpm2-kira-test:$(BASE_TAG)

## test-docker-all: Run the container tests against both pcsc-lite generations
test-docker-all:
	@$(MAKE) test-docker BASE=debian:trixie
	@$(MAKE) test-docker BASE=debian:bookworm

## test-pcsc: Run the PC/SC wire protocol tests against a local pcscd
##            Needs pcscd running and vsmartcard-vpcd configured
test-pcsc:
	@echo "Running PC/SC tests (requires a running pcscd with a virtual reader)..."
	$(GOTEST) -v -tags=pcsc -timeout 5m ./internal/pcsc/

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
	$(GOTEST) -v -tags=unit ./...
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
