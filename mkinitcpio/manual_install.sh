#!/bin/bash

# TPM2-Kira mkinitcpio Hook Installation Script
# This script installs the mkinitcpio hooks for tpm2-kira integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if tpm2-kira is installed
check_tpm2_kira() {
    if ! command -v tpm2-kira &> /dev/null; then
        print_error "tpm2-kira binary not found in PATH"
        print_info "Please install tpm2-kira first: make build && make install"
        exit 1
    fi
    print_success "tpm2-kira binary found: $(which tpm2-kira)"
}

# Check if mkinitcpio directories exist
check_mkinitcpio() {
    if [[ ! -d "/etc/initcpio" ]]; then
        print_error "mkinitcpio not found - /etc/initcpio directory missing"
        print_info "This system may not use mkinitcpio (Arch Linux based)"
        exit 1
    fi

    if [[ ! -d "/etc/initcpio/hooks" ]]; then
        mkdir -p /etc/initcpio/hooks
        print_info "Created /etc/initcpio/hooks directory"
    fi

    if [[ ! -d "/etc/initcpio/install" ]]; then
        mkdir -p /etc/initcpio/install
        print_info "Created /etc/initcpio/install directory"
    fi
}

# Install traditional hook
install_traditional_hook() {
    print_info "Installing traditional mkinitcpio hook..."

    cp hooks/tpm2-kira /etc/initcpio/hooks/
    chmod +x /etc/initcpio/hooks/tpm2-kira

    cp install/tpm2-kira /etc/initcpio/install/
    chmod +x /etc/initcpio/install/tpm2-kira

    print_success "Traditional hook installed (tpm2-kira)"
}

# Install systemd hook
install_systemd_hook() {
    print_info "Installing systemd mkinitcpio hook..."

    cp hooks/sd-tpm2-kira /etc/initcpio/hooks/
    chmod +x /etc/initcpio/hooks/sd-tpm2-kira

    cp install/sd-tpm2-kira /etc/initcpio/install/
    chmod +x /etc/initcpio/install/sd-tpm2-kira

    print_success "Systemd hook installed (sd-tpm2-kira)"
}

# Create systemd service directory if needed
setup_systemd_services() {
    if [[ ! -d "/usr/lib/systemd/system" ]]; then
        mkdir -p /usr/lib/systemd/system
        print_info "Created /usr/lib/systemd/system directory"
    fi
}

# Check current mkinitcpio configuration
check_mkinitcpio_config() {
    print_info "Checking current mkinitcpio configuration..."

    if [[ -f "/etc/mkinitcpio.conf" ]]; then
        if grep -q "^HOOKS=" /etc/mkinitcpio.conf; then
            current_hooks=$(grep "^HOOKS=" /etc/mkinitcpio.conf)
            print_info "Current HOOKS line: $current_hooks"

            if echo "$current_hooks" | grep -q "systemd"; then
                print_info "Systemd-based initramfs detected"
                print_warning "Add 'sd-tpm2-kira' to your HOOKS array"
            else
                print_info "Traditional initramfs detected"
                print_warning "Add 'tpm2-kira' to your HOOKS array"
            fi
        else
            print_warning "No HOOKS line found in /etc/mkinitcpio.conf"
        fi
    else
        print_warning "/etc/mkinitcpio.conf not found"
    fi
}

# Show post-installation instructions
show_instructions() {
    echo
    print_success "Installation completed!"
    echo
    print_info "Next steps:"
    echo "1. Edit /etc/mkinitcpio.conf and add the appropriate hook:"
    echo "   - For traditional initramfs: add 'tpm2-kira' to HOOKS"
    echo "   - For systemd initramfs: add 'sd-tpm2-kira' to HOOKS"
    echo
    echo "   Example traditional HOOKS line:"
    echo "   HOOKS=(base udev autodetect modconf block filesystems keyboard fsck tpm2-kira)"
    echo
    echo "   Example systemd HOOKS line:"
    echo "   HOOKS=(base systemd autodetect modconf block filesystems keyboard fsck sd-tpm2-kira)"
    echo
    echo "2. Seal a TOTP secret (if not already done):"
    echo "   tpm2-kira seal --password \"your-secure-password\""
    echo
    echo "3. Rebuild initramfs:"
    echo "   mkinitcpio -P"
    echo
    echo "4. Reboot to test the integration"
    echo
    print_warning "Important: Make sure you have sealed a TOTP secret before rebooting!"
}

# Main installation function
main() {
    echo "TPM2-Kira mkinitcpio Hook Installer"
    echo "=================================="
    echo

    # Change to script directory
    cd "$(dirname "$0")"

    # Perform checks
    check_root
    check_tpm2_kira
    check_mkinitcpio

    # Install hooks
    install_traditional_hook
    install_systemd_hook
    setup_systemd_services

    # Check configuration and show instructions
    check_mkinitcpio_config
    show_instructions
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "TPM2-Kira mkinitcpio Hook Installer"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --traditional  Install only traditional hook"
        echo "  --systemd      Install only systemd hook"
        echo
        echo "With no options, installs both hooks."
        exit 0
        ;;
    --traditional)
        cd "$(dirname "$0")"
        check_root
        check_tpm2_kira
        check_mkinitcpio
        install_traditional_hook
        print_success "Traditional hook installed"
        ;;
    --systemd)
        cd "$(dirname "$0")"
        check_root
        check_tpm2_kira
        check_mkinitcpio
        install_systemd_hook
        setup_systemd_services
        print_success "Systemd hook installed"
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
