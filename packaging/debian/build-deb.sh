#!/bin/bash
# Build script for creating Debian packages for tpm2-kira
# This script automates the entire Debian package building process

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_NAME="tpm2-kira"
BUILD_DIR="$PROJECT_ROOT/build/debian"
DIST_DIR="$PROJECT_ROOT/dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking build dependencies..."

    local missing_deps=()

    # Essential build tools
    if ! command_exists dpkg-buildpackage; then
        missing_deps+=("dpkg-dev")
    fi

    if ! command_exists debuild; then
        missing_deps+=("devscripts")
    fi

    if ! command_exists dh; then
        missing_deps+=("debhelper")
    fi

    if ! command_exists go; then
        missing_deps+=("golang-go")
    fi

    if ! command_exists git; then
        missing_deps+=("git")
    fi

    # Optional but recommended
    if ! command_exists lintian; then
        print_warning "lintian not found - package quality checks will be skipped"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Install them with:"
        echo "  sudo apt update"
        echo "  sudo apt install ${missing_deps[*]}"
        exit 1
    fi

    print_success "All required dependencies are installed"
}

# Function to get version from git
get_version() {
    cd "$PROJECT_ROOT"
    if git describe --tags --exact-match >/dev/null 2>&1; then
        git describe --tags --exact-match
    else
        echo "0.0.0"
    fi
}

# Function to prepare build environment
prepare_build_env() {
    print_status "Preparing build environment..."

    # Clean up any previous builds
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$DIST_DIR"

    # Get version
    VERSION=$(get_version)
    print_status "Building version: $VERSION"

    # Create source directory
    SOURCE_DIR="$BUILD_DIR/${PACKAGE_NAME}-${VERSION}"
    mkdir -p "$SOURCE_DIR"

    # Copy source files
    cd "$PROJECT_ROOT"
    cp -r . "$SOURCE_DIR/"

    # Remove build artifacts and git data
    cd "$SOURCE_DIR"
    rm -rf .git build dist
    rm -f "$PACKAGE_NAME" # Remove any existing binary

    # Copy debian packaging files
    cp -r packaging/debian debian/

    print_success "Build environment prepared in $SOURCE_DIR"
}

# Function to create source tarball
create_source_tarball() {
    print_status "Creating source tarball..."

    cd "$BUILD_DIR"
    VERSION=$(get_version)

    tar -czf "${PACKAGE_NAME}_${VERSION}.orig.tar.gz" \
        --exclude=debian \
        "${PACKAGE_NAME}-${VERSION}/"

    print_success "Source tarball created: ${PACKAGE_NAME}_${VERSION}.orig.tar.gz"
}

# Function to build package
build_package() {
    print_status "Building Debian package..."

    cd "$BUILD_DIR/${PACKAGE_NAME}-$(get_version)"

    # Make sure debian files are executable
    chmod +x debian/rules
    chmod +x debian/postinst debian/prerm

    # Build the package
    print_status "Running dpkg-buildpackage..."
    dpkg-buildpackage -us -uc -b

    print_success "Package build completed"
}

# Function to run quality checks
run_quality_checks() {
    if ! command_exists lintian; then
        print_warning "Skipping quality checks (lintian not installed)"
        return 0
    fi

    print_status "Running package quality checks..."

    cd "$BUILD_DIR"
    VERSION=$(get_version)

    # Run lintian on the .deb file
    if [ -f "${PACKAGE_NAME}_${VERSION}-1_"*.deb ]; then
        lintian "${PACKAGE_NAME}_${VERSION}-1_"*.deb || {
            print_warning "Lintian found some issues (this may be normal)"
        }
    else
        print_warning "Could not find .deb file for lintian check"
    fi
}

# Function to copy results to dist directory
copy_results() {
    print_status "Copying build results..."

    cd "$BUILD_DIR"
    VERSION=$(get_version)

    # Copy all generated files to dist directory
    cp "${PACKAGE_NAME}_${VERSION}"* "$DIST_DIR/" 2>/dev/null || true

    # List what was created
    echo ""
    print_success "Build artifacts created in $DIST_DIR:"
    ls -la "$DIST_DIR/${PACKAGE_NAME}_${VERSION}"* 2>/dev/null || {
        print_error "No build artifacts found!"
        return 1
    }
}

# Function to test installation (optional)
test_installation() {
    read -p "Do you want to test package installation? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Testing package installation..."

        cd "$BUILD_DIR"
        VERSION=$(get_version)
        DEB_FILE=$(ls "${PACKAGE_NAME}_${VERSION}-1_"*.deb 2>/dev/null | head -1)

        if [ -n "$DEB_FILE" ]; then
            print_status "Installing $DEB_FILE..."
            sudo dpkg -i "$DEB_FILE" || {
                print_warning "Installation failed, trying to fix dependencies..."
                sudo apt-get install -f
            }

            print_status "Testing tpm2-kira command..."
            if tpm2-kira version; then
                print_success "Package installed and working correctly"
            else
                print_error "Package installed but command not working"
            fi
        else
            print_error "Could not find .deb file to test"
        fi
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build Debian package for tpm2-kira"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -c, --clean      Clean build directory before building"
    echo "  -t, --test       Test installation after building"
    echo "  -q, --quick      Skip quality checks"
    echo ""
    echo "Environment variables:"
    echo "  DEBFULLNAME      Full name for package maintainer"
    echo "  DEBEMAIL         Email for package maintainer"
    echo ""
}

# Main function
main() {
    local clean_build=false
    local test_install=false
    local skip_quality=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--clean)
                clean_build=true
                shift
                ;;
            -t|--test)
                test_install=true
                shift
                ;;
            -q|--quick)
                skip_quality=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Header
    echo "=========================================="
    echo "  tpm2-kira Debian Package Builder"
    echo "=========================================="
    echo ""

    # Clean if requested
    if [ "$clean_build" = true ]; then
        print_status "Cleaning previous builds..."
        rm -rf "$BUILD_DIR" "$DIST_DIR"
    fi

    # Check dependencies
    check_dependencies

    # Build process
    prepare_build_env
    create_source_tarball
    build_package

    # Quality checks
    if [ "$skip_quality" = false ]; then
        run_quality_checks
    fi

    # Copy results
    copy_results

    # Test installation if requested
    if [ "$test_install" = true ]; then
        test_installation
    fi

    # Success message
    echo ""
    print_success "Debian package build completed successfully!"
    echo ""
    echo "To install the package:"
    echo "  sudo dpkg -i $DIST_DIR/${PACKAGE_NAME}_$(get_version)-1_*.deb"
    echo "  sudo apt-get install -f  # if there are dependency issues"
    echo ""
    echo "To upload to a repository:"
    echo "  dput your-repo $DIST_DIR/${PACKAGE_NAME}_$(get_version)-1_*.changes"
    echo ""
}

# Run main function with all arguments
main "$@"
