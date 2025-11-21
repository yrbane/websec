#!/bin/bash
#
# WebSec Interactive Installation Script
#
# This script automates the complete deployment of WebSec with:
# - Dependency checking and installation
# - Rust toolchain setup
# - System user creation
# - Repository cloning and compilation
# - Linux capabilities configuration
# - Binary verification
#
# Usage: sudo bash install.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WEBSEC_USER="websec"
INSTALL_DIR="/opt/websec"
RUST_VERSION="stable"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to ask user confirmation
ask_confirmation() {
    local prompt="$1"
    local default="${2:-n}"

    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$prompt" response
    response=${response:-$default}

    [[ "$response" =~ ^[Yy]$ ]]
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect package manager
detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local pkg_manager=$(detect_package_manager)
    local missing_deps=()

    print_info "Checking system dependencies..."

    # Check required packages
    local required_packages=(
        "git"
        "gcc"
        "pkg-config"
        "libssl-dev"
        "redis-server"
    )

    for pkg in "${required_packages[@]}"; do
        case "$pkg_manager" in
            apt)
                if ! dpkg -l | grep -q "^ii  $pkg"; then
                    missing_deps+=("$pkg")
                fi
                ;;
            dnf|yum)
                if [[ "$pkg" == "libssl-dev" ]]; then
                    pkg="openssl-devel"
                elif [[ "$pkg" == "redis-server" ]]; then
                    pkg="redis"
                fi
                if ! rpm -qa | grep -q "$pkg"; then
                    missing_deps+=("$pkg")
                fi
                ;;
            pacman)
                if [[ "$pkg" == "libssl-dev" ]]; then
                    pkg="openssl"
                elif [[ "$pkg" == "redis-server" ]]; then
                    pkg="redis"
                fi
                if ! pacman -Q "$pkg" >/dev/null 2>&1; then
                    missing_deps+=("$pkg")
                fi
                ;;
        esac
    done

    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        print_success "All dependencies are already installed"
        return 0
    fi

    print_warning "Missing dependencies: ${missing_deps[*]}"

    # Generate install command
    local install_cmd=""
    case "$pkg_manager" in
        apt)
            install_cmd="apt-get update && apt-get install -y ${missing_deps[*]}"
            ;;
        dnf)
            install_cmd="dnf install -y ${missing_deps[*]}"
            ;;
        yum)
            install_cmd="yum install -y ${missing_deps[*]}"
            ;;
        pacman)
            install_cmd="pacman -S --noconfirm ${missing_deps[*]}"
            ;;
        *)
            print_error "Unknown package manager. Please install manually: ${missing_deps[*]}"
            exit 1
            ;;
    esac

    echo -e "\nCommand to install dependencies:"
    echo -e "${GREEN}$install_cmd${NC}\n"

    if ask_confirmation "Do you want to install these dependencies now?"; then
        print_info "Installing dependencies..."
        eval "$install_cmd"
        print_success "Dependencies installed successfully"
    else
        print_error "Cannot proceed without dependencies. Exiting."
        exit 1
    fi
}

# Function to install Rust
install_rust() {
    print_info "Checking Rust installation..."

    # Check if running as root user (not just with sudo)
    if [[ -n "$SUDO_USER" ]]; then
        local real_user="$SUDO_USER"
        local real_home=$(eval echo ~"$real_user")
    else
        local real_user="root"
        local real_home="$HOME"
    fi

    # Check if Rust is installed for the real user
    if sudo -u "$real_user" bash -c "command -v cargo >/dev/null 2>&1"; then
        local rust_version=$(sudo -u "$real_user" bash -c "rustc --version 2>/dev/null || echo 'unknown'")
        print_success "Rust is already installed: $rust_version"
        return 0
    fi

    print_warning "Rust is not installed"
    echo -e "\nCommand to install Rust:"
    echo -e "${GREEN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y${NC}\n"

    if ask_confirmation "Do you want to install Rust now?"; then
        print_info "Installing Rust for user $real_user..."
        sudo -u "$real_user" bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"

        # Source cargo env for this session
        export PATH="$real_home/.cargo/bin:$PATH"

        print_success "Rust installed successfully"
        sudo -u "$real_user" bash -c "source $real_home/.cargo/env && rustc --version"
    else
        print_error "Cannot proceed without Rust. Exiting."
        exit 1
    fi
}

# Function to create websec user
create_websec_user() {
    print_info "Checking websec system user..."

    if id "$WEBSEC_USER" &>/dev/null; then
        print_success "User '$WEBSEC_USER' already exists"
        return 0
    fi

    print_warning "User '$WEBSEC_USER' does not exist"
    echo -e "\nCommand to create user:"
    echo -e "${GREEN}useradd -r -s /bin/false -d $INSTALL_DIR $WEBSEC_USER${NC}\n"

    if ask_confirmation "Do you want to create the websec user now?" "y"; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$WEBSEC_USER"
        print_success "User '$WEBSEC_USER' created successfully"
    else
        print_error "Cannot proceed without websec user. Exiting."
        exit 1
    fi
}

# Function to clone repository
clone_repository() {
    print_info "Checking WebSec repository..."

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        print_success "Repository already exists at $INSTALL_DIR"

        if ask_confirmation "Do you want to update the repository?"; then
            print_info "Updating repository..."
            cd "$INSTALL_DIR"
            git pull
            print_success "Repository updated"
        fi
        return 0
    fi

    if [[ -d "$INSTALL_DIR" ]] && [[ -n "$(ls -A "$INSTALL_DIR")" ]]; then
        print_warning "Directory $INSTALL_DIR exists but is not a git repository"
        if ! ask_confirmation "Do you want to remove it and clone fresh?"; then
            print_error "Cannot proceed. Exiting."
            exit 1
        fi
        rm -rf "$INSTALL_DIR"
    fi

    print_info "Cloning WebSec repository to $INSTALL_DIR..."

    # Get the current repository URL
    local current_dir=$(pwd)
    local repo_url=""

    if git rev-parse --git-dir > /dev/null 2>&1; then
        repo_url=$(git config --get remote.origin.url)
        print_info "Using repository URL: $repo_url"
    else
        print_warning "Not in a git repository. Using default GitHub URL."
        repo_url="https://github.com/yrbane/websec.git"
    fi

    git clone "$repo_url" "$INSTALL_DIR"
    print_success "Repository cloned successfully"
}

# Function to compile WebSec
compile_websec() {
    print_info "Compiling WebSec..."

    cd "$INSTALL_DIR"

    # Determine which user should compile
    if [[ -n "$SUDO_USER" ]]; then
        local build_user="$SUDO_USER"
        local real_home=$(eval echo ~"$build_user")
    else
        local build_user="root"
        local real_home="$HOME"
    fi

    print_info "Compiling as user: $build_user"

    # Source cargo environment and build
    sudo -u "$build_user" bash -c "
        source $real_home/.cargo/env
        cd $INSTALL_DIR
        cargo build --release --features tls
    "

    if [[ -f "$INSTALL_DIR/target/release/websec" ]]; then
        print_success "WebSec compiled successfully"
    else
        print_error "Compilation failed - binary not found"
        exit 1
    fi
}

# Function to apply ownership and capabilities
apply_permissions() {
    print_info "Applying ownership and capabilities..."

    cd "$INSTALL_DIR"

    # Change ownership
    print_info "Setting ownership to $WEBSEC_USER:$WEBSEC_USER..."
    chown -R "$WEBSEC_USER:$WEBSEC_USER" "$INSTALL_DIR"
    print_success "Ownership applied"

    # Apply capability
    print_info "Applying CAP_NET_BIND_SERVICE capability..."
    setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/target/release/websec"
    print_success "Capability applied"
}

# Function to install default configuration
install_default_config() {
    print_info "Installing default configuration..."

    local config_dir="/etc/websec"
    local config_file="$config_dir/websec.toml"
    local example_config="$INSTALL_DIR/config/websec.toml.example"

    # Check if example config exists
    if [[ ! -f "$example_config" ]]; then
        print_warning "Configuration example not found at $example_config"
        print_info "Skipping configuration installation"
        return 0
    fi

    # Create config directory if it doesn't exist
    if [[ ! -d "$config_dir" ]]; then
        print_info "Creating configuration directory: $config_dir"
        mkdir -p "$config_dir"
    fi

    # Check if config already exists
    if [[ -f "$config_file" ]]; then
        print_success "Configuration file already exists at $config_file"

        if ask_confirmation "Do you want to backup and replace it with the default configuration?"; then
            local backup_file="$config_file.backup.$(date +%Y%m%d-%H%M%S)"
            print_info "Backing up existing config to $backup_file"
            cp "$config_file" "$backup_file"
        else
            print_info "Keeping existing configuration"
            return 0
        fi
    fi

    # Copy configuration
    print_info "Copying default configuration..."
    cp "$example_config" "$config_file"

    # Ask if user wants to customize key settings
    echo -e "\n${BLUE}Configuration customization${NC}"
    echo "The default configuration uses:"
    echo "  - Listen: 0.0.0.0:8080"
    echo "  - Backend: http://127.0.0.1:3000"
    echo ""

    if ask_confirmation "Do you want to customize the listen address and backend URL?"; then
        # Ask for listen address
        echo -ne "${BLUE}Enter listen address [0.0.0.0:80]: ${NC}"
        read listen_address
        listen_address=${listen_address:-"0.0.0.0:80"}

        # Ask for backend URL
        echo -ne "${BLUE}Enter backend URL [http://127.0.0.1:8080]: ${NC}"
        read backend_url
        backend_url=${backend_url:-"http://127.0.0.1:8080"}

        # Update config file
        sed -i "s|listen = \"0.0.0.0:8080\"|listen = \"$listen_address\"|g" "$config_file"
        sed -i "s|backend = \"http://127.0.0.1:3000\"|backend = \"$backend_url\"|g" "$config_file"

        print_success "Configuration customized with:"
        echo "  - Listen: $listen_address"
        echo "  - Backend: $backend_url"
    else
        print_info "Using default configuration values"
    fi

    # Apply correct permissions
    print_info "Applying configuration permissions..."
    chown root:$WEBSEC_USER "$config_dir"
    chmod 750 "$config_dir"
    chown root:$WEBSEC_USER "$config_file"
    chmod 640 "$config_file"

    print_success "Configuration installed at $config_file"

    # Test configuration
    print_info "Testing configuration..."
    if sudo -u "$WEBSEC_USER" "$INSTALL_DIR/target/release/websec" --config "$config_file" run --dry-run >/dev/null 2>&1; then
        print_success "Configuration is valid"
    else
        print_warning "Configuration validation failed (may need SSL certificates or Redis)"
        print_info "You can test with: sudo -u $WEBSEC_USER $INSTALL_DIR/target/release/websec --config $config_file run --dry-run"
    fi
}

# Function to verify installation
verify_installation() {
    print_info "Verifying installation..."

    local binary="$INSTALL_DIR/target/release/websec"

    # Check binary exists
    if [[ ! -f "$binary" ]]; then
        print_error "Binary not found at $binary"
        return 1
    fi
    print_success "Binary exists: $binary"

    # Check ownership
    local owner=$(stat -c '%U:%G' "$binary")
    if [[ "$owner" == "$WEBSEC_USER:$WEBSEC_USER" ]]; then
        print_success "Ownership correct: $owner"
    else
        print_warning "Ownership is $owner (expected $WEBSEC_USER:$WEBSEC_USER)"
    fi

    # Check capability
    local cap=$(getcap "$binary")
    if echo "$cap" | grep -q "cap_net_bind_service"; then
        print_success "Capability set: $cap"
    else
        print_error "Capability not set correctly"
        return 1
    fi

    # Test binary execution
    print_info "Testing binary version..."
    if sudo -u "$WEBSEC_USER" "$binary" --version; then
        print_success "Binary executes correctly"
    else
        print_error "Binary execution failed"
        return 1
    fi

    print_success "Installation verification complete"
}

# Function to install to system path
install_to_system_path() {
    local source_binary="$INSTALL_DIR/target/release/websec"
    local target_path="/usr/local/bin/websec"

    print_info "System installation option"
    echo -e "\nThis will copy the binary to $target_path"
    echo -e "${YELLOW}Note: You will need to reapply the capability after each recompilation${NC}\n"

    if ask_confirmation "Do you want to install websec to system path?"; then
        # Copy binary
        cp "$source_binary" "$target_path"

        # Apply same capability to system binary
        setcap 'cap_net_bind_service=+ep' "$target_path"

        # Keep ownership as root for system binary
        chown root:root "$target_path"
        chmod 755 "$target_path"

        print_success "WebSec installed to $target_path"
        print_info "You can now run: websec --version"
    else
        print_info "Skipping system installation"
        print_info "You can run websec from: $source_binary"
    fi
}

# Function to display next steps
display_next_steps() {
    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ WebSec Installation Complete${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    print_info "Next Steps:\n"

    echo "1. Review and edit configuration (if needed):"
    echo -e "   ${BLUE}sudo nano /etc/websec/websec.toml${NC}"
    echo -e "   Configuration already installed with your settings\n"

    echo "2. Configure SSL certificates (if using HTTPS):"
    echo -e "   ${BLUE}sudo chmod 755 /etc/letsencrypt${NC}"
    echo -e "   ${BLUE}sudo chmod 755 /etc/letsencrypt/live${NC}"
    echo -e "   ${BLUE}sudo chmod 755 /etc/letsencrypt/archive${NC}"
    echo -e "   ${BLUE}sudo chown root:$WEBSEC_USER /etc/letsencrypt/archive/your-domain.com${NC}"
    echo -e "   ${BLUE}sudo chmod 750 /etc/letsencrypt/archive/your-domain.com${NC}"
    echo -e "   ${BLUE}sudo chmod 640 /etc/letsencrypt/archive/your-domain.com/*.pem${NC}\n"

    echo "3. Test configuration (dry-run):"
    echo -e "   ${BLUE}sudo -u $WEBSEC_USER $INSTALL_DIR/target/release/websec --config /etc/websec/websec.toml run --dry-run${NC}\n"

    echo "4. Create systemd service:"
    echo -e "   ${BLUE}sudo cp $INSTALL_DIR/systemd/websec.service /etc/systemd/system/${NC}"
    echo -e "   ${BLUE}sudo systemctl daemon-reload${NC}"
    echo -e "   ${BLUE}sudo systemctl enable websec${NC}"
    echo -e "   ${BLUE}sudo systemctl start websec${NC}\n"

    echo "5. Check status and logs:"
    echo -e "   ${BLUE}sudo systemctl status websec${NC}"
    echo -e "   ${BLUE}sudo journalctl -u websec -f${NC}\n"

    print_warning "Important: After recompiling WebSec, you MUST reapply the capability:"
    echo -e "   ${YELLOW}sudo setcap 'cap_net_bind_service=+ep' $INSTALL_DIR/target/release/websec${NC}\n"

    echo -e "For complete deployment instructions, see:"
    echo -e "   ${BLUE}$INSTALL_DIR/docs/deployment-checklist.md${NC}"
    echo -e "   ${BLUE}$INSTALL_DIR/docs/troubleshooting-guide.md${NC}\n"
}

# Main installation flow
main() {
    echo -e "${BLUE}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "          WebSec Interactive Installation Script"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${NC}\n"

    print_info "This script will install WebSec with Linux capabilities (non-root)\n"

    # Step 1: Check root
    check_root

    # Step 2: Install dependencies
    install_dependencies

    # Step 3: Install Rust
    install_rust

    # Step 4: Create websec user
    create_websec_user

    # Step 5: Clone repository
    clone_repository

    # Step 6: Compile
    compile_websec

    # Step 7: Apply permissions and capabilities
    apply_permissions

    # Step 8: Install default configuration
    install_default_config

    # Step 9: Verify installation
    verify_installation

    # Step 10: Optional system path installation
    install_to_system_path

    # Step 11: Display next steps
    display_next_steps
}

# Run main function
main "$@"
