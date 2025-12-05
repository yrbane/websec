#!/bin/bash
#
# WebSec Interactive Installation & Deployment Script
#
# This script automates the complete deployment of WebSec.
# It can be run locally (sudo ./install.sh) or used to deploy to a remote server via SSH.
#
# Usage:
#   Local install:  sudo bash install.sh
#   Remote deploy:  ./install.sh [options] <user@host_or_alias>
#
# Options (Remote deploy):
#   -i <key_path>   Path to SSH private key. Overrides IdentityFile from ~/.ssh/config.
#   -p <port>       SSH port. Overrides Port from ~/.ssh/config.
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
CONFIG_DIR="/etc/websec"
LOG_DIR="/var/log/websec"
DATA_DIR="/var/lib/websec"
REPO_URL="https://github.com/yrbane/websec.git"

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

# Parse Arguments
TARGET=""
REMOTE_MODE=false
SSH_PORT_ARG=""       # Will be "-p <port>" if user specified
IDENTITY_FILE_ARG=""  # Will be "-i <key>" if user specified

# We assume remote mode if any arguments are passed (flags or target)
if [[ $# -gt 0 ]]; then
    REMOTE_MODE=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--identity)
                if [[ -z "$2" ]]; then
                    echo "Error: Option $1 requires an argument"
                    exit 1
                fi
                IDENTITY_FILE_ARG="-i $2"
                shift 2
                ;; 
            -p|--port)
                if [[ -z "$2" ]]; then
                    echo "Error: Option $1 requires an argument"
                    exit 1
                fi
                SSH_PORT_ARG="-p $2"
                shift 2
                ;; 
            -*)
                echo "Unknown option: $1"
                exit 1
                ;; 
            *)
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                else
                    echo "Error: Too many arguments provided (Target already set to '$TARGET', unexpected '$1')"
                    exit 1
                fi
                shift
                ;; 
        esac
    done
fi

# --- Remote Deployment Logic ---

if [[ "$REMOTE_MODE" == "true" ]]; then
    # Enable debug output for the script itself
    set -x
    
    if [[ -z "$TARGET" ]]; then
        echo "Error: Remote mode detected but no target specified."
        echo "Usage: ./install.sh [options] <user@host_or_alias>"
        exit 1
    fi

    echo -e "${BLUE}[INFO]${NC} Preparing deployment on $TARGET..."

    # 1. Verify SSH connection
    echo -e "${BLUE}[INFO]${NC} Verifying SSH connection..."
    # Attempt connection with user-provided args, otherwise rely on ~/.ssh/config
    # ConnectTimeout is crucial to not hang indefinitely
    if ssh $IDENTITY_FILE_ARG $SSH_PORT_ARG -o ConnectTimeout=10 "$TARGET" "echo 'SSH OK'" 2>/dev/null; then
        echo -e "${GREEN}[✓]${NC} SSH connection established"
    else
        echo -e "${RED}[✗]${NC} Unable to connect to $TARGET"
        echo "-------------------------------------------------------"
        echo "Debugging SSH connection to $TARGET (verbose output):"
        # Try again in verbose mode to show the exact SSH error
        ssh -v $IDENTITY_FILE_ARG $SSH_PORT_ARG "$TARGET" "exit"
        echo "-------------------------------------------------------"
        exit 1
    fi

    # 2. Copy install script
    echo -e "${BLUE}[INFO]${NC} Transferring installation script..."
    if ! scp $IDENTITY_FILE_ARG $SSH_PORT_ARG "$0" "$TARGET:/tmp/websec-install.sh"; then
        print_error "Failed to copy script to remote server."
        exit 1
    fi

    # 3. Execute remote install
    echo -e "${BLUE}[INFO]${NC} Starting remote installation..."
    echo "----------------------------------------------------------------"
    # -t forces pseudo-tty allocation for sudo password prompt if needed
    ssh $IDENTITY_FILE_ARG $SSH_PORT_ARG -t "$TARGET" "chmod +x /tmp/websec-install.sh && sudo /tmp/websec-install.sh"
    echo "----------------------------------------------------------------"

    echo -e "${GREEN}[✓]${NC} Remote deployment finished!"
    # Disable debug output before exiting
    set +x
    exit 0
fi

# --- Local Installation Logic ---

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "Local installation must be run as root (use sudo)"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

# Detect package manager
detect_package_manager() {
    if command -v apt-get >/dev/null; then echo "apt";
    elif command -v dnf >/dev/null; then echo "dnf";
    elif command -v yum >/dev/null; then echo "yum";
    elif command -v pacman >/dev/null; then echo "pacman";
    else echo "unknown"; fi
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


# Install dependencies
install_dependencies() {
    print_info "Checking system dependencies..."
    local pkg_manager=$(detect_package_manager)
    local deps=("git" "gcc" "pkg-config" "libssl-dev")
    
    case "$pkg_manager" in
        apt)
            apt-get update
            apt-get install -y "${deps[@]}"
            ;; 
        dnf|yum)
            # Map libssl-dev to openssl-devel
            deps=("git" "gcc" "pkg-config" "openssl-devel")
            $pkg_manager install -y "${deps[@]}"
            ;; 
        pacman)
            deps=("git" "gcc" "pkg-config" "openssl")
            pacman -S --noconfirm "${deps[@]}"
            ;; 
        *)
            print_warning "Unknown package manager. Please ensure dependencies are installed manually: ${deps[*]}"
            ;; 
    esac
    print_success "Dependencies installed"
}

# Install Rust if missing
install_rust() {
    if command -v cargo >/dev/null; then
        print_success "Rust is already installed"
        return
    fi

    print_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    print_success "Rust installed successfully"
}

# Create websec user and directories
setup_user_and_dirs() {
    print_info "Setting up user and directories..."

    # Create user
    if ! id "$WEBSEC_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" "$WEBSEC_USER"
        print_success "User '$WEBSEC_USER' created"
    else
        print_success "User '$WEBSEC_USER' already exists"
    fi

    # Create directories
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    
    # Set permissions
    chown -R "$WEBSEC_USER:$WEBSEC_USER" "$INSTALL_DIR" "$LOG_DIR" "$DATA_DIR"
    # Config dir owned by root, readable by websec
    chown root:"$WEBSEC_USER" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    
    print_success "Directories created and permissions set"
}

# Clone and Compile
install_websec() {
    print_info "Installing WebSec..."

    # Clone or pull
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        print_info "Updating repository..."
        cd "$INSTALL_DIR"
        # Ensure correct ownership for git operations
        if ! sudo -u "$WEBSEC_USER" git pull; then
            print_warning "Git pull failed (SSH issue?). Falling back to HTTPS reset..."
            # Force HTTPS remote to avoid SSH key issues on server
            sudo -u "$WEBSEC_USER" git remote set-url origin "$REPO_URL"
            sudo -u "$WEBSEC_USER" git fetch origin
            sudo -u "$WEBSEC_USER" git reset --hard origin/main
            print_success "Repository reset to origin/main via HTTPS"
        fi
    else
        print_info "Cloning repository..."
        # Ensure empty dir before clone
        if [[ -d "$INSTALL_DIR" ]]; then rm -rf "$INSTALL_DIR"; mkdir -p "$INSTALL_DIR"; chown "$WEBSEC_USER:$WEBSEC_USER" "$INSTALL_DIR"; fi
        sudo -u "$WEBSEC_USER" git clone "$REPO_URL" "$INSTALL_DIR"
    fi

    # Compile
    print_info "Compiling (this may take a few minutes)..."
    cd "$INSTALL_DIR"
    # Source cargo env if needed
    source $HOME/.cargo/env 2>/dev/null || true
    
    cargo build --release --features tls
    
    # Install binary to system path
    cp "$INSTALL_DIR/target/release/websec" /usr/local/bin/websec
    chmod 755 /usr/local/bin/websec
    
    # Set capabilities
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec
    
    print_success "WebSec compiled and installed to /usr/local/bin/websec"
}

# Configure
configure_websec() {
    print_info "Configuring WebSec..."
    
    local config_file="$CONFIG_DIR/websec.toml"
    
    if [[ ! -f "$config_file" ]]; then
        cp "$INSTALL_DIR/config/websec.toml.example" "$config_file"
        chown root:"$WEBSEC_USER" "$CONFIG_DIR"
        chmod 750 "$CONFIG_DIR"
        chown root:"$WEBSEC_USER" "$config_file"
        chmod 640 "$config_file"
        
        # Customize for systemd path
        # Use sled by default for easy install
        sed -i 's|type = "redis"|type = "sled"|' "$config_file"
        sed -i 's|# path = "websec.db"|path = "/var/lib/websec/websec.db"|' "$config_file"
        
        print_success "Default configuration installed at $config_file"
        print_info "Default storage set to Sled (embedded DB) at $DATA_DIR/websec.db"
    else
        print_info "Configuration already exists, skipping overwrite"
    fi
}

# Install Systemd Service
install_systemd() {
    print_info "Installing Systemd service..."
    
    cat > /etc/systemd/system/websec.service <<EOF
[Unit]
Description=WebSec Security Proxy
After=network.target syslog.target

[Service]
Type=simple
User=$WEBSEC_USER
Group=$WEBSEC_USER
ExecStart=/usr/local/bin/websec run
Environment=WEBSEC_CONFIG=$CONFIG_DIR/websec.toml
Restart=always
RestartSec=5
# Security hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable websec
    print_success "Systemd service installed and enabled"
}

# Main execution
main() {
    echo -e "${BLUE}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "          WebSec Interactive Installation Script"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${NC}\n"

    install_dependencies
    install_rust
    setup_user_and_dirs
    install_websec
    configure_websec
    install_systemd

    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ Installation Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    echo "You can now start WebSec with:"
    echo -e "${BLUE}sudo systemctl start websec${NC}"
    echo -e "Check status with:"
    echo -e "${BLUE}sudo systemctl status websec${NC}"
    echo -e "Check logs with:"
    echo -e "${BLUE}sudo journalctl -u websec -f${NC}"
}

main "$@"