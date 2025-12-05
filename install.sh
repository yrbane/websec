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
#   --force-deploy  Skip SSH connection verification and force deployment attempt.
#   --debug         Enable verbose script execution (set -x).
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
REPO_URL_HTTPS="https://github.com/yrbane/websec.git"
REPO_URL_SSH="git@github.com:yrbane/websec.git"

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
FORCE_DEPLOY=false
DEBUG_MODE=false

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
            --force-deploy)
                FORCE_DEPLOY=true
                shift
                ;; 
            --debug)
                DEBUG_MODE=true
                shift
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

if [[ "$DEBUG_MODE" == "true" ]]; then
    set -x
fi

# --- Remote Deployment Logic ---

if [[ "$REMOTE_MODE" == "true" ]]; then
    if [[ -z "$TARGET" ]]; then
        echo "Error: Remote mode detected but no target specified."
        echo "Usage: ./install.sh [options] <user@host_or_alias>"
        exit 1
    fi

    echo -e "${BLUE}[INFO]${NC} Preparing deployment on $TARGET..."

    # 1. Verify SSH connection (unless forced)
    if [[ "$FORCE_DEPLOY" == "false" ]]; then
        echo -e "${BLUE}[INFO]${NC} Verifying SSH connection..."
        if ssh $IDENTITY_FILE_ARG $SSH_PORT_ARG -o ConnectTimeout=10 "$TARGET" "echo 'SSH OK'" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} SSH connection established"
        else
            echo -e "${RED}[✗]${NC} Unable to connect to $TARGET"
            echo "-------------------------------------------------------"
            echo "Debugging SSH connection to $TARGET (verbose output):"
            ssh -v $IDENTITY_FILE_ARG $SSH_PORT_ARG "$TARGET" "exit" || true
            echo "-------------------------------------------------------"
            echo "Use --force-deploy to skip this check if you know what you are doing."
            exit 1
        fi
    else
        print_warning "Skipping SSH verification (--force-deploy used)"
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
    ssh $IDENTITY_FILE_ARG $SSH_PORT_ARG -t "$TARGET" "chmod +x /tmp/websec-install.sh && sudo /tmp/websec-install.sh"
    echo "----------------------------------------------------------------"

    echo -e "${GREEN}[✓]${NC} Remote deployment finished!"
    if [[ "$DEBUG_MODE" == "true" ]]; then set +x; fi
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

    if ! id "$WEBSEC_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" "$WEBSEC_USER"
        print_success "User '$WEBSEC_USER' created"
    else
        print_success "User '$WEBSEC_USER' already exists"
    fi

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    chown -R "$WEBSEC_USER:$WEBSEC_USER" "$INSTALL_DIR" "$LOG_DIR" "$DATA_DIR"
    chown root:"$WEBSEC_USER" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    
    print_success "Directories created and permissions set"
}

# Share SSH keys with websec user if present
setup_websec_ssh() {
    local calling_user="${SUDO_USER:-$USER}"
    local calling_home=$(eval echo ~"$calling_user")
    local websec_home="$DATA_DIR"
    local websec_ssh="$websec_home/.ssh"

    # If there is an SSH config or keys in the calling user's home, we might need them
    if [[ -d "$calling_home/.ssh" ]]; then
        print_info "Checking for SSH keys to share with websec user..."
        
        mkdir -p "$websec_ssh"
        chmod 700 "$websec_ssh"
        
        # Copy config if exists
        if [[ -f "$calling_home/.ssh/config" ]]; then
            cp "$calling_home/.ssh/config" "$websec_ssh/"
            print_info "Copied SSH config to websec user"
        fi
        
        # Copy 'websec' key specifically if it exists
        if [[ -f "$calling_home/.ssh/websec" ]]; then
             cp "$calling_home/.ssh/websec" "$websec_ssh/id_rsa"
             print_info "Copied 'websec' key to websec user as id_rsa"
        elif [[ -f "$calling_home/.ssh/id_rsa" ]]; then
             cp "$calling_home/.ssh/id_rsa" "$websec_ssh/id_rsa"
             print_info "Copied 'id_rsa' key to websec user"
        fi
        
        # Also known_hosts to avoid prompt
        if [[ -f "$calling_home/.ssh/known_hosts" ]]; then
             cp "$calling_home/.ssh/known_hosts" "$websec_ssh/"
        fi
        
        # Fix permissions
        chown -R "$WEBSEC_USER:$WEBSEC_USER" "$websec_ssh"
        chmod 600 "$websec_ssh"/* || true
        chmod 700 "$websec_ssh"
    fi
}

# Check GitHub connectivity and loop until successful
check_github_access() {
    set +e  # Temporarily disable exit on error to handle SSH checks gracefully
    local websec_ssh="$DATA_DIR/.ssh"
    local key_file="$websec_ssh/websec_key" # New standardized key filename
    local pub_key_file="$key_file.pub"
    
    # Ensure we trust GitHub host to avoid prompt
    mkdir -p "$websec_ssh"
    if ! grep -q "github.com" "$websec_ssh/known_hosts" 2>/dev/null; then
        print_info "Adding github.com to known_hosts..."
        ssh-keyscan github.com >> "$websec_ssh/known_hosts" 2>/dev/null
        chown "$WEBSEC_USER:$WEBSEC_USER" "$websec_ssh/known_hosts"
        chmod 600 "$websec_ssh/known_hosts"
    fi

    # Ensure permissions are correct
    chown -R "$WEBSEC_USER:$WEBSEC_USER" "$websec_ssh"
    chmod 700 "$websec_ssh"
    if [[ -f "$key_file" ]]; then
        chmod 600 "$key_file" 2>/dev/null || true
        chown "$WEBSEC_USER:$WEBSEC_USER" "$key_file"
    fi

    # Configure git command environment
    export GIT_SSH_COMMAND="ssh -i $key_file -o UserKnownHostsFile=$websec_ssh/known_hosts -o StrictHostKeyChecking=no"

    print_info "Testing GitHub connectivity..."
    
    while true; do
        # Test SSH connection to GitHub - capture output
        # We run this as websec user
        # Added -v for verbose output to see which key is offered
        OUTPUT=$(sudo -u "$WEBSEC_USER" GIT_SSH_COMMAND="$GIT_SSH_COMMAND" ssh -v -T git@github.com 2>&1)
        
        # ssh -T returns 1 on success (authenticated but no shell access) but prints success msg
        if echo "$OUTPUT" | grep -q "successfully authenticated"; then
            print_success "GitHub authentication successful"
            set -e # Re-enable exit on error
            return 0
        fi

        print_warning "GitHub authentication failed."
        echo "----------------------------------------------------------------"
        echo "Last error details from SSH:"
        # Filter for relevant errors, including key offer details
        echo "$OUTPUT" | grep -E "Permission denied|Authentication failed|timed out|Could not resolve|Connection refused|Offering public key|Server accepted key" | tail -n 10
        echo "----------------------------------------------------------------"
        
        # Prompt to regenerate key
        if ask_confirmation "Do you want to REGENERATE a new SSH key for deployment?"; then
            print_info "Removing previous key and generating a new one..."
            rm -f "$key_file" "$pub_key_file"
        fi

        # Generate key if missing (or just removed)
        if [[ ! -f "$key_file" ]]; then
            print_info "Generating new SSH key: $key_file"
            # Remove spaces from hostname just in case
            local host_clean=$(hostname | tr -d '[:space:]')
            sudo -u "$WEBSEC_USER" ssh-keygen -t ed25519 -C "websec_user@$host_clean" -f "$key_file" -N "" -q
            chmod 600 "$key_file"
            chown "$WEBSEC_USER:$WEBSEC_USER" "$key_file" "$pub_key_file"
        fi

        # Show public key for copy-paste
        print_warning "ACTION REQUIRED: Add this Deploy Key to your GitHub repository!"
        print_info "Key file generated at: $pub_key_file"
        echo "----------------------------------------------------------------"
        echo -e "${YELLOW}$(cat "$pub_key_file")${NC}" # Display in yellow/orange
        echo "----------------------------------------------------------------"
        echo "URL: https://github.com/yrbane/websec/settings/keys/new"
        echo ""
        
        read -p "Press Enter once you have added the key to GitHub to retry..."
    done
    set -e # Re-enable exit on error
}

# Clone and Compile
install_websec() {
    print_info "Installing WebSec..."
    
    setup_websec_ssh
    
    # Check connectivity loop
    check_github_access

    # Determine the correct remote URL
    local target_url="$REPO_URL_SSH" # Always use SSH now after check_github_access
    
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        print_info "Updating repository..."
        cd "$INSTALL_DIR"
        
        # Correct remote URL if needed
        current_remote=$(sudo -u "$WEBSEC_USER" git remote get-url origin 2>/dev/null || echo "")
        
        if [[ "$current_remote" != "$target_url" ]]; then
             print_info "Updating remote URL from '$current_remote' to '$target_url'"
             sudo -u "$WEBSEC_USER" git remote set-url origin "$target_url"
        fi
        
        # Ensure correct ownership for git operations
        if ! sudo -u "$WEBSEC_USER" GIT_SSH_COMMAND="$GIT_SSH_COMMAND" git pull; then
            print_warning "Git pull failed."
            print_info "Attempting hard reset..."
            sudo -u "$WEBSEC_USER" GIT_SSH_COMMAND="$GIT_SSH_COMMAND" git fetch origin
            sudo -u "$WEBSEC_USER" GIT_SSH_COMMAND="$GIT_SSH_COMMAND" git reset --hard origin/main
            print_success "Repository updated (reset)"
        else
            print_success "Repository updated"
        fi
    else
        print_info "Cloning repository..."
        if [[ -d "$INSTALL_DIR" ]]; then rm -rf "$INSTALL_DIR"; mkdir -p "$INSTALL_DIR"; chown "$WEBSEC_USER:$WEBSEC_USER" "$INSTALL_DIR"; fi
        
        if ! sudo -u "$WEBSEC_USER" GIT_SSH_COMMAND="$GIT_SSH_COMMAND" git clone "$target_url" "$INSTALL_DIR"; then
             print_error "Clone failed even with verified key. Please check permissions."
             exit 1
        fi
        print_success "Repository cloned"
    fi

    print_info "Compiling (this may take a few minutes)..."
    cd "$INSTALL_DIR"
    source $HOME/.cargo/env 2>/dev/null || true
    
    cargo build --release --features tls
    
    cp "$INSTALL_DIR/target/release/websec" /usr/local/bin/websec
    chmod 755 /usr/local/bin/websec
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec
    
    print_success "WebSec compiled and installed to /usr/local/bin/websec"
}

# Configure
configure_websec() {
    print_info "Configuring WebSec..."
    local config_file="$CONFIG_DIR/websec.toml"
    
    if [[ ! -f "$config_file" ]]; then
        cp "$INSTALL_DIR/config/websec.toml.example" "$config_file"
        chown root:"$WEBSEC_USER" "$config_file"
        chmod 640 "$config_file"
        
        sed -i 's|type = "redis"|type = "sled"|' "$config_file"
        sed -i 's|# path = "websec.db"|path = "/var/lib/websec/websec.db"|' "$config_file"
        
        print_success "Default configuration installed at $config_file"
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

# Configure UFW and Fail2Ban whitelists
setup_firewall() {
    print_info "Configuring firewall and whitelists..."

    # Get current IP
    local current_ip=""
    if [[ -n "$SSH_CLIENT" ]]; then
        current_ip=$(echo $SSH_CLIENT | awk '{print $1}')
    elif [[ -n "$SSH_CONNECTION" ]]; then
        current_ip=$(echo $SSH_CONNECTION | awk '{print $1}')
    fi

    if [[ -z "$current_ip" ]]; then
        print_warning "Could not detect your IP address from SSH session."
        echo -ne "${BLUE}Enter your IP address to whitelist (or leave empty to skip): ${NC}"
        read current_ip
    fi

    if [[ -n "$current_ip" ]]; then
        print_info "Whitelisting IP: $current_ip"

        # Fail2Ban
        if command -v fail2ban-client >/dev/null; then
            print_info "Configuring Fail2Ban..."
            local jail_local="/etc/fail2ban/jail.local"
            if [[ ! -f "$jail_local" ]]; then
                echo -e "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1" > "$jail_local"
            fi
            
            if ! grep -q "$current_ip" "$jail_local"; then
                sed -i "/^ignoreip/ s/$/ $current_ip/" "$jail_local"
                fail2ban-client reload >/dev/null
                print_success "Added $current_ip to Fail2Ban ignoreip"
            else
                print_success "IP already whitelisted in Fail2Ban"
            fi
        else
            print_warning "Fail2Ban not installed, skipping."
        fi

        # UFW
        if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
            print_info "Configuring UFW..."
            ufw allow from "$current_ip" to any port ssh comment 'Allow SSH from admin IP'
            ufw allow 80/tcp comment 'Allow HTTP'
            ufw allow 443/tcp comment 'Allow HTTPS'
            print_success "Allowed SSH, HTTP, HTTPS in UFW"
        fi

        # WebSec config
        local config_file="$CONFIG_DIR/websec.toml"
        if [[ -f "$config_file" ]]; then
            if ! grep -q "\"$current_ip\"" "$config_file"; then
                sed -i "/^whitelist = \[/ a \    \"$current_ip\"," "$config_file"
                print_success "Added $current_ip to WebSec whitelist"
            fi
        fi
    else
        print_warning "No IP provided, skipping whitelist configuration."
    fi
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
    setup_firewall

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
