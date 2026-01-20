#!/bin/bash
#
# dnstt-server deployment script
# Based on bugfloyd/dnstt-deploy structure
#

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dnstt"
CONFIG_FILE="$CONFIG_DIR/dnstt.conf"
DNSTT_USER="dnstt"
SERVICE_NAME="dnstt-server"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect OS and package manager
detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    fi

    if command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    else
        echo -e "${RED}Unsupported package manager${NC}"
        exit 1
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="arm" ;;
        i686)    ARCH="386" ;;
    esac
}

# Get default network interface
get_default_interface() {
    ip route | grep default | awk '{print $5}' | head -1
}

# Load existing configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
}

# Save configuration
save_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
NS_SUBDOMAIN="$NS_SUBDOMAIN"
MTU_VALUE="$MTU_VALUE"
TUNNEL_MODE="$TUNNEL_MODE"
EOF
}

# Install dependencies
install_deps() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    case "$PKG_MANAGER" in
        apt)
            apt-get update -qq
            apt-get install -y -qq git golang iptables iptables-persistent
            ;;
        dnf|yum)
            $PKG_MANAGER install -y -q git golang iptables iptables-services
            ;;
    esac
}

# Create dnstt user
create_user() {
    if ! id "$DNSTT_USER" &>/dev/null; then
        useradd -r -s /bin/false "$DNSTT_USER"
    fi
}

# Build and install binary
install_binary() {
    BINARY_PATH="$INSTALL_DIR/dnstt-server"

    echo -e "${BLUE}Building dnstt-server...${NC}"
    cd "$REPO_DIR/dnstt-server"
    go build -o "$BINARY_PATH" .

    chmod +x "$BINARY_PATH"
    echo -e "${GREEN}Binary built and installed${NC}"
}

# Generate keys
generate_keys() {
    PRIVKEY_FILE="$CONFIG_DIR/server.key"
    PUBKEY_FILE="$CONFIG_DIR/server.pub"

    if [ ! -f "$PRIVKEY_FILE" ]; then
        echo -e "${BLUE}Generating keypair...${NC}"
        "$INSTALL_DIR/dnstt-server" -gen-key -privkey-file "$PRIVKEY_FILE" -pubkey-file "$PUBKEY_FILE"
        chown "$DNSTT_USER:$DNSTT_USER" "$PRIVKEY_FILE" "$PUBKEY_FILE"
        chmod 600 "$PRIVKEY_FILE"
        chmod 644 "$PUBKEY_FILE"
    fi
}

# Configure iptables for DNS redirection
configure_iptables() {
    echo -e "${BLUE}Configuring iptables...${NC}"

    # Remove existing rules if any
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
    ip6tables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true

    # Add new rules
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
    ip6tables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300

    # Save rules
    if [ "$PKG_MANAGER" = "apt" ]; then
        netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4
    else
        service iptables save 2>/dev/null || true
    fi

    # Handle firewalld if active
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=53/udp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi

    echo -e "${GREEN}iptables configured (53 -> 5300)${NC}"
}

# Install Dante SOCKS proxy
install_dante() {
    echo -e "${BLUE}Installing Dante SOCKS proxy...${NC}"

    case "$PKG_MANAGER" in
        apt)
            apt-get install -y -qq dante-server
            ;;
        dnf|yum)
            $PKG_MANAGER install -y -q dante-server 2>/dev/null || {
                echo -e "${YELLOW}Dante not available, skipping${NC}"
                return
            }
            ;;
    esac

    INTERFACE=$(get_default_interface)

    cat > /etc/danted.conf << EOF
logoutput: syslog
internal: 127.0.0.1 port = 1080
external: $INTERFACE

socksmethod: none
clientmethod: none

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}
EOF

    systemctl enable danted
    systemctl restart danted
    echo -e "${GREEN}Dante running on 127.0.0.1:1080${NC}"
}

# Get SSH port
get_ssh_port() {
    ss -tlnp | grep sshd | awk '{print $4}' | grep -oE '[0-9]+$' | head -1
}

# Create systemd service
create_service() {
    if [ "$TUNNEL_MODE" = "socks" ]; then
        UPSTREAM="127.0.0.1:1080"
    else
        SSH_PORT=$(get_ssh_port)
        UPSTREAM="127.0.0.1:${SSH_PORT:-22}"
    fi

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=dnstt DNS Tunnel Server
After=network.target

[Service]
Type=simple
User=$DNSTT_USER
Group=$DNSTT_USER
ExecStart=$INSTALL_DIR/dnstt-server -udp :5300 -privkey-file $CONFIG_DIR/server.key -mtu $MTU_VALUE $NS_SUBDOMAIN $UPSTREAM
Restart=always
RestartSec=5
LimitNOFILE=65535

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/
ReadWritePaths=$CONFIG_DIR

AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# Start service
start_service() {
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}Service started successfully${NC}"
    else
        echo -e "${RED}Service failed to start${NC}"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
    fi
}

# Show public key
show_pubkey() {
    echo ""
    echo -e "${GREEN}========== PUBLIC KEY ==========${NC}"
    cat "$CONFIG_DIR/server.pub"
    echo -e "${GREEN}=================================${NC}"
    echo ""
}

# Installation
do_install() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi

    detect_system
    load_config

    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     dnstt-server Installation            ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"

    # Get NS subdomain
    read -p "Enter nameserver subdomain (e.g., t1.example.com) [$NS_SUBDOMAIN]: " input
    NS_SUBDOMAIN="${input:-$NS_SUBDOMAIN}"
    if [ -z "$NS_SUBDOMAIN" ]; then
        echo -e "${RED}Subdomain is required${NC}"
        exit 1
    fi

    # Get MTU
    read -p "Enter MTU value [${MTU_VALUE:-1232}]: " input
    MTU_VALUE="${input:-${MTU_VALUE:-1232}}"

    # Get tunnel mode
    echo ""
    echo "Tunnel mode:"
    echo "  1) SOCKS proxy (Dante on 127.0.0.1:1080)"
    echo "  2) SSH"
    read -p "Select mode [1]: " mode_choice
    case "$mode_choice" in
        2) TUNNEL_MODE="ssh" ;;
        *) TUNNEL_MODE="socks" ;;
    esac

    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo "  Subdomain: $NS_SUBDOMAIN"
    echo "  MTU: $MTU_VALUE"
    echo "  Mode: $TUNNEL_MODE"
    echo ""
    read -p "Continue? (Y/n): " confirm
    if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
        exit 0
    fi

    save_config
    install_deps
    create_user
    mkdir -p "$CONFIG_DIR"
    chown "$DNSTT_USER:$DNSTT_USER" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    install_binary
    generate_keys
    configure_iptables

    if [ "$TUNNEL_MODE" = "socks" ]; then
        install_dante
    fi

    create_service
    start_service
    show_pubkey

    echo -e "${BLUE}Commands:${NC}"
    echo "  Status:  systemctl status $SERVICE_NAME"
    echo "  Logs:    journalctl -u $SERVICE_NAME -f"
    echo "  Restart: systemctl restart $SERVICE_NAME"
    echo ""
}

# Show status
do_status() {
    systemctl status "$SERVICE_NAME" --no-pager
}

# Show logs
do_logs() {
    journalctl -u "$SERVICE_NAME" -f
}

# Show config info
do_info() {
    load_config
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo "  Subdomain: $NS_SUBDOMAIN"
    echo "  MTU: $MTU_VALUE"
    echo "  Mode: $TUNNEL_MODE"
    echo ""

    if [ -f "$CONFIG_DIR/server.pub" ]; then
        show_pubkey
    fi
}

# Update binary
do_update() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi

    detect_system

    if [ -f "$INSTALL_DIR/dnstt-server" ]; then
        cp "$INSTALL_DIR/dnstt-server" "$INSTALL_DIR/dnstt-server.bak"
    fi

    echo -e "${BLUE}Pulling latest changes...${NC}"
    cd "$REPO_DIR"
    git pull || true

    install_binary
    systemctl restart "$SERVICE_NAME"

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}Update complete${NC}"
        rm -f "$INSTALL_DIR/dnstt-server.bak"
    else
        echo -e "${YELLOW}Rolling back...${NC}"
        mv "$INSTALL_DIR/dnstt-server.bak" "$INSTALL_DIR/dnstt-server"
        systemctl restart "$SERVICE_NAME"
    fi
}

# Menu
show_menu() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║          dnstt-server Manager            ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  1) Install / Reconfigure"
    echo "  2) Update binary"
    echo "  3) Service status"
    echo "  4) View logs"
    echo "  5) Show config info"
    echo "  0) Exit"
    echo ""
    read -p "Select option: " choice

    case "$choice" in
        1) do_install ;;
        2) do_update ;;
        3) do_status ;;
        4) do_logs ;;
        5) do_info ;;
        0) exit 0 ;;
        *) show_menu ;;
    esac
}

# Main
if [ $# -eq 0 ]; then
    show_menu
else
    case "$1" in
        install) do_install ;;
        update) do_update ;;
        status) do_status ;;
        logs) do_logs ;;
        info) do_info ;;
        *) show_menu ;;
    esac
fi
