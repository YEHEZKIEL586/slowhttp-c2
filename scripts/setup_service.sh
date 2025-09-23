#!/bin/bash

# Distributed Slow HTTP C2 - Systemd Service Setup Script
# This script sets up the C2 as a system service

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SERVICE_NAME="slowhttp-c2"
SERVICE_USER="slowhttp-c2"
INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

print_banner() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║               SYSTEMD SERVICE SETUP                         ║${NC}"
    echo -e "${CYAN}║           Distributed Slow HTTP C2                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_requirements() {
    echo -e "${BLUE}[CHECK] Verifying requirements...${NC}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root${NC}"
        echo "Usage: sudo $0"
        exit 1
    fi
    
    # Check if systemd is available
    if ! command -v systemctl &> /dev/null; then
        echo -e "${RED}[ERROR] Systemd not available on this system${NC}"
        exit 1
    fi
    
    # Check if installation directory exists
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "${RED}[ERROR] Installation directory not found: $INSTALL_DIR${NC}"
        exit 1
    fi
    
    # Check if main script exists
    if [ ! -f "$INSTALL_DIR/slowhttp_c2.py" ]; then
        echo -e "${RED}[ERROR] Main script not found: $INSTALL_DIR/slowhttp_c2.py${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[SUCCESS] Requirements check passed${NC}"
}

create_service_user() {
    echo -e "${BLUE}[SETUP] Creating service user...${NC}"
    
    # Check if user already exists
    if id "$SERVICE_USER" &>/dev/null; then
        echo -e "${YELLOW}[INFO] User '$SERVICE_USER' already exists${NC}"
    else
        # Create system user
        useradd --system --shell /bin/false --home /nonexistent \
                --no-create-home --group "$SERVICE_USER"
        echo -e "${GREEN}[SUCCESS] Created system user '$SERVICE_USER'${NC}"
    fi
    
    # Set ownership of installation directory
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    
    echo -e "${GREEN}[SUCCESS] Service user configured${NC}"
}

create_service_file() {
    echo -e "${BLUE}[SETUP] Creating systemd service file...${NC}"
    
    # Create service file
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Distributed Slow HTTP C2 Server
Documentation=https://github.com/yourusername/slowhttp-c2
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/bin:/bin
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/slowhttp_c2.py --daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF
    
    # Set proper permissions
    chmod 644 "$SERVICE_FILE"
    
    echo -e "${GREEN}[SUCCESS] Service file created at $SERVICE_FILE${NC}"
}

create_environment_file() {
    echo -e "${BLUE}[SETUP] Creating environment configuration...${NC}"
    
    # Create environment file
    cat > /etc/default/$SERVICE_NAME << EOF
# Environment configuration for Distributed Slow HTTP C2

# Python environment
PYTHONPATH=$INSTALL_DIR
PYTHONUNBUFFERED=1

# Logging
LOG_LEVEL=INFO
LOG_FILE=$INSTALL_DIR/logs/c2.log

# Security
ENCRYPTION_KEY_FILE=$INSTALL_DIR/key.key
DATABASE_FILE=$INSTALL_DIR/c2_database.db

# Network
BIND_HOST=127.0.0.1
BIND_PORT=5000

# Limits
MAX_VPS_NODES=100
DEFAULT_CONNECTIONS=1000
SSH_TIMEOUT=30
EOF
    
    # Set proper permissions
    chmod 640 /etc/default/$SERVICE_NAME
    chown root:$SERVICE_USER /etc/default/$SERVICE_NAME
    
    echo -e "${GREEN}[SUCCESS] Environment file created${NC}"
}

setup_logging() {
    echo -e "${BLUE}[SETUP] Configuring logging...${NC}"
    
    # Create logs directory
    mkdir -p "$INSTALL_DIR/logs"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/logs"
    chmod 755 "$INSTALL_DIR/logs"
    
    # Create logrotate configuration
    cat > /etc/logrotate.d/$SERVICE_NAME << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF
    
    echo -e "${GREEN}[SUCCESS] Logging configured${NC}"
}

setup_firewall() {
    echo -e "${BLUE}[SETUP] Configuring firewall (optional)...${NC}"
    
    read -p "Configure firewall to allow C2 web interface? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # UFW configuration
        if command -v ufw &> /dev/null; then
            ufw allow 5000/tcp comment "Slow HTTP C2"
            echo -e "${GREEN}[SUCCESS] UFW rule added${NC}"
        fi
        
        # Firewalld configuration
        if command -v firewall-cmd &> /dev/null; then
            firewall-cmd --permanent --add-port=5000/tcp
            firewall-cmd --reload
            echo -e "${GREEN}[SUCCESS] Firewalld rule added${NC}"
        fi
        
        # IPTables fallback
        if command -v iptables &> /dev/null; then
            iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
            echo -e "${YELLOW}[INFO] IPTables rule added (may not persist)${NC}"
        fi
    else
        echo -e "${YELLOW}[INFO] Firewall configuration skipped${NC}"
    fi
}

enable_and_start_service() {
    echo -e "${BLUE}[SETUP] Enabling and starting service...${NC}"
    
    # Reload systemd daemon
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    echo -e "${GREEN}[SUCCESS] Service enabled for auto-start${NC}"
    
    # Start service
    if systemctl start "$SERVICE_NAME"; then
        echo -e "${GREEN}[SUCCESS] Service started successfully${NC}"
        
        # Wait a moment and check status
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}[SUCCESS] Service is running${NC}"
        else
            echo -e "${YELLOW}[WARNING] Service may have issues, check status${NC}"
        fi
    else
        echo -e "${RED}[ERROR] Failed to start service${NC}"
        echo "Check logs with: journalctl -u $SERVICE_NAME -n 50"
    fi
}

create_management_scripts() {
    echo -e "${BLUE}[SETUP] Creating management scripts...${NC}"
    
    # Create start script
    cat > /usr/local/bin/$SERVICE_NAME-start << EOF
#!/bin/bash
systemctl start $SERVICE_NAME
systemctl status $SERVICE_NAME
EOF
    chmod +x /usr/local/bin/$SERVICE_NAME-start
    
    # Create stop script
    cat > /usr/local/bin/$SERVICE_NAME-stop << EOF
#!/bin/bash
systemctl stop $SERVICE_NAME
systemctl status $SERVICE_NAME
EOF
    chmod +x /usr/local/bin/$SERVICE_NAME-stop
    
    # Create restart script
    cat > /usr/local/bin/$SERVICE_NAME-restart << EOF
#!/bin/bash
systemctl restart $SERVICE_NAME
systemctl status $SERVICE_NAME
EOF
    chmod +x /usr/local/bin/$SERVICE_NAME-restart
    
    # Create logs script
    cat > /usr/local/bin/$SERVICE_NAME-logs << EOF
#!/bin/bash
if [ "\$1" = "-f" ]; then
    journalctl -u $SERVICE_NAME -f
else
    journalctl -u $SERVICE_NAME -n 50
fi
EOF
    chmod +x /usr/local/bin/$SERVICE_NAME-logs
    
    echo -e "${GREEN}[SUCCESS] Management scripts created${NC}"
}

display_service_info() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    SERVICE INSTALLED                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Service Management Commands:${NC}"
    echo -e "  Start:   ${GREEN}sudo systemctl start $SERVICE_NAME${NC}"
    echo -e "  Stop:    ${GREEN}sudo systemctl stop $SERVICE_NAME${NC}"
    echo -e "  Restart: ${GREEN}sudo systemctl restart $SERVICE_NAME${NC}"
    echo -e "  Status:  ${GREEN}sudo systemctl status $SERVICE_NAME${NC}"
    echo -e "  Logs:    ${GREEN}sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo ""
    echo -e "${YELLOW}Quick Commands:${NC}"
    echo -e "  Start:   ${GREEN}sudo $SERVICE_NAME-start${NC}"
    echo -e "  Stop:    ${GREEN}sudo $SERVICE_NAME-stop${NC}"
    echo -e "  Restart: ${GREEN}sudo $SERVICE_NAME-restart${NC}"
    echo -e "  Logs:    ${GREEN}sudo $SERVICE_NAME-logs${NC}"
    echo ""
    echo -e "${YELLOW}Service Details:${NC}"
    echo -e "  Name: $SERVICE_NAME"
    echo -e "  User: $SERVICE_USER"
    echo -e "  Directory: $INSTALL_DIR"
    echo -e "  Service File: $SERVICE_FILE"
    echo -e "  Environment: /etc/default/$SERVICE_NAME"
    echo ""
    echo -e "${YELLOW}Web Interface:${NC}"
    echo -e "  URL: ${CYAN}http://localhost:5000${NC}"
    echo -e "  (Configure firewall if accessing remotely)"
    echo ""
}

# Uninstall function
uninstall_service() {
    echo -e "${YELLOW}[UNINSTALL] Removing systemd service...${NC}"
    
    # Stop and disable service
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Remove service file
    rm -f "$SERVICE_FILE"
    
    # Remove environment file
    rm -f "/etc/default/$SERVICE_NAME"
    
    # Remove logrotate configuration
    rm -f "/etc/logrotate.d/$SERVICE_NAME"
    
    # Remove management scripts
    rm -f "/usr/local/bin/$SERVICE_NAME-start"
    rm -f "/usr/local/bin/$SERVICE_NAME-stop"
    rm -f "/usr/local/bin/$SERVICE_NAME-restart"
    rm -f "/usr/local/bin/$SERVICE_NAME-logs"
    
    # Remove service user (optional)
    read -p "Remove service user '$SERVICE_USER'? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        echo -e "${GREEN}[SUCCESS] Service user removed${NC}"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}[SUCCESS] Service uninstalled${NC}"
}

# Main function
main() {
    print_banner
    
    # Check for uninstall flag
    if [[ "$1" == "--uninstall" ]]; then
        uninstall_service
        exit 0
    fi
    
    echo -e "${YELLOW}This will install Distributed Slow HTTP C2 as a system service.${NC}"
    echo -e "${YELLOW}Installation directory: $INSTALL_DIR${NC}"
    echo ""
    read -p "Continue with service installation? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}[START] Beginning service installation...${NC}"
    
    check_requirements
    create_service_user
    create_service_file
    create_environment_file
    setup_logging
    setup_firewall
    create_management_scripts
    enable_and_start_service
    
    display_service_info
    
    echo -e "${GREEN}[COMPLETE] Service installation finished successfully!${NC}"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Distributed Slow HTTP C2 - Systemd Service Setup"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo "  --uninstall     Remove the systemd service"
        echo ""
        echo "Examples:"
        echo "  sudo $0                Install service"
        echo "  sudo $0 --uninstall    Remove service"
        exit 0
        ;;
    --uninstall)
        main "$@"
        ;;
    "")
        main "$@"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac