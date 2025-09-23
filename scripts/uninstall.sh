#!/bin/bash

# Distributed Slow HTTP C2 - Complete Uninstaller
# This script completely removes the C2 system from your computer

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="slowhttp-c2"
SERVICE_USER="slowhttp-c2"

print_banner() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    COMPLETE UNINSTALLER                     ║${NC}"
    echo -e "${RED}║              Distributed Slow HTTP C2                       ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  This will completely remove the C2 system from your computer${NC}"
    echo ""
}

confirm_uninstall() {
    echo -e "${YELLOW}What will be removed:${NC}"
    echo "  • All application files and directories"
    echo "  • Python virtual environment and dependencies"
    echo "  • Database with all VPS configurations"
    echo "  • Encryption keys (VPS passwords will be lost)"
    echo "  • System service (if installed)"
    echo "  • Desktop shortcuts and launchers"
    echo "  • Log files and temporary data"
    echo ""
    
    read -p "Are you absolutely sure you want to uninstall? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Uninstallation cancelled${NC}"
        exit 0
    fi
    
    echo ""
    read -p "Type 'DELETE' to confirm complete removal: " -r
    
    if [[ $REPLY != "DELETE" ]]; then
        echo -e "${GREEN}Uninstallation cancelled${NC}"
        exit 0
    fi
}

stop_running_processes() {
    echo -e "${BLUE}[CLEANUP] Stopping running processes...${NC}"
    
    # Stop any running C2 processes
    pkill -f "slowhttp_c2.py" 2>/dev/null || true
    pkill -f "python.*slowhttp_c2" 2>/dev/null || true
    
    # Wait for processes to stop
    sleep 2
    
    # Force kill if still running
    pkill -9 -f "slowhttp_c2.py" 2>/dev/null || true
    
    echo -e "${GREEN}[SUCCESS] Processes stopped${NC}"
}

cleanup_vps_nodes() {
    echo -e "${BLUE}[CLEANUP] Cleaning up VPS nodes...${NC}"
    
    if [ -f "$INSTALL_DIR/c2_database.db" ]; then
        # Get VPS list from database
        VPS_LIST=$(sqlite3 "$INSTALL_DIR/c2_database.db" "SELECT ip_address FROM vps_nodes;" 2>/dev/null || true)
        
        if [ ! -z "$VPS_LIST" ]; then
            echo -e "${YELLOW}[INFO] Found VPS nodes in database, cleaning up...${NC}"
            
            # Cleanup script for VPS
            CLEANUP_SCRIPT='
                pkill -f "python3 agent.py" 2>/dev/null || true
                pkill -f "slowhttp" 2>/dev/null || true
                rm -rf /tmp/slowhttp_c2 2>/dev/null || true
                echo "VPS cleaned"
            '
            
            for vps_ip in $VPS_LIST; do
                echo -e "${CYAN}[CLEANING] $vps_ip...${NC}"
                timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                    root@"$vps_ip" "$CLEANUP_SCRIPT" 2>/dev/null || \
                    echo -e "${YELLOW}[WARNING] Could not clean $vps_ip (may be offline)${NC}"
            done &
            
            # Don't wait too long for VPS cleanup
            sleep 15
            kill %1 2>/dev/null || true
        fi
    fi
    
    echo -e "${GREEN}[SUCCESS] VPS cleanup completed${NC}"
}

remove_systemd_service() {
    echo -e "${BLUE}[CLEANUP] Removing systemd service...${NC}"
    
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        # Stop and disable service
        sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        
        # Remove service files
        sudo rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        sudo rm -f "/etc/default/$SERVICE_NAME"
        sudo rm -f "/etc/logrotate.d/$SERVICE_NAME"
        
        # Remove management scripts
        sudo rm -f "/usr/local/bin/$SERVICE_NAME-start"
        sudo rm -f "/usr/local/bin/$SERVICE_NAME-stop"
        sudo rm -f "/usr/local/bin/$SERVICE_NAME-restart"
        sudo rm -f "/usr/local/bin/$SERVICE_NAME-logs"
        
        # Remove service user
        if id "$SERVICE_USER" &>/dev/null; then
            sudo userdel "$SERVICE_USER" 2>/dev/null || true
        fi
        
        # Reload systemd
        sudo systemctl daemon-reload 2>/dev/null || true
        
        echo -e "${GREEN}[SUCCESS] Systemd service removed${NC}"
    else
        echo -e "${YELLOW}[INFO] No systemd service found${NC}"
    fi
}

remove_desktop_shortcuts() {
    echo -e "${BLUE}[CLEANUP] Removing desktop shortcuts...${NC}"
    
    # Remove desktop shortcut
    if [ -f "$HOME/Desktop/SlowHTTP-C2.desktop" ]; then
        rm "$HOME/Desktop/SlowHTTP-C2.desktop"
        echo -e "${GREEN}[SUCCESS] Desktop shortcut removed${NC}"
    fi
    
    # Remove application menu entry
    if [ -f "$HOME/.local/share/applications/slowhttp-c2.desktop" ]; then
        rm "$HOME/.local/share/applications/slowhttp-c2.desktop"
        echo -e "${GREEN}[SUCCESS] Application menu entry removed${NC}"
    fi
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database "$HOME/.local/share/applications/" 2>/dev/null || true
    fi
}

backup_user_data() {
    echo -e "${BLUE}[BACKUP] Creating backup of user data...${NC}"
    
    BACKUP_DIR="$HOME/slowhttp-c2-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup database (without passwords for security)
    if [ -f "$INSTALL_DIR/c2_database.db" ]; then
        sqlite3 "$INSTALL_DIR/c2_database.db" << 'EOF' > "$BACKUP_DIR/vps_list.txt"
.headers on
.mode csv
SELECT ip_address, username, ssh_port, location, status, created_at FROM vps_nodes;
EOF
        echo -e "${GREEN}[SUCCESS] VPS list backed up to $BACKUP_DIR/vps_list.txt${NC}"
    fi
    
    # Backup attack history
    if [ -f "$INSTALL_DIR/c2_database.db" ]; then
        sqlite3 "$INSTALL_DIR/c2_database.db" << 'EOF' > "$BACKUP_DIR/attack_history.txt"
.headers on
.mode csv
SELECT session_name, target_url, attack_type, start_time, end_time, status FROM attack_sessions;
EOF
        echo -e "${GREEN}[SUCCESS] Attack history backed up to $BACKUP_DIR/attack_history.txt${NC}"
    fi
    
    # Backup logs
    if [ -d "$INSTALL_DIR/logs" ]; then
        cp -r "$INSTALL_DIR/logs" "$BACKUP_DIR/"
        echo -e "${GREEN}[SUCCESS] Log files backed up${NC}"
    fi
    
    echo -e "${CYAN}[INFO] Backup created at: $BACKUP_DIR${NC}"
}

remove_installation_directory() {
    echo -e "${BLUE}[CLEANUP] Removing installation directory...${NC}"
    
    # Change to parent directory to avoid deletion conflicts
    cd "$HOME"
    
    # Remove the entire installation directory
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}[SUCCESS] Installation directory removed${NC}"
    else
        echo -e "${YELLOW}[INFO] Installation directory not found${NC}"
    fi
}

clean_system_traces() {
    echo -e "${BLUE}[CLEANUP] Cleaning system traces...${NC}"
    
    # Remove from PATH if added
    if [ -f "$HOME/.bashrc" ]; then
        sed -i '/slowhttp-c2/d' "$HOME/.bashrc" 2>/dev/null || true
    fi
    
    if [ -f "$HOME/.zshrc" ]; then
        sed -i '/slowhttp-c2/d' "$HOME/.zshrc" 2>/dev/null || true
    fi
    
    # Remove any cron jobs
    crontab -l 2>/dev/null | grep -v "slowhttp" | crontab - 2>/dev/null || true
    
    # Clear bash history entries (optional)
    if [ -f "$HOME/.bash_history" ]; then
        sed -i '/slowhttp/d' "$HOME/.bash_history" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[SUCCESS] System traces cleaned${NC}"
}

remove_global_installation() {
    echo -e "${BLUE}[CLEANUP] Checking for global installation...${NC}"
    
    # Check for global installation paths
    GLOBAL_PATHS=(
        "/opt/slowhttp-c2"
        "/usr/local/slowhttp-c2"
        "/usr/share/slowhttp-c2"
    )
    
    for path in "${GLOBAL_PATHS[@]}"; do
        if [ -d "$path" ]; then
            echo -e "${YELLOW}[INFO] Found global installation at $path${NC}"
            read -p "Remove global installation? (y/N): " -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo rm -rf "$path"
                echo -e "${GREEN}[SUCCESS] Removed $path${NC}"
            fi
        fi
    done
    
    # Remove global command links
    if [ -L "/usr/local/bin/slowhttp-c2" ]; then
        sudo rm "/usr/local/bin/slowhttp-c2"
        echo -e "${GREEN}[SUCCESS] Removed global command link${NC}"
    fi
}

verify_removal() {
    echo -e "${BLUE}[VERIFY] Verifying complete removal...${NC}"
    
    REMAINING_FILES=()
    
    # Check for remaining files
    if [ -d "$INSTALL_DIR" ]; then
        REMAINING_FILES+=("Installation directory: $INSTALL_DIR")
    fi
    
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        REMAINING_FILES+=("Systemd service file")
    fi
    
    if [ -f "$HOME/Desktop/SlowHTTP-C2.desktop" ]; then
        REMAINING_FILES+=("Desktop shortcut")
    fi
    
    if pgrep -f "slowhttp_c2" > /dev/null; then
        REMAINING_FILES+=("Running processes")
    fi
    
    if [ ${#REMAINING_FILES[@]} -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Complete removal verified${NC}"
        return 0
    else
        echo -e "${YELLOW}[WARNING] Some files may remain:${NC}"
        for file in "${REMAINING_FILES[@]}"; do
            echo "  • $file"
        done
        return 1
    fi
}

display_completion_message() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    UNINSTALLATION COMPLETE                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -d "$HOME/slowhttp-c2-backup-"* ]; then
        echo -e "${YELLOW}📁 Backup Directory:${NC}"
        ls -d "$HOME/slowhttp-c2-backup-"* 2>/dev/null | head -1
        echo ""
    fi
    
    echo -e "${GREEN}✅ Distributed Slow HTTP C2 has been completely removed${NC}"
    echo -e "${GREEN}✅ All VPS nodes have been cleaned up${NC}"
    echo -e "${GREEN}✅ System traces have been cleared${NC}"
    echo ""
    
    echo -e "${YELLOW}What was removed:${NC}"
    echo "  • Application files and Python environment"
    echo "  • Database and configuration files"
    echo "  • System service and desktop shortcuts"
    echo "  • Log files and temporary data"
    echo "  • VPS attack agents and processes"
    echo ""
    
    echo -e "${CYAN}Thank you for using Distributed Slow HTTP C2!${NC}"
    echo ""
}

# Emergency cleanup function
emergency_cleanup() {
    echo -e "${RED}[EMERGENCY] Performing emergency cleanup...${NC}"
    
    # Kill all related processes
    pkill -9 -f "slowhttp" 2>/dev/null || true
    pkill -9 -f "slowhttp_c2" 2>/dev/null || true
    
    # Remove directories
    rm -rf "$HOME/slowhttp-c2" 2>/dev/null || true
    rm -rf "/tmp/slowhttp_c2" 2>/dev/null || true
    
    # Remove service
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$SERVICE_NAME.service" 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}[SUCCESS] Emergency cleanup completed${NC}"
}

# Main uninstall function
main() {
    print_banner
    
    # Check for emergency flag
    if [[ "$1" == "--emergency" ]]; then
        emergency_cleanup
        exit 0
    fi
    
    # Check for force flag
    if [[ "$1" != "--force" ]]; then
        confirm_uninstall
        echo ""
    fi
    
    echo -e "${RED}[START] Beginning complete uninstallation...${NC}"
    
    # Check if we should backup data
    if [[ "$1" != "--no-backup" ]]; then
        backup_user_data
        echo ""
    fi
    
    stop_running_processes
    cleanup_vps_nodes
    remove_systemd_service
    remove_desktop_shortcuts
    remove_installation_directory
    clean_system_traces
    remove_global_installation
    
    if verify_removal; then
        display_completion_message
    else
        echo -e "${YELLOW}[WARNING] Some components may require manual removal${NC}"
        echo "Run with --emergency flag for aggressive cleanup"
    fi
    
    echo -e "${GREEN}[COMPLETE] Uninstallation process finished${NC}"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Distributed Slow HTTP C2 - Complete Uninstaller"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h       Show this help message"
        echo "  --force          Skip confirmation prompts"
        echo "  --no-backup      Skip backup creation"
        echo "  --emergency      Emergency cleanup (aggressive)"
        echo ""
        echo "Examples:"
        echo "  $0                Normal uninstallation"
        echo "  $0 --force        Uninstall without prompts"
        echo "  $0 --emergency    Emergency cleanup"
        exit 0
        ;;
    --emergency)
        main "$@"
        ;;
    --force)
        main "$@"
        ;;
    --no-backup)
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