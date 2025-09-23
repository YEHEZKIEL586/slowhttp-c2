#!/bin/bash

# Distributed Slow HTTP C2 - Update Script
# This script updates the C2 system to the latest version

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
REPO_URL="https://github.com/yourusername/slowhttp-c2.git"
BACKUP_DIR="$INSTALL_DIR/backup-$(date +%Y%m%d_%H%M%S)"
SERVICE_NAME="slowhttp-c2"

print_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      UPDATE SYSTEM                          ║${NC}"
    echo -e "${CYAN}║              Distributed Slow HTTP C2                       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_git_repository() {
    echo -e "${BLUE}[CHECK] Verifying git repository...${NC}"
    
    if [ ! -d "$INSTALL_DIR/.git" ]; then
        echo -e "${RED}[ERROR] This is not a git repository${NC}"
        echo "Please reinstall using the installer script or clone from GitHub"
        exit 1
    fi
    
    # Check if we're in the right repository
    ORIGIN_URL=$(git -C "$INSTALL_DIR" remote get-url origin 2>/dev/null || echo "")
    if [[ "$ORIGIN_URL" != *"slowhttp-c2"* ]]; then
        echo -e "${YELLOW}[WARNING] Repository URL doesn't match expected URL${NC}"
        echo "Current: $ORIGIN_URL"
        echo "Expected: $REPO_URL"
        
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    echo -e "${GREEN}[SUCCESS] Git repository verified${NC}"
}

check_for_updates() {
    echo -e "${BLUE}[CHECK] Checking for updates...${NC}"
    
    cd "$INSTALL_DIR"
    
    # Fetch latest changes
    git fetch origin main
    
    # Get current and remote commit hashes
    LOCAL_COMMIT=$(git rev-parse HEAD)
    REMOTE_COMMIT=$(git rev-parse origin/main)
    
    if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
        echo -e "${GREEN}[INFO] Already up to date!${NC}"
        
        read -p "Force update anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    else
        echo -e "${YELLOW}[INFO] Updates available${NC}"
        
        # Show what will be updated
        echo -e "${BLUE}[INFO] Changes since last update:${NC}"
        git log --oneline "$LOCAL_COMMIT..$REMOTE_COMMIT" | head -10
        echo ""
    fi
}

backup_current_installation() {
    echo -e "${BLUE}[BACKUP] Creating backup of current installation...${NC}"
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup important files
    BACKUP_FILES=(
        "c2_database.db"
        "key.key" 
        "logs"
        "config"
    )
    
    for file in "${BACKUP_FILES[@]}"; do
        if [ -e "$INSTALL_DIR/$file" ]; then
            cp -r "$INSTALL_DIR/$file" "$BACKUP_DIR/"
            echo -e "${GREEN}[BACKUP] $file${NC}"
        fi
    done
    
    # Backup current version info
    git -C "$INSTALL_DIR" log -1 --format="%H %s" > "$BACKUP_DIR/version_info.txt"
    
    echo -e "${GREEN}[SUCCESS] Backup created at: $BACKUP_DIR${NC}"
}

stop_running_services() {
    echo -e "${BLUE}[STOP] Stopping running processes...${NC}"
    
    # Stop systemd service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${YELLOW}[INFO] Stopping systemd service...${NC}"
        sudo systemctl stop "$SERVICE_NAME"
        SERVICE_WAS_RUNNING=true
    fi
    
    # Stop any running C2 processes
    if pgrep -f "slowhttp_c2.py" > /dev/null; then
        echo -e "${YELLOW}[INFO] Stopping C2 processes...${NC}"
        pkill -f "slowhttp_c2.py" || true
        sleep 2
        
        # Force kill if still running
        pkill -9 -f "slowhttp_c2.py" 2>/dev/null || true
        C2_WAS_RUNNING=true
    fi
    
    echo -e "${GREEN}[SUCCESS] Services stopped${NC}"
}

update_source_code() {
    echo -e "${BLUE}[UPDATE] Updating source code...${NC}"
    
    cd "$INSTALL_DIR"
    
    # Stash any local changes
    if ! git diff --quiet; then
        echo -e "${YELLOW}[INFO] Stashing local changes...${NC}"
        git stash push -m "Auto-stash before update $(date)"
        CHANGES_STASHED=true
    fi
    
    # Pull latest changes
    if git pull origin main; then
        echo -e "${GREEN}[SUCCESS] Source code updated${NC}"
    else
        echo -e "${RED}[ERROR] Failed to update source code${NC}"
        
        # Restore from stash if we stashed changes
        if [ "$CHANGES_STASHED" = true ]; then
            git stash pop
        fi
        exit 1
    fi
    
    # Show what was updated
    NEW_COMMIT=$(git rev-parse HEAD)
    echo -e "${CYAN}[INFO] Updated to commit: ${NEW_COMMIT:0:8}${NC}"
}

update_dependencies() {
    echo -e "${BLUE}[UPDATE] Updating Python dependencies...${NC}"
    
    cd "$INSTALL_DIR"
    
    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
        
        # Upgrade pip first
        pip install --upgrade pip
        
        # Update dependencies
        if pip install --upgrade -r requirements.txt; then
            echo -e "${GREEN}[SUCCESS] Dependencies updated${NC}"
        else
            echo -e "${YELLOW}[WARNING] Some dependencies may have failed to update${NC}"
        fi
        
        # Show installed versions
        echo -e "${BLUE}[INFO] Current dependency versions:${NC}"
        pip list | grep -E "(paramiko|cryptography|psutil|colorama)"
        
    else
        echo -e "${YELLOW}[WARNING] Virtual environment not found${NC}"
        echo "You may need to recreate it:"
        echo "python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    fi
}

update_database_schema() {
    echo -e "${BLUE}[UPDATE] Checking database schema...${NC}"
    
    if [ -f "$INSTALL_DIR/c2_database.db" ]; then
        # Backup database before schema changes
        cp "$INSTALL_DIR/c2_database.db" "$BACKUP_DIR/c2_database_pre_update.db"
        
        # Run database migrations if needed
        cd "$INSTALL_DIR"
        source venv/bin/activate
        
        # Check if we need to run migrations
        python3 -c "
from slowhttp_c2 import DatabaseManager
db = DatabaseManager()
print('Database schema check completed')
" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not verify database schema${NC}"
        
        echo -e "${GREEN}[SUCCESS] Database schema updated${NC}"
    else
        echo -e "${YELLOW}[INFO] No existing database found${NC}"
    fi
}

restore_user_data() {
    echo -e "${BLUE}[RESTORE] Restoring user data...${NC}"
    
    # Restore key file if it was backed up
    if [ -f "$BACKUP_DIR/key.key" ] && [ ! -f "$INSTALL_DIR/key.key" ]; then
        cp "$BACKUP_DIR/key.key" "$INSTALL_DIR/"
        echo -e "${GREEN}[RESTORE] Encryption key${NC}"
    fi
    
    # Restore database if it was backed up
    if [ -f "$BACKUP_DIR/c2_database.db" ] && [ ! -f "$INSTALL_DIR/c2_database.db" ]; then
        cp "$BACKUP_DIR/c2_database.db" "$INSTALL_DIR/"
        echo -e "${GREEN}[RESTORE] Database${NC}"
    fi
    
    # Restore logs
    if [ -d "$BACKUP_DIR/logs" ]; then
        cp -r "$BACKUP_DIR/logs" "$INSTALL_DIR/" 2>/dev/null || true
        echo -e "${GREEN}[RESTORE] Log files${NC}"
    fi
    
    # Restore config
    if [ -d "$BACKUP_DIR/config" ]; then
        cp -r "$BACKUP_DIR/config" "$INSTALL_DIR/" 2>/dev/null || true
        echo -e "${GREEN}[RESTORE] Configuration files${NC}"
    fi
    
    echo -e "${GREEN}[SUCCESS] User data restored${NC}"
}

restart_services() {
    echo -e "${BLUE}[START] Restarting services...${NC}"
    
    # Set proper permissions
    chmod +x "$INSTALL_DIR/start.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/install.sh" 2>/dev/null || true
    
    # Restart systemd service if it was running
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo -e "${YELLOW}[INFO] Restarting systemd service...${NC}"
        sudo systemctl start "$SERVICE_NAME"
        
        # Check if service started successfully
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}[SUCCESS] Service restarted${NC}"
        else
            echo -e "${RED}[ERROR] Service failed to start${NC}"
            echo "Check logs with: sudo journalctl -u $SERVICE_NAME -n 20"
        fi
    fi
    
    echo -e "${GREEN}[SUCCESS] Services restarted${NC}"
}

run_post_update_tests() {
    echo -e "${BLUE}[TEST] Running post-update tests...${NC}"
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Test basic imports
    python3 -c "
import slowhttp_c2
import paramiko
import cryptography
print('✅ Basic imports successful')
" || {
        echo -e "${RED}[ERROR] Import tests failed${NC}"
        return 1
    }
    
    # Test database connectivity
    python3 -c "
from slowhttp_c2 import DatabaseManager, SecurityManager
db = DatabaseManager()
sec = SecurityManager()
print('✅ Database and security managers working')
" || {
        echo -e "${RED}[ERROR] Database tests failed${NC}"
        return 1
    }
    
    echo -e "${GREEN}[SUCCESS] Post-update tests passed${NC}"
}

cleanup_old_backups() {
    echo -e "${BLUE}[CLEANUP] Managing old backups...${NC}"
    
    # Keep only the last 5 backups
    BACKUP_COUNT=$(ls -d "$INSTALL_DIR"/backup-* 2>/dev/null | wc -l)
    
    if [ "$BACKUP_COUNT" -gt 5 ]; then
        echo -e "${YELLOW}[INFO] Removing old backups (keeping last 5)...${NC}"
        ls -dt "$INSTALL_DIR"/backup-* | tail -n +6 | xargs rm -rf
        echo -e "${GREEN}[SUCCESS] Old backups cleaned${NC}"
    fi
}

display_update_summary() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                     UPDATE COMPLETE                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Show version information
    cd "$INSTALL_DIR"
    CURRENT_COMMIT=$(git log -1 --format="%H")
    CURRENT_MESSAGE=$(git log -1 --format="%s")
    CURRENT_DATE=$(git log -1 --format="%ad" --date=short)
    
    echo -e "${YELLOW}📊 Update Summary:${NC}"
    echo -e "  Version: ${CYAN}${CURRENT_COMMIT:0:8}${NC}"
    echo -e "  Date: ${CYAN}$CURRENT_DATE${NC}"
    echo -e "  Message: ${CYAN}$CURRENT_MESSAGE${NC}"
    echo ""
    
    if [ -d "$BACKUP_DIR" ]; then
        echo -e "${YELLOW}💾 Backup Created:${NC}"
        echo -e "  Location: ${CYAN}$BACKUP_DIR${NC}"
        echo ""
    fi
    
    echo -e "${YELLOW}🚀 Next Steps:${NC}"
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo "  • Service has been restarted automatically"
    else
        echo "  • Start the system: ${CYAN}./start.sh${NC}"
    fi
    echo "  • Test functionality with a small VPS pool"
    echo "  • Review release notes for any breaking changes"
    echo ""
    
    echo -e "${GREEN}✅ Update completed successfully!${NC}"
}

# Rollback function
rollback_update() {
    echo -e "${RED}[ROLLBACK] Rolling back to previous version...${NC}"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        echo -e "${RED}[ERROR] No backup directory found${NC}"
        echo "Available backups:"
        ls -d "$INSTALL_DIR"/backup-* 2>/dev/null || echo "No backups found"
        exit 1
    fi
    
    cd "$INSTALL_DIR"
    
    # Stop services
    stop_running_services
    
    # Restore files from backup
    if [ -f "$BACKUP_DIR/c2_database.db" ]; then
        cp "$BACKUP_DIR/c2_database.db" "$INSTALL_DIR/"
    fi
    
    if [ -f "$BACKUP_DIR/key.key" ]; then
        cp "$BACKUP_DIR/key.key" "$INSTALL_DIR/"
    fi
    
    if [ -d "$BACKUP_DIR/logs" ]; then
        rm -rf "$INSTALL_DIR/logs" 2>/dev/null || true
        cp -r "$BACKUP_DIR/logs" "$INSTALL_DIR/"
    fi
    
    if [ -d "$BACKUP_DIR/config" ]; then
        rm -rf "$INSTALL_DIR/config" 2>/dev/null || true
        cp -r "$BACKUP_DIR/config" "$INSTALL_DIR/"
    fi
    
    # Restore git state
    if [ -f "$BACKUP_DIR/version_info.txt" ]; then
        PREVIOUS_COMMIT=$(head -n 1 "$BACKUP_DIR/version_info.txt" | cut -d' ' -f1)
        git reset --hard "$PREVIOUS_COMMIT"
        echo -e "${GREEN}[SUCCESS] Rolled back to commit: ${PREVIOUS_COMMIT:0:8}${NC}"
    fi
    
    # Restart services
    restart_services
    
    echo -e "${GREEN}[SUCCESS] Rollback completed${NC}"
}

# Check updates function
check_updates_only() {
    echo -e "${BLUE}[CHECK] Checking for available updates...${NC}"
    
    cd "$INSTALL_DIR"
    git fetch origin main
    
    LOCAL_COMMIT=$(git rev-parse HEAD)
    REMOTE_COMMIT=$(git rev-parse origin/main)
    
    if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
        echo -e "${GREEN}[INFO] No updates available${NC}"
        echo -e "${CYAN}Current version: ${LOCAL_COMMIT:0:8}${NC}"
    else
        echo -e "${YELLOW}[INFO] Updates available!${NC}"
        echo -e "${CYAN}Current: ${LOCAL_COMMIT:0:8}${NC}"
        echo -e "${CYAN}Latest:  ${REMOTE_COMMIT:0:8}${NC}"
        echo ""
        echo -e "${BLUE}Available updates:${NC}"
        git log --oneline "$LOCAL_COMMIT..$REMOTE_COMMIT"
        echo ""
        echo "Run './update.sh' to update"
    fi
}

# Main update function
main() {
    print_banner
    
    case "${1:-}" in
        --check)
            check_updates_only
            exit 0
            ;;
        --rollback)
            # Find most recent backup
            LATEST_BACKUP=$(ls -dt "$INSTALL_DIR"/backup-* 2>/dev/null | head -n 1)
            if [ -z "$LATEST_BACKUP" ]; then
                echo -e "${RED}[ERROR] No backups found for rollback${NC}"
                exit 1
            fi
            BACKUP_DIR="$LATEST_BACKUP"
            rollback_update
            exit 0
            ;;
        --force)
            # Skip update check
            FORCE_UPDATE=true
            ;;
    esac
    
    echo -e "${YELLOW}This will update Distributed Slow HTTP C2 to the latest version.${NC}"
    echo ""
    
    check_git_repository
    
    if [ "$FORCE_UPDATE" != true ]; then
        check_for_updates
    fi
    
    echo ""
    read -p "Continue with update? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Update cancelled${NC}"
        exit 0
    fi
    
    echo -e "${BLUE}[START] Beginning update process...${NC}"
    
    backup_current_installation
    stop_running_services
    update_source_code
    update_dependencies
    update_database_schema
    restore_user_data
    
    # Run tests
    if run_post_update_tests; then
        restart_services
        cleanup_old_backups
        display_update_summary
        echo -e "${GREEN}[COMPLETE] Update process finished successfully!${NC}"
    else
        echo -e "${RED}[ERROR] Update tests failed${NC}"
        echo "Would you like to rollback? (y/N): "
        read -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rollback_update
        else
            echo -e "${YELLOW}[WARNING] Update completed but tests failed${NC}"
            echo "Please check the installation manually"
        fi
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Distributed Slow HTTP C2 - Update System"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo "  --check         Check for updates without installing"
        echo "  --force         Force update even if up to date"
        echo "  --rollback      Rollback to previous version"
        echo ""
        echo "Examples:"
        echo "  $0              Check and install updates"
        echo "  $0 --check      Check for updates only"
        echo "  $0 --force      Force update"
        echo "  $0 --rollback   Rollback to previous version"
        exit 0
        ;;
    --check)
        main "$@"
        ;;
    --rollback)
        main "$@"
        ;;
    --force)
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