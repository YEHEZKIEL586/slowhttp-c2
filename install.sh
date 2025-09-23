#!/bin/bash

# Distributed Slow HTTP C2 - Installation Script
# Version: 1.1.0 (Fixed)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/YEHEZKIEL586/slowhttp-c2.git"
INSTALL_DIR="$HOME/slowhttp-c2"
PYTHON_MIN_VERSION="3.6"
INSTALLER_VERSION="1.1.0"
LOG_FILE="/tmp/slowhttp-c2-install.log"

# Global variables
OS=""
PKG_MANAGER=""
PKG_UPDATE=""
PKG_INSTALL=""
FORCE_INSTALL=false
QUIET_MODE=false
NO_SERVICE=false
CUSTOM_DIR=""
START_TIME=$(date +%s)

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Error handling
error_exit() {
    local error_message="$1"
    echo -e "${RED}[ERROR] $error_message${NC}" >&2
    log "ERROR: $error_message"
    echo -e "${YELLOW}Log file available at: $LOG_FILE${NC}"
    exit 1
}

# Show help
show_help() {
    cat << EOF
Distributed Slow HTTP C2 Installer v$INSTALLER_VERSION

USAGE:
    bash install.sh [OPTIONS]

OPTIONS:
    --help, -h          Show this help
    --version, -v       Show installer version
    --force             Force install without confirmation
    --dir PATH          Custom installation directory
    --no-service        Don't setup systemd service
    --quiet, -q         Quiet installation mode

EXAMPLES:
    bash install.sh --force --dir /opt/slowhttp-c2
    bash install.sh --no-service --quiet

WARNING:
    This tool is ONLY for education and authorized testing!
    Illegal usage may result in legal consequences.
EOF
}

# Banner
print_banner() {
    if [ "$QUIET_MODE" != true ]; then
        clear
        echo -e "${CYAN}${WHITE}${BOLD}"
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                    DISTRIBUTED SLOW HTTP C2 INSTALLER                       ║"
        echo "║                           Installation v$INSTALLER_VERSION                         ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "${RED}${BOLD}⚠️  WARNING: ONLY FOR EDUCATION AND AUTHORIZED TESTING! ⚠️${NC}"
        echo -e "${RED}   Unauthorized use on systems you don't own is ILLEGAL!${NC}"
        echo ""
    fi
}

# Check if running as root
check_user() {
    log "Checking user permissions"
    
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[WARNING] Running as root. It's recommended to use a regular user.${NC}"
        echo -e "${YELLOW}Installing as root can pose security risks.${NC}"
        
        if [ "$FORCE_INSTALL" != true ]; then
            read -p "Continue as root? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Installation cancelled by user"
            fi
        fi
        log "User chose to continue as root"
    else
        log "Running as regular user: $(whoami)"
    fi
}

# Detect operating system
detect_os() {
    log "Detecting operating system"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
            PKG_MANAGER="apt"
            PKG_UPDATE="apt update"
            PKG_INSTALL="apt install -y"
            echo -e "${GREEN}[INFO] Detected Debian/Ubuntu system${NC}"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            echo -e "${GREEN}[INFO] Detected RedHat/CentOS system${NC}"
        elif [ -f /etc/fedora-release ]; then
            OS="fedora"
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf update -y"
            PKG_INSTALL="dnf install -y"
            echo -e "${GREEN}[INFO] Detected Fedora system${NC}"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PKG_INSTALL="pacman -S --noconfirm"
            echo -e "${GREEN}[INFO] Detected Arch Linux system${NC}"
        else
            OS="linux"
            echo -e "${YELLOW}[WARNING] Generic Linux detected${NC}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}[INFO] Detected macOS system${NC}"
    else
        OS="unknown"
        echo -e "${YELLOW}[WARNING] Unknown system: $OSTYPE${NC}"
    fi
    
    log "Detected OS: $OS"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python() {
    log "Checking Python installation"
    echo -e "${BLUE}[CHECK] Checking Python installation...${NC}"
    
    if command_exists python3; then
        local python_version
        python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[INFO] Python ${python_version} found${NC}"
            log "Found Python version: $python_version"
            
            # Check if version is sufficient
            if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)" 2>/dev/null; then
                echo -e "${GREEN}[INFO] Python version is sufficient${NC}"
                log "Python version is sufficient"
            else
                error_exit "Python ${PYTHON_MIN_VERSION}+ required, found ${python_version}"
            fi
        else
            error_exit "Python3 found but cannot execute"
        fi
    else
        echo -e "${YELLOW}[WARNING] Python3 not found, will install...${NC}"
        log "Python3 not found, will install"
    fi
    
    # Check pip
    if ! command_exists pip3 && ! python3 -m pip --version >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARNING] pip not found, will install...${NC}"
        log "pip not found, will install"
    fi
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies"
    echo -e "${BLUE}[INSTALL] Installing system dependencies...${NC}"
    
    case $OS in
        "debian")
            if ! sudo $PKG_UPDATE; then
                error_exit "Failed to update package lists"
            fi
            local packages="python3 python3-pip python3-venv git curl wget build-essential libffi-dev libssl-dev openssh-client"
            if ! sudo $PKG_INSTALL $packages; then
                error_exit "Failed to install dependencies for Debian/Ubuntu"
            fi
            ;;
        "redhat")
            local packages="python3 python3-pip git curl wget gcc openssl-devel libffi-devel openssh-clients"
            if ! sudo $PKG_INSTALL $packages; then
                error_exit "Failed to install dependencies for RedHat/CentOS"
            fi
            ;;
        "fedora")
            local packages="python3 python3-pip git curl wget gcc openssl-devel libffi-devel openssh-clients"
            if ! sudo $PKG_INSTALL $packages; then
                error_exit "Failed to install dependencies for Fedora"
            fi
            ;;
        "arch")
            local packages="python python-pip git curl wget base-devel openssh"
            if ! sudo $PKG_INSTALL $packages; then
                error_exit "Failed to install dependencies for Arch Linux"
            fi
            ;;
        "macos")
            if ! command_exists brew; then
                echo -e "${BLUE}[INSTALL] Installing Homebrew...${NC}"
                if ! /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
                    error_exit "Failed to install Homebrew"
                fi
            fi
            
            if ! brew install python3 git curl wget; then
                error_exit "Failed to install dependencies for macOS"
            fi
            ;;
        *)
            echo -e "${YELLOW}[WARNING] Please install the following dependencies manually:${NC}"
            echo "  - python3 (>= 3.6)"
            echo "  - python3-pip"
            echo "  - python3-venv"
            echo "  - git"
            echo "  - curl"
            echo "  - wget"
            echo "  - build tools (gcc, make, etc.)"
            echo "  - ssh client"
            
            if [ "$FORCE_INSTALL" != true ]; then
                read -p "Continue installation? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    error_exit "Installation cancelled - dependencies incomplete"
                fi
            fi
            ;;
    esac
    
    log "System dependencies installation completed"
    echo -e "${GREEN}[SUCCESS] System dependencies installed successfully${NC}"
}

# Create project structure directly (without git clone)
create_project() {
    log "Creating project structure"
    echo -e "${BLUE}[CREATE] Creating project structure...${NC}"
    
    # Remove existing directory if it exists
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}[WARNING] Directory $INSTALL_DIR already exists${NC}"
        
        if [ "$FORCE_INSTALL" = true ]; then
            echo -e "${YELLOW}[INFO] Force mode active, removing existing directory...${NC}"
            if ! rm -rf "$INSTALL_DIR"; then
                error_exit "Failed to remove existing directory"
            fi
        else
            read -p "Remove existing installation? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if ! rm -rf "$INSTALL_DIR"; then
                    error_exit "Failed to remove existing directory"
                fi
                echo -e "${GREEN}[INFO] Existing directory removed${NC}"
            else
                error_exit "Installation cancelled - directory already exists"
            fi
        fi
    fi
    
    # Create directory structure
    mkdir -p "$INSTALL_DIR"/{logs,config,agents}
    cd "$INSTALL_DIR" || error_exit "Failed to enter installation directory"
    
    # Create requirements.txt
    cat > requirements.txt << 'EOF'
# Distributed Slow HTTP C2 - Python Dependencies
paramiko>=2.9.0
cryptography>=3.4.8
colorama>=0.4.4
psutil>=5.8.0
requests>=2.25.0
bcrypt>=3.2.0
EOF
    
    log "Project structure created successfully"
    echo -e "${GREEN}[SUCCESS] Project structure created${NC}"
}

# Setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment"
    echo -e "${BLUE}[SETUP] Creating Python virtual environment...${NC}"
    
    # Create virtual environment
    if ! python3 -m venv venv; then
        error_exit "Failed to create virtual environment"
    fi
    
    echo -e "${GREEN}[SUCCESS] Virtual environment created successfully${NC}"
    
    # Activate virtual environment
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    else
        error_exit "Virtual environment activation file not found"
    fi
    
    # Verify virtual environment
    if [ -z "$VIRTUAL_ENV" ]; then
        error_exit "Virtual environment not activated successfully"
    fi
    
    echo -e "${GREEN}[INFO] Virtual environment activated: $VIRTUAL_ENV${NC}"
    
    # Upgrade pip
    echo -e "${BLUE}[SETUP] Upgrading pip...${NC}"
    if ! python -m pip install --upgrade pip; then
        echo -e "${YELLOW}[WARNING] Failed to upgrade pip, continuing with existing version${NC}"
    fi
    
    # Install Python dependencies
    echo -e "${BLUE}[SETUP] Installing Python dependencies...${NC}"
    if [ -f "requirements.txt" ]; then
        if ! pip install -r requirements.txt; then
            error_exit "Failed to install Python dependencies from requirements.txt"
        fi
    else
        error_exit "requirements.txt not found"
    fi
    
    # Verify installation
    if ! python -c "import paramiko, cryptography, colorama; print('Dependencies OK')"; then
        error_exit "Python dependencies verification failed"
    fi
    
    log "Python environment setup completed"
    echo -e "${GREEN}[SUCCESS] Python environment setup completed${NC}"
}

# Create main application file
create_main_app() {
    log "Creating main application file"
    echo -e "${BLUE}[CREATE] Creating main application...${NC}"
    
    # This will create a placeholder for the main app
    # In a real deployment, you would copy the actual slowhttp_c2.py here
    cat > slowhttp_c2.py << 'EOF'
#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Main Application
Purpose: Educational and Authorized Penetration Testing Only
"""

import sys
import os

def main():
    print("="*80)
    print("    DISTRIBUTED SLOW HTTP TESTING C2 - PLACEHOLDER")
    print("="*80)
    print()
    print("⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️")
    print("   Unauthorized use against systems you don't own is ILLEGAL!")
    print()
    print("This is a placeholder installation.")
    print("Please replace this file with the actual slowhttp_c2.py")
    print()
    print("Installation directory:", os.getcwd())
    print("Python executable:", sys.executable)
    print("Python version:", sys.version)
    print()
    print("To complete setup:")
    print("1. Replace slowhttp_c2.py with the actual application")
    print("2. Run: ./start.sh")
    print()

if __name__ == '__main__':
    main()
EOF
    
    chmod +x slowhttp_c2.py
    
    log "Main application file created"
    echo -e "${GREEN}[SUCCESS] Main application placeholder created${NC}"
}

# Create launcher scripts
create_launchers() {
    log "Creating launcher scripts"
    echo -e "${BLUE}[SETUP] Creating launcher scripts...${NC}"
    
    # Create start.sh
    cat > start.sh << 'EOF'
#!/bin/bash
# Distributed Slow HTTP C2 - Quick Launcher
cd "$(dirname "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found!${NC}"
    echo -e "${YELLOW}Please run the installer first${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}🔧 Activating Python environment...${NC}"
source venv/bin/activate

# Check if main script exists
if [ ! -f "slowhttp_c2.py" ]; then
    echo -e "${RED}❌ Main script (slowhttp_c2.py) not found!${NC}"
    exit 1
fi

# Check Python dependencies
echo -e "${BLUE}🔍 Checking dependencies...${NC}"
if ! python3 -c "import paramiko, cryptography" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Dependencies missing. Installing...${NC}"
    pip install -r requirements.txt
fi

# Create necessary directories
mkdir -p logs config

# Clear screen and show banner
clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    🎯 DISTRIBUTED SLOW HTTP C2                              ║${NC}"
echo -e "${CYAN}║                           Starting System...                                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📂 Working Directory: $(pwd)${NC}"
echo -e "${GREEN}🐍 Python Environment: $(which python)${NC}"
echo -e "${GREEN}📊 Python Version: $(python --version)${NC}"
echo ""
echo -e "${RED}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️${NC}"
echo ""

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}🛑 Shutting down C2 system...${NC}"; exit 0' INT

# Launch main application
python3 slowhttp_c2.py "$@"

# Exit message
echo ""
echo -e "${CYAN}👋 Thank you for using Distributed Slow HTTP C2!${NC}"
EOF
    
    # Create update.sh
    cat > update.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🔄 Updating Distributed Slow HTTP C2..."

# Update Python dependencies
if [ -d "venv" ]; then
    source venv/bin/activate
    pip install --upgrade -r requirements.txt
    echo "✅ Dependencies updated!"
else
    echo "❌ Virtual environment not found"
    exit 1
fi

echo "✅ Update completed!"
EOF
    
    # Create uninstaller
    cat > uninstall.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🗑️  Uninstalling Distributed Slow HTTP C2..."
echo ""
echo "⚠️  This will remove:"
echo "   • All application files"
echo "   • Python virtual environment"
echo "   • Database and configuration"
echo "   • Log files"
echo ""

read -p "Are you sure you want to completely remove the installation? (type 'DELETE' to confirm): " -r
echo

if [[ $REPLY == "DELETE" ]]; then
    CURRENT_DIR=$(pwd)
    cd ..
    
    if rm -rf "$CURRENT_DIR"; then
        echo "✅ Uninstall completed!"
        echo "📂 Directory removed: $CURRENT_DIR"
    else
        echo "❌ Failed to remove directory"
        exit 1
    fi
else
    echo "❌ Uninstall cancelled"
fi
EOF
    
    # Make scripts executable
    chmod +x start.sh update.sh uninstall.sh
    
    log "Launcher scripts created successfully"
    echo -e "${GREEN}[SUCCESS] Launcher scripts created successfully${NC}"
}

# Security setup
setup_security() {
    log "Setting up security measures"
    echo -e "${BLUE}[SECURITY] Applying security measures...${NC}"
    
    # Set proper permissions
    chmod 700 "$INSTALL_DIR" 2>/dev/null || true
    chmod 600 "$INSTALL_DIR"/*.py 2>/dev/null || true
    
    # Create comprehensive .gitignore
    cat > .gitignore << 'EOF'
# Database and logs
*.db
*.log
key.key
*.sqlite
*.sqlite3

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST
venv/
env/
ENV/

# System files
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# Configuration files with sensitive data
config.ini
.env
local_config.py

# Temporary files
*.tmp
*.temp
/tmp/

# SSH keys
id_rsa*
id_dsa*
id_ecdsa*
*.pem

# Sensitive data
passwords.txt
credentials.txt
vps_list.txt
targets.txt
EOF
    
    log "Security measures applied successfully"
    echo -e "${GREEN}[SUCCESS] Security measures applied${NC}"
}

# Verify installation
verify_installation() {
    log "Verifying installation"
    echo -e "${BLUE}[VERIFY] Verifying installation...${NC}"
    
    # Check if required files exist
    local required_files=("slowhttp_c2.py" "requirements.txt" "start.sh" "update.sh" "uninstall.sh")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            error_exit "Required file not found: $file"
        fi
    done
    
    # Check virtual environment
    if [ ! -d "venv" ]; then
        error_exit "Virtual environment not found"
    fi
    
    # Test Python imports
    source venv/bin/activate
    
    echo -e "${BLUE}[TEST] Testing Python dependencies...${NC}"
    if ! python -c "import paramiko, cryptography, colorama; print('✅ All dependencies OK')"; then
        error_exit "Python dependencies verification failed"
    fi
    
    # Test main script syntax
    if ! python -m py_compile slowhttp_c2.py; then
        error_exit "Main script syntax check failed"
    fi
    
    # Check permissions
    if [ ! -x "start.sh" ] || [ ! -x "update.sh" ] || [ ! -x "uninstall.sh" ]; then
        echo -e "${YELLOW}[FIX] Fixing script permissions...${NC}"
        chmod +x start.sh update.sh uninstall.sh
    fi
    
    log "Installation verification completed successfully"
    echo -e "${GREEN}[SUCCESS] Installation verification completed!${NC}"
}

# Show completion message
show_completion() {
    local install_time=$(($(date +%s) - START_TIME))
    
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                            INSTALLATION SUCCESSFUL!                         ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  📍 Installation Location: ${WHITE}$(printf "%-41s" "$INSTALL_DIR")${GREEN} ║"
    echo -e "║  ⏱️  Installation Time: ${WHITE}$(printf "%-46s" "${install_time}s")${GREEN} ║"
    echo -e "║  🐍 Python Environment: ${WHITE}$(printf "%-42s" "$VIRTUAL_ENV")${GREEN} ║"
    echo "║                                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                            USAGE INSTRUCTIONS                               ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  🚀 ${WHITE}To Run:${GREEN}                                                         ║"
    echo -e "║     ${CYAN}cd $INSTALL_DIR${GREEN}"
    printf "║     %-70s║\n" ""
    echo -e "║     ${CYAN}./start.sh${GREEN}                                                          ║"
    echo "║                                                                              ║"
    echo -e "║  🔧 ${WHITE}Manual Run:${GREEN}                                                     ║"
    echo -e "║     ${CYAN}source venv/bin/activate && python slowhttp_c2.py${GREEN}                  ║"
    echo "║                                                                              ║"
    echo -e "║  🔄 ${WHITE}Update:${GREEN}                                                         ║"
    echo -e "║     ${CYAN}./update.sh${GREEN}                                                         ║"
    echo "║                                                                              ║"
    echo -e "║  🗑️  ${WHITE}Uninstall:${GREEN}                                                       ║"
    echo -e "║     ${CYAN}./uninstall.sh${GREEN}                                                      ║"
    echo "║                                                                              ║"
    echo "║  ⚠️  ${WHITE}IMPORTANT: Replace slowhttp_c2.py with actual application!${GREEN}        ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${RED}${BOLD}⚠️  IMPORTANT WARNING:${NC}"
    echo -e "${RED}   • This tool is ONLY for educational purposes and authorized testing${NC}"
    echo -e "${RED}   • Unauthorized use on systems you don't own is ILLEGAL${NC}"
    echo -e "${RED}   • You are fully responsible for how you use this tool${NC}"
    echo -e "${RED}   • Always follow applicable laws and regulations${NC}"
    echo ""
    
    log "Installation completed successfully in ${install_time}s"
}

# Main function
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "Distributed Slow HTTP C2 Installer v$INSTALLER_VERSION"
                exit 0
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --quiet|-q)
                QUIET_MODE=true
                shift
                ;;
            --no-service)
                NO_SERVICE=true
                shift
                ;;
            --dir=*)
                CUSTOM_DIR="${1#*=}"
                shift
                ;;
            --dir)
                CUSTOM_DIR="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}[ERROR] Unknown option: $1${NC}" >&2
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done
    
    # Set custom directory if provided
    if [ -n "$CUSTOM_DIR" ]; then
        INSTALL_DIR="$CUSTOM_DIR"
    fi
    
    # Start logging
    log "=== Slowhttp C2 Installation Started ==="
    log "Installer Version: $INSTALLER_VERSION"
    log "Install Directory: $INSTALL_DIR"
    
    # Show banner
    print_banner
    
    # System checks
    check_user
    detect_os
    check_python
    
    # Installation steps
    echo -e "${BLUE}[INFO] Starting installation process...${NC}"
    install_dependencies
    create_project
    setup_python_env
    create_main_app
    create_launchers
    setup_security
    
    # Verification
    verify_installation
    
    # Completion
    show_completion
    
    log "=== Installation Completed Successfully ==="
}

# Error handling for script
trap 'error_exit "Unexpected error occurred at line $LINENO"' ERR

# Run main function with all arguments
main "$@"
