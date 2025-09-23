#!/bin/bash

# Distributed Slow HTTP C2 - GitHub Installer
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/YEHEZKIEL586/slowhttp-c2.git"
INSTALL_DIR="$HOME/slowhttp-c2"
PYTHON_MIN_VERSION="3.6"

# Banner
print_banner() {
    clear
    echo -e "${CYAN}${WHITE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    DISTRIBUTED SLOW HTTP C2 INSTALLER                       ║"
    echo "║                           GitHub Installation                               ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${RED}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️${NC}"
    echo -e "${RED}   Unauthorized use against systems you don't own is ILLEGAL!${NC}"
    echo ""
}

# Check if running as root
check_user() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[WARNING] Running as root. Consider using a regular user.${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}Installation cancelled${NC}"
            exit 1
        fi
    fi
}

# Detect operating system
detect_os() {
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
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PKG_INSTALL="pacman -S --noconfirm"
            echo -e "${GREEN}[INFO] Detected Arch Linux system${NC}"
        else
            OS="linux"
            echo -e "${YELLOW}[WARNING] Generic Linux detected, may need manual dependency installation${NC}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}[INFO] Detected macOS system${NC}"
    else
        OS="unknown"
        echo -e "${YELLOW}[WARNING] Unknown operating system detected${NC}"
    fi
}

# Check Python version
check_python() {
    echo -e "${BLUE}[CHECK] Checking Python installation...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        echo -e "${GREEN}[INFO] Python ${PYTHON_VERSION} found${NC}"
        
        # Check if version is sufficient
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)"; then
            echo -e "${GREEN}[INFO] Python version is sufficient${NC}"
        else
            echo -e "${RED}[ERROR] Python ${PYTHON_MIN_VERSION}+ required, found ${PYTHON_VERSION}${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}[WARNING] Python3 not found, will install...${NC}"
        INSTALL_PYTHON=true
    fi
}

# Install system dependencies
install_dependencies() {
    echo -e "${BLUE}[INSTALL] Installing system dependencies...${NC}"
    
    case $OS in
        "debian")
            sudo $PKG_UPDATE
            sudo $PKG_INSTALL python3 python3-pip python3-venv git curl wget build-essential libffi-dev libssl-dev
            ;;
        "redhat")
            sudo $PKG_UPDATE
            sudo $PKG_INSTALL python3 python3-pip git curl wget gcc openssl-devel libffi-devel
            ;;
        "arch")
            sudo $PKG_UPDATE
            sudo $PKG_INSTALL python python-pip git curl wget base-devel
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                echo -e "${BLUE}[INSTALL] Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh)"
            fi
            brew install python3 git curl wget
            ;;
        *)
            echo -e "${YELLOW}[WARNING] Please install python3, pip, git, curl manually${NC}"
            ;;
    esac
}

# Check if git is available
check_git() {
    if ! command -v git &> /dev/null; then
        echo -e "${RED}[ERROR] Git is required but not installed${NC}"
        echo -e "${YELLOW}[INFO] Installing git...${NC}"
        
        case $OS in
            "debian") sudo apt install -y git ;;
            "redhat") sudo yum install -y git ;;
            "arch") sudo pacman -S --noconfirm git ;;
            "macos") brew install git ;;
            *) echo -e "${RED}[ERROR] Please install git manually${NC}"; exit 1 ;;
        esac
    fi
}

# Download/clone repository
download_repo() {
    echo -e "${BLUE}[DOWNLOAD] Cloning repository...${NC}"
    
    # Remove existing directory if it exists
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}[WARNING] Directory $INSTALL_DIR already exists${NC}"
        read -p "Remove existing installation? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            echo -e "${GREEN}[INFO] Removed existing directory${NC}"
        else
            echo -e "${RED}[ERROR] Installation cancelled${NC}"
            exit 1
        fi
    fi
    
    # Clone repository
    if git clone "$REPO_URL" "$INSTALL_DIR"; then
        echo -e "${GREEN}[SUCCESS] Repository cloned successfully${NC}"
    else
        echo -e "${RED}[ERROR] Failed to clone repository${NC}"
        echo -e "${YELLOW}[INFO] You can also download manually from: $REPO_URL${NC}"
        exit 1
    fi
    
    cd "$INSTALL_DIR"
}

# Setup Python virtual environment
setup_python_env() {
    echo -e "${BLUE}[SETUP] Creating Python virtual environment...${NC}"
    
    # Create virtual environment
    if python3 -m venv venv; then
        echo -e "${GREEN}[SUCCESS] Virtual environment created${NC}"
    else
        echo -e "${RED}[ERROR] Failed to create virtual environment${NC}"
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    echo -e "${BLUE}[SETUP] Upgrading pip...${NC}"
    pip install --upgrade pip
    
    # Install Python dependencies
    echo -e "${BLUE}[SETUP] Installing Python dependencies...${NC}"
    if pip install -r requirements.txt; then
        echo -e "${GREEN}[SUCCESS] Python dependencies installed${NC}"
    else
        echo -e "${RED}[ERROR] Failed to install Python dependencies${NC}"
        echo -e "${YELLOW}[INFO] You may need to install them manually:${NC}"
        echo -e "${YELLOW}pip install paramiko cryptography${NC}"
        exit 1
    fi
}

# Create launcher scripts
create_launchers() {
    echo -e "${BLUE}[SETUP] Creating launcher scripts...${NC}"
    
    # Make start.sh executable
    chmod +x start.sh
    
    # Create update script
    cat > update.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🔄 Updating Distributed Slow HTTP C2..."

# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip install --upgrade -r requirements.txt

echo "✅ Update completed!"
EOF

    # Create uninstaller
    cat > uninstall.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🗑️  Uninstalling Distributed Slow HTTP C2..."

read -p "Are you sure you want to completely remove the installation? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd ..
    rm -rf "$(basename "$PWD")"
    echo "✅ Uninstallation completed!"
else
    echo "❌ Uninstallation cancelled"
fi
EOF

    # Make scripts executable
    chmod +x update.sh uninstall.sh
    
    echo -e "${GREEN}[SUCCESS] Launcher scripts created${NC}"
}

# Setup systemd service (optional)
setup_service() {
    if [[ "$OS" == "debian" || "$OS" == "redhat" || "$OS" == "arch" ]]; then
        read -p "Setup as system service? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[SETUP] Creating systemd service...${NC}"
            
            SERVICE_FILE="/etc/systemd/system/slowhttp-c2.service"
            
            sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Distributed Slow HTTP C2 Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/slowhttp_c2.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
            
            sudo systemctl daemon-reload
            
            echo -e "${GREEN}[SUCCESS] Systemd service created${NC}"
            echo -e "${CYAN}[INFO] Enable service: sudo systemctl enable slowhttp-c2${NC}"
            echo -e "${CYAN}[INFO] Start service: sudo systemctl start slowhttp-c2${NC}"
            echo -e "${CYAN}[INFO] View logs: sudo journalctl -u slowhttp-c2 -f${NC}"
        fi
    fi
}

# Security setup
setup_security() {
    echo -e "${BLUE}[SECURITY] Setting up security measures...${NC}"
    
    # Set proper permissions
    chmod 700 "$INSTALL_DIR"
    chmod 600 "$INSTALL_DIR"/*.py 2>/dev/null || true
    
    # Create .gitignore
    cat > .gitignore << 'EOF'
# Database and logs
*.db
*.log
key.key

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
venv/
env/
ENV/

# System files
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# Configuration
config.ini
.env
local_config.py

# Backup files
*.bak
*.backup
*~
EOF
    
    echo -e "${GREEN}[SUCCESS] Security measures applied${NC}"
}

# Final setup and instructions
final_setup() {
    echo -e "${GREEN}[SUCCESS] Installation completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                           INSTALLATION COMPLETE                             ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}📂 Installation Directory: ${INSTALL_DIR}${NC}"
    echo -e "${YELLOW}🚀 Start C2 System: ./start.sh${NC}"
    echo -e "${YELLOW}🔄 Update Tool: ./update.sh${NC}"
    echo -e "${YELLOW}🗑️  Uninstall: ./uninstall.sh${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "1. Change to installation directory: cd $INSTALL_DIR"
    echo "2. Start the C2 system: ./start.sh"
    echo "3. Add VPS nodes to your pool"
    echo "4. Deploy agents to VPS nodes"
    echo "5. Configure and launch attacks"
    echo ""
    echo -e "${GREEN}Quick Start:${NC}"
    echo -e "${WHITE}cd $INSTALL_DIR && ./start.sh${NC}"
    echo ""
    echo -e "${RED}⚠️  REMEMBER: Only use for authorized testing!${NC}"
}

# Main installation function
main() {
    print_banner
    
    echo -e "${YELLOW}This will install the Distributed Slow HTTP C2 tool.${NC}"
    echo -e "${YELLOW}The installation will create a directory at: $INSTALL_DIR${NC}"
    echo ""
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}[START] Beginning installation process...${NC}"
    
    check_user
    detect_os
    check_python
    check_git
    install_dependencies
    download_repo
    setup_python_env
    create_launchers
    setup_service
    setup_security
    final_setup
    
    echo -e "${GREEN}[COMPLETE] Installation finished successfully!${NC}"
}

# Handle interruption
trap 'echo -e "\n${RED}[INTERRUPTED] Installation cancelled by user${NC}"; exit 1' INT

# Run main installation
main "$@"
