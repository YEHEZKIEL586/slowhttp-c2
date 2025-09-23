#!/bin/bash

# Distributed Slow HTTP C2 - GitHub Installer
# Usage: curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

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
    echo -e "${RED}⚠️  PERINGATAN: HANYA UNTUK PENDIDIKAN DAN TESTING YANG DIOTORISASI! ⚠️${NC}"
    echo -e "${RED}   Penggunaan tanpa izin pada sistem yang bukan milik Anda adalah ILEGAL!${NC}"
    echo ""
}

# Check if running as root
check_user() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[PERINGATAN] Berjalan sebagai root. Pertimbangkan menggunakan user biasa.${NC}"
        read -p "Lanjutkan saja? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}Instalasi dibatalkan${NC}"
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
            echo -e "${GREEN}[INFO] Terdeteksi sistem Debian/Ubuntu${NC}"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            echo -e "${GREEN}[INFO] Terdeteksi sistem RedHat/CentOS${NC}"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PKG_INSTALL="pacman -S --noconfirm"
            echo -e "${GREEN}[INFO] Terdeteksi sistem Arch Linux${NC}"
        else
            OS="linux"
            echo -e "${YELLOW}[PERINGATAN] Linux generik terdeteksi, mungkin perlu instalasi manual dependency${NC}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}[INFO] Terdeteksi sistem macOS${NC}"
    else
        OS="unknown"
        echo -e "${YELLOW}[PERINGATAN] Sistem operasi tidak dikenali${NC}"
    fi
}

# Check Python version
check_python() {
    echo -e "${BLUE}[CEK] Memeriksa instalasi Python...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        echo -e "${GREEN}[INFO] Python ${PYTHON_VERSION} ditemukan${NC}"
        
        # Check if version is sufficient
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)"; then
            echo -e "${GREEN}[INFO] Versi Python sudah cukup${NC}"
        else
            echo -e "${RED}[ERROR] Python ${PYTHON_MIN_VERSION}+ diperlukan, ditemukan ${PYTHON_VERSION}${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}[PERINGATAN] Python3 tidak ditemukan, akan diinstal...${NC}"
        INSTALL_PYTHON=true
    fi
}

# Install system dependencies
install_dependencies() {
    echo -e "${BLUE}[INSTALL] Menginstal dependency sistem...${NC}"
    
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
                echo -e "${BLUE}[INSTALL] Menginstal Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install python3 git curl wget
            ;;
        *)
            echo -e "${YELLOW}[PERINGATAN] Silakan instal python3, pip, git, curl secara manual${NC}"
            ;;
    esac
}

# Check if git is available
check_git() {
    if ! command -v git &> /dev/null; then
        echo -e "${RED}[ERROR] Git diperlukan tapi tidak terinstal${NC}"
        echo -e "${YELLOW}[INFO] Menginstal git...${NC}"
        
        case $OS in
            "debian") sudo apt install -y git ;;
            "redhat") sudo yum install -y git ;;
            "arch") sudo pacman -S --noconfirm git ;;
            "macos") brew install git ;;
            *) echo -e "${RED}[ERROR] Silakan instal git secara manual${NC}"; exit 1 ;;
        esac
    fi
}

# Download/clone repository
download_repo() {
    echo -e "${BLUE}[DOWNLOAD] Cloning repository...${NC}"
    
    # Remove existing directory if it exists
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}[PERINGATAN] Direktori $INSTALL_DIR sudah ada${NC}"
        read -p "Hapus instalasi yang sudah ada? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            echo -e "${GREEN}[INFO] Direktori yang ada telah dihapus${NC}"
        else
            echo -e "${RED}[ERROR] Instalasi dibatalkan${NC}"
            exit 1
        fi
    fi
    
    # Clone repository
    if git clone "$REPO_URL" "$INSTALL_DIR"; then
        echo -e "${GREEN}[BERHASIL] Repository berhasil di-clone${NC}"
    else
        echo -e "${RED}[ERROR] Gagal clone repository${NC}"
        echo -e "${YELLOW}[INFO] Anda juga bisa download manual dari: $REPO_URL${NC}"
        exit 1
    fi
    
    cd "$INSTALL_DIR"
}

# Setup Python virtual environment
setup_python_env() {
    echo -e "${BLUE}[SETUP] Membuat Python virtual environment...${NC}"
    
    # Create virtual environment
    if python3 -m venv venv; then
        echo -e "${GREEN}[BERHASIL] Virtual environment berhasil dibuat${NC}"
    else
        echo -e "${RED}[ERROR] Gagal membuat virtual environment${NC}"
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    echo -e "${BLUE}[SETUP] Mengupgrade pip...${NC}"
    pip install --upgrade pip
    
    # Install Python dependencies
    echo -e "${BLUE}[SETUP] Menginstal dependency Python...${NC}"
    if pip install -r requirements.txt; then
        echo -e "${GREEN}[BERHASIL] Dependency Python berhasil diinstal${NC}"
    else
        echo -e "${RED}[ERROR] Gagal menginstal dependency Python${NC}"
        echo -e "${YELLOW}[INFO] Anda mungkin perlu menginstalnya secara manual:${NC}"
        echo -e "${YELLOW}pip install paramiko cryptography${NC}"
        exit 1
    fi
}

# Create launcher scripts
create_launchers() {
    echo -e "${BLUE}[SETUP] Membuat script launcher...${NC}"
    
    # Make start.sh executable
    chmod +x start.sh
    
    # Create update script
    cat > update.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🔄 Mengupdate Distributed Slow HTTP C2..."

# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip install --upgrade -r requirements.txt

echo "✅ Update selesai!"
EOF

    # Create uninstaller
    cat > uninstall.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🗑️  Menguninstal Distributed Slow HTTP C2..."

read -p "Apakah Anda yakin ingin menghapus instalasi sepenuhnya? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd ..
    rm -rf "$(basename "$PWD")"
    echo "✅ Uninstall selesai!"
else
    echo "❌ Uninstall dibatalkan"
fi
EOF

    # Make scripts executable
    chmod +x update.sh uninstall.sh
    
    echo -e "${GREEN}[BERHASIL] Script launcher berhasil dibuat${NC}"
}

# Setup systemd service (optional)
setup_service() {
    if [[ "$OS" == "debian" || "$OS" == "redhat" || "$OS" == "arch" ]]; then
        read -p "Setup sebagai system service? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[SETUP] Membuat systemd service...${NC}"
            
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
            
            echo -e "${GREEN}[BERHASIL] Systemd service berhasil dibuat${NC}"
            echo -e "${CYAN}[INFO] Enable service: sudo systemctl enable slowhttp-c2${NC}"
            echo -e "${CYAN}[INFO] Start service: sudo systemctl start slowhttp-c2${NC}"
            echo -e "${CYAN}[INFO] Lihat logs: sudo journalctl -u slowhttp-c2 -f${NC}"
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
    
    echo -e "${GREEN}[BERHASIL] Security measures berhasil diterapkan${NC}"
}

# Final setup and instructions
final_setup() {
    echo -e "${GREEN}[BERHASIL] Instalasi berhasil diselesaikan!${NC}"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                           INSTALASI SELESAI                                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}📂 Direktori Instalasi: ${INSTALL_DIR}${NC}"
    echo -e "${YELLOW}🚀 Jalankan C2 System: ./start.sh${NC}"
    echo -e "${YELLOW}🔄 Update Tool: ./update.sh${NC}"
    echo -e "${YELLOW}🗑️  Uninstall: ./uninstall.sh${NC}"
    echo ""
    echo -e "${CYAN}Langkah Selanjutnya:${NC}"
    echo "1. Pindah ke direktori instalasi: cd $INSTALL_DIR"
    echo "2. Jalankan sistem C2: ./start.sh"
    echo "3. Tambahkan VPS nodes ke pool Anda"
    echo "4. Deploy agents ke VPS nodes"
    echo "5. Konfigurasi dan luncurkan serangan"
    echo ""
    echo -e "${GREEN}Quick Start:${NC}"
    echo -e "${WHITE}cd $INSTALL_DIR && ./start.sh${NC}"
    echo ""
    echo -e "${RED}⚠️  INGAT: Hanya gunakan untuk testing yang diotorisasi!${NC}"
}

# Main installation function
main() {
    print_banner
    
    echo -e "${YELLOW}Ini akan menginstal tool Distributed Slow HTTP C2.${NC}"
    echo -e "${YELLOW}Instalasi akan membuat direktori di: $INSTALL_DIR${NC}"
    echo ""
    read -p "Lanjutkan dengan instalasi? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Instalasi dibatalkan${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}[MULAI] Memulai proses instalasi...${NC}"
    
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
    
    echo -e "${GREEN}[SELESAI] Instalasi berhasil diselesaikan!${NC}"
}

# Handle interruption
trap 'echo -e "\n${RED}[TERINTERUPSI] Instalasi dibatalkan oleh user${NC}"; exit 1' INT

# Run main installation
main "$@"
