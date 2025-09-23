#!/bin/bash

# Distributed Slow HTTP C2 - GitHub Installer
# Usage: curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash
# Version: 1.0.0

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
INSTALLER_VERSION="1.0.0"
LOG_FILE="/tmp/slowhttp-c2-install.log"

# Global variables
OS=""
PKG_MANAGER=""
PKG_UPDATE=""
PKG_INSTALL=""
INSTALL_PYTHON=false
CLEANUP_ON_EXIT=false

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Error handling
error_exit() {
    local error_message="$1"
    echo -e "${RED}[ERROR] $error_message${NC}" >&2
    log "ERROR: $error_message"
    
    if [ "$CLEANUP_ON_EXIT" = true ]; then
        cleanup_on_failure
    fi
    
    echo -e "${YELLOW}Log file tersedia di: $LOG_FILE${NC}"
    exit 1
}

# Cleanup on failure
cleanup_on_failure() {
    echo -e "${YELLOW}[CLEANUP] Membersihkan file instalasi yang gagal...${NC}"
    
    if [ -d "$INSTALL_DIR" ] && [ "$INSTALL_DIR" != "$HOME" ]; then
        read -p "Hapus direktori instalasi yang gagal? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            echo -e "${GREEN}[INFO] Direktori instalasi yang gagal telah dihapus${NC}"
        fi
    fi
}

# Show help
show_help() {
    cat << EOF
Distributed Slow HTTP C2 Installer v$INSTALLER_VERSION

PENGGUNAAN:
    bash install.sh [OPTIONS]
    curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

OPTIONS:
    --help, -h          Tampilkan bantuan ini
    --version, -v       Tampilkan versi installer
    --force             Force install tanpa konfirmasi
    --dir PATH          Custom installation directory
    --no-service        Jangan setup systemd service
    --quiet, -q         Mode instalasi quiet (minimal output)

CONTOH:
    bash install.sh --force --dir /opt/slowhttp-c2
    bash install.sh --no-service --quiet

SUPPORT:
    Repository: https://github.com/YEHEZKIEL586/slowhttp-c2
    Issues: https://github.com/YEHEZKIEL586/slowhttp-c2/issues

PERINGATAN:
    Tool ini HANYA untuk pendidikan dan testing yang diotorisasi!
    Penggunaan ilegal dapat mengakibatkan tuntutan hukum.
EOF
}

# Banner
print_banner() {
    if [ "$QUIET_MODE" != true ]; then
        clear
        echo -e "${CYAN}${WHITE}${BOLD}"
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                    DISTRIBUTED SLOW HTTP C2 INSTALLER                       ║"
        echo "║                           GitHub Installation v$INSTALLER_VERSION                         ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "${RED}${BOLD}⚠️  PERINGATAN: HANYA UNTUK PENDIDIKAN DAN TESTING YANG DIOTORISASI! ⚠️${NC}"
        echo -e "${RED}   Penggunaan tanpa izin pada sistem yang bukan milik Anda adalah ILEGAL!${NC}"
        echo ""
    fi
}

# Check if running as root
check_user() {
    log "Checking user permissions"
    
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[PERINGATAN] Berjalan sebagai root. Sangat disarankan menggunakan user biasa.${NC}"
        echo -e "${YELLOW}Instalasi sebagai root dapat menimbulkan risiko keamanan.${NC}"
        
        if [ "$FORCE_INSTALL" != true ]; then
            read -p "Lanjutkan sebagai root? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Instalasi dibatalkan oleh user"
            fi
        fi
        log "User chose to continue as root"
    else
        log "Running as regular user: $(whoami)"
    fi
}

# Check system requirements
check_system_requirements() {
    log "Checking system requirements"
    
    # Check available disk space (minimum 500MB)
    local available_space
    available_space=$(df "$HOME" | awk 'NR==2 {print $4}')
    
    if [ "$available_space" -lt 512000 ]; then
        error_exit "Ruang disk tidak cukup. Diperlukan minimal 500MB, tersedia: $((available_space/1024))MB"
    fi
    
    # Check internet connectivity
    if ! ping -c 1 google.com &> /dev/null && ! ping -c 1 github.com &> /dev/null; then
        error_exit "Tidak ada koneksi internet. Diperlukan koneksi internet untuk instalasi."
    fi
    
    log "System requirements check passed"
    echo -e "${GREEN}[INFO] System requirements check passed${NC}"
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
            echo -e "${GREEN}[INFO] Terdeteksi sistem Debian/Ubuntu${NC}"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            PKG_MANAGER="yum"
            PKG_UPDATE="yum update -y"
            PKG_INSTALL="yum install -y"
            echo -e "${GREEN}[INFO] Terdeteksi sistem RedHat/CentOS${NC}"
        elif [ -f /etc/fedora-release ]; then
            OS="fedora"
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf update -y"
            PKG_INSTALL="dnf install -y"
            echo -e "${GREEN}[INFO] Terdeteksi sistem Fedora${NC}"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PKG_INSTALL="pacman -S --noconfirm"
            echo -e "${GREEN}[INFO] Terdeteksi sistem Arch Linux${NC}"
        elif [ -f /etc/alpine-release ]; then
            OS="alpine"
            PKG_MANAGER="apk"
            PKG_UPDATE="apk update"
            PKG_INSTALL="apk add"
            echo -e "${GREEN}[INFO] Terdeteksi sistem Alpine Linux${NC}"
        elif [ -f /etc/gentoo-release ]; then
            OS="gentoo"
            echo -e "${YELLOW}[PERINGATAN] Gentoo terdeteksi - instalasi manual dependency mungkin diperlukan${NC}"
        else
            OS="linux"
            echo -e "${YELLOW}[PERINGATAN] Linux generik terdeteksi, mungkin perlu instalasi manual dependency${NC}"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}[INFO] Terdeteksi sistem macOS${NC}"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        echo -e "${YELLOW}[PERINGATAN] Windows terdeteksi - gunakan WSL untuk hasil terbaik${NC}"
    else
        OS="unknown"
        echo -e "${YELLOW}[PERINGATAN] Sistem operasi tidak dikenali: $OSTYPE${NC}"
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
    echo -e "${BLUE}[CEK] Memeriksa instalasi Python...${NC}"
    
    if command_exists python3; then
        local python_version
        python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[INFO] Python ${python_version} ditemukan${NC}"
            log "Found Python version: $python_version"
            
            # Check if version is sufficient
            if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)" 2>/dev/null; then
                echo -e "${GREEN}[INFO] Versi Python sudah cukup${NC}"
                log "Python version is sufficient"
            else
                error_exit "Python ${PYTHON_MIN_VERSION}+ diperlukan, ditemukan ${python_version}"
            fi
        else
            error_exit "Python3 ditemukan tapi tidak dapat dijalankan"
        fi
    else
        echo -e "${YELLOW}[PERINGATAN] Python3 tidak ditemukan, akan diinstal...${NC}"
        INSTALL_PYTHON=true
        log "Python3 not found, will install"
    fi
    
    # Check pip
    if ! command_exists pip3 && ! python3 -m pip --version >/dev/null 2>&1; then
        echo -e "${YELLOW}[PERINGATAN] pip tidak ditemukan, akan diinstal...${NC}"
        log "pip not found, will install"
    fi
}

# Check required tools
check_required_tools() {
    log "Checking required tools"
    echo -e "${BLUE}[CEK] Memeriksa tools yang diperlukan...${NC}"
    
    local missing_tools=()
    
    # Check git
    if ! command_exists git; then
        missing_tools+=("git")
    else
        local git_version
        git_version=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log "Found git version: $git_version"
    fi
    
    # Check curl
    if ! command_exists curl; then
        missing_tools+=("curl")
    fi
    
    # Check wget (fallback)
    if ! command_exists wget; then
        missing_tools+=("wget")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}[INFO] Tools yang akan diinstal: ${missing_tools[*]}${NC}"
        log "Missing tools: ${missing_tools[*]}"
    else
        echo -e "${GREEN}[INFO] Semua tools yang diperlukan sudah terinstal${NC}"
        log "All required tools are available"
    fi
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies"
    echo -e "${BLUE}[INSTALL] Menginstal dependency sistem...${NC}"
    
    # Update package lists first
    if [ "$OS" != "macos" ] && [ "$OS" != "unknown" ] && [ -n "$PKG_UPDATE" ]; then
        echo -e "${BLUE}[UPDATE] Memperbarui package lists...${NC}"
        if ! eval "sudo $PKG_UPDATE"; then
            error_exit "Gagal memperbarui package lists"
        fi
    fi
    
    case $OS in
        "debian")
            local packages="python3 python3-pip python3-venv git curl wget build-essential libffi-dev libssl-dev openssh-client"
            if ! eval "sudo $PKG_INSTALL $packages"; then
                error_exit "Gagal menginstal dependency untuk Debian/Ubuntu"
            fi
            ;;
        "redhat")
            local packages="python3 python3-pip git curl wget gcc openssl-devel libffi-devel openssh-clients"
            if ! eval "sudo $PKG_INSTALL $packages"; then
                error_exit "Gagal menginstal dependency untuk RedHat/CentOS"
            fi
            ;;
        "fedora")
            local packages="python3 python3-pip git curl wget gcc openssl-devel libffi-devel openssh-clients"
            if ! eval "sudo $PKG_INSTALL $packages"; then
                error_exit "Gagal menginstal dependency untuk Fedora"
            fi
            ;;
        "arch")
            local packages="python python-pip git curl wget base-devel openssh"
            if ! eval "sudo $PKG_INSTALL $packages"; then
                error_exit "Gagal menginstal dependency untuk Arch Linux"
            fi
            ;;
        "alpine")
            local packages="python3 py3-pip git curl wget build-base libffi-dev openssl-dev openssh-client"
            if ! eval "sudo $PKG_INSTALL $packages"; then
                error_exit "Gagal menginstal dependency untuk Alpine Linux"
            fi
            ;;
        "macos")
            if ! command_exists brew; then
                echo -e "${BLUE}[INSTALL] Menginstal Homebrew...${NC}"
                if ! /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
                    error_exit "Gagal menginstal Homebrew"
                fi
                
                # Add brew to PATH for current session
                eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || eval "$(/usr/local/bin/brew shellenv)" 2>/dev/null
            fi
            
            if ! brew install python3 git curl wget; then
                error_exit "Gagal menginstal dependency untuk macOS"
            fi
            ;;
        *)
            echo -e "${YELLOW}[PERINGATAN] Silakan instal dependency berikut secara manual:${NC}"
            echo "  - python3 (>= 3.6)"
            echo "  - python3-pip"
            echo "  - python3-venv"
            echo "  - git"
            echo "  - curl"
            echo "  - wget"
            echo "  - build tools (gcc, make, etc.)"
            echo "  - ssh client"
            
            if [ "$FORCE_INSTALL" != true ]; then
                read -p "Lanjutkan instalasi? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    error_exit "Instalasi dibatalkan - dependency tidak lengkap"
                fi
            fi
            ;;
    esac
    
    log "System dependencies installation completed"
    echo -e "${GREEN}[BERHASIL] Dependency sistem berhasil diinstal${NC}"
}

# Download/clone repository
download_repo() {
    log "Starting repository download"
    echo -e "${BLUE}[DOWNLOAD] Mengunduh repository...${NC}"
    
    # Remove existing directory if it exists
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}[PERINGATAN] Direktori $INSTALL_DIR sudah ada${NC}"
        
        if [ "$FORCE_INSTALL" = true ]; then
            echo -e "${YELLOW}[INFO] Force mode aktif, menghapus direktori yang ada...${NC}"
            if ! rm -rf "$INSTALL_DIR"; then
                error_exit "Gagal menghapus direktori yang ada"
            fi
        else
            read -p "Hapus instalasi yang sudah ada? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if ! rm -rf "$INSTALL_DIR"; then
                    error_exit "Gagal menghapus direktori yang ada"
                fi
                echo -e "${GREEN}[INFO] Direktori yang ada telah dihapus${NC}"
            else
                error_exit "Instalasi dibatalkan - direktori sudah ada"
            fi
        fi
    fi
    
    # Enable cleanup on failure from this point
    CLEANUP_ON_EXIT=true
    
    # Clone repository with error handling
    echo -e "${BLUE}[INFO] Cloning dari: $REPO_URL${NC}"
    if ! git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"; then
        # Try with different methods
        echo -e "${YELLOW}[PERINGATAN] Git clone gagal, mencoba dengan wget...${NC}"
        
        if command_exists wget; then
            local zip_url="https://github.com/YEHEZKIEL586/slowhttp-c2/archive/refs/heads/main.zip"
            local temp_zip="/tmp/slowhttp-c2.zip"
            
            if wget -O "$temp_zip" "$zip_url" && command_exists unzip; then
                mkdir -p "$INSTALL_DIR"
                if unzip -q "$temp_zip" -d "/tmp/" && mv "/tmp/slowhttp-c2-main/"* "$INSTALL_DIR/"; then
                    rm -f "$temp_zip"
                    rm -rf "/tmp/slowhttp-c2-main"
                    echo -e "${GREEN}[BERHASIL] Repository berhasil diunduh dengan wget${NC}"
                else
                    error_exit "Gagal extract atau move files dari zip"
                fi
            else
                error_exit "Gagal download repository dengan wget"
            fi
        else
            error_exit "Gagal clone repository dan wget tidak tersedia"
        fi
    else
        echo -e "${GREEN}[BERHASIL] Repository berhasil di-clone${NC}"
    fi
    
    # Verify download
    if [ ! -f "$INSTALL_DIR/slowhttp_c2.py" ]; then
        error_exit "File utama slowhttp_c2.py tidak ditemukan setelah download"
    fi
    
    if [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
        error_exit "File requirements.txt tidak ditemukan setelah download"
    fi
    
    log "Repository download completed successfully"
    cd "$INSTALL_DIR" || error_exit "Gagal masuk ke direktori instalasi"
}

# Setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment"
    echo -e "${BLUE}[SETUP] Membuat Python virtual environment...${NC}"
    
    # Create virtual environment
    if ! python3 -m venv venv; then
        error_exit "Gagal membuat virtual environment"
    fi
    
    echo -e "${GREEN}[BERHASIL] Virtual environment berhasil dibuat${NC}"
    
    # Activate virtual environment
    if [ -f "venv/bin/activate" ]; then
        # shellcheck source=/dev/null
        source venv/bin/activate
    else
        error_exit "File aktivasi virtual environment tidak ditemukan"
    fi
    
    # Verify virtual environment
    if [ -z "$VIRTUAL_ENV" ]; then
        error_exit "Virtual environment tidak berhasil diaktifkan"
    fi
    
    echo -e "${GREEN}[INFO] Virtual environment diaktifkan: $VIRTUAL_ENV${NC}"
    
    # Upgrade pip
    echo -e "${BLUE}[SETUP] Mengupgrade pip...${NC}"
    if ! python -m pip install --upgrade pip; then
        echo -e "${YELLOW}[PERINGATAN] Gagal upgrade pip, lanjutkan dengan versi yang ada${NC}"
    fi
    
    # Install Python dependencies
    echo -e "${BLUE}[SETUP] Menginstal dependency Python...${NC}"
    if [ -f "requirements.txt" ]; then
        if ! pip install -r requirements.txt; then
            error_exit "Gagal menginstal dependency Python dari requirements.txt"
        fi
    else
        # Fallback manual installation
        echo -e "${YELLOW}[PERINGATAN] requirements.txt tidak ditemukan, menginstal dependency manual...${NC}"
        if ! pip install paramiko cryptography; then
            error_exit "Gagal menginstal dependency Python secara manual"
        fi
    fi
    
    # Verify installation
    if ! python -c "import paramiko, cryptography; print('Dependencies OK')"; then
        error_exit "Verifikasi dependency Python gagal"
    fi
    
    log "Python environment setup completed"
    echo -e "${GREEN}[BERHASIL] Python environment berhasil di-setup${NC}"
}

# Create launcher scripts
create_launchers() {
    log "Creating launcher scripts"
    echo -e "${BLUE}[SETUP] Membuat script launcher...${NC}"
    
    # Make start.sh executable if exists
    if [ -f "start.sh" ]; then
        chmod +x start.sh
    else
        echo -e "${YELLOW}[PERINGATAN] start.sh tidak ditemukan di repository${NC}"
    fi
    
    # Create update script
    cat > update.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🔄 Mengupdate Distributed Slow HTTP C2..."

# Check if git repository
if [ -d ".git" ]; then
    # Pull latest changes
    if git pull origin main; then
        echo "✅ Repository berhasil diupdate!"
    else
        echo "❌ Gagal update repository"
        exit 1
    fi
else
    echo "⚠️  Ini bukan git repository, download manual diperlukan"
    echo "   Kunjungi: https://github.com/YEHEZKIEL586/slowhttp-c2"
    exit 1
fi

# Update dependencies
if [ -d "venv" ]; then
    source venv/bin/activate
    pip install --upgrade -r requirements.txt
    echo "✅ Dependencies berhasil diupdate!"
else
    echo "❌ Virtual environment tidak ditemukan"
    exit 1
fi

echo "✅ Update selesai!"
EOF

    # Create uninstaller
    cat > uninstall.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🗑️  Menguninstal Distributed Slow HTTP C2..."
echo ""
echo "⚠️  Ini akan menghapus:"
echo "   • Semua file aplikasi"
echo "   • Virtual environment Python"
echo "   • Database dan konfigurasi"
echo "   • Log files"
echo ""

read -p "Apakah Anda yakin ingin menghapus instalasi sepenuhnya? (ketik 'HAPUS' untuk konfirmasi): " -r
echo

if [[ $REPLY == "HAPUS" ]]; then
    cd ..
    INSTALL_DIR=$(basename "$PWD")
    cd ..
    
    if rm -rf "$INSTALL_DIR"; then
        echo "✅ Uninstall selesai!"
        echo "📂 Direktori '$INSTALL_DIR' telah dihapus"
    else
        echo "❌ Gagal menghapus direktori"
        exit 1
    fi
else
    echo "❌ Uninstall dibatalkan"
fi
EOF

    # Make scripts executable
    chmod +x update.sh uninstall.sh
    
    log "Launcher scripts created successfully"
    echo -e "${GREEN}[BERHASIL] Script launcher berhasil dibuat${NC}"
}

# Setup systemd service (optional)
setup_service() {
    if [[ "$NO_SERVICE" == true ]]; then
        echo -e "${YELLOW}[INFO] Melewati setup service (--no-service digunakan)${NC}"
        return
    fi
    
    if [[ "$OS" == "debian" || "$OS" == "redhat" || "$OS" == "fedora" || "$OS" == "arch" ]]; then
        if [ "$FORCE_INSTALL" = true ]; then
            setup_service_answer="y"
        else
            read -p "Setup sebagai system service? (y/N): " -n 1 -r
            echo
            setup_service_answer="$REPLY"
        fi
        
        if [[ $setup_service_answer =~ ^[Yy]$ ]]; then
            log "Setting up systemd service"
            echo -e "${BLUE}[SETUP] Membuat systemd service...${NC}"
            
            local service_file="/etc/systemd/system/slowhttp-c2.service"
            
            if ! sudo tee "$service_file" > /dev/null << EOF; then
                error_exit "Gagal membuat systemd service file"
            fi
[Unit]
Description=Distributed Slow HTTP C2 Server
Documentation=https://github.com/YEHEZKIEL586/slowhttp-c2
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/bin:/bin
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/slowhttp_c2.py --daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowhttp-c2

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF
            
            if ! sudo systemctl daemon-reload; then
                echo -e "${YELLOW}[PERINGATAN] Gagal reload systemd daemon${NC}"
            fi
            
            log "Systemd service created successfully"
            echo -e "${GREEN}[BERHASIL] Systemd service berhasil dibuat${NC}"
            echo -e "${CYAN}[INFO] Untuk menggunakan service:${NC}"
            echo -e "${CYAN}       Enable: sudo systemctl enable slowhttp-c2${NC}"
            echo -e "${CYAN}       Start:  sudo systemctl start slowhttp-c2${NC}"
            echo -e "${CYAN}       Status: sudo systemctl status slowhttp-c2${NC}"
            echo -e "${CYAN}       Logs:   sudo journalctl -u slowhttp-c2 -f${NC}"
        fi
    else
        echo -e "${YELLOW}[INFO] Systemd service tidak tersedia untuk OS ini${NC}"
    fi
}

# Security setup
setup_security() {
    log "Setting up security measures"
    echo -e "${BLUE}[SECURITY] Menerapkan security measures...${NC}"
    
    # Set proper permissions
    if ! chmod 700 "$INSTALL_DIR"; then
        echo -e "${YELLOW}[PERINGATAN] Gagal set permission direktori${NC}"
    fi
    
    if ! chmod 600 "$INSTALL_DIR"/*.py 2>/dev/null; then
        echo -e "${YELLOW}[PERINGATAN] Gagal set permission file Python${NC}"
    fi
    
    # Create comprehensive .gitignore if not exists
    if [ ! -f ".gitignore" ]; then
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
env.bak/
venv.bak/

# System files
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# IDE
.vscode/
.idea/
*.sublime-project
*.sublime-workspace

# Configuration files with sensitive data
config.ini
.env
local_config.py
production_config.py

# Backup files
*.bak
*.backup

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
    fi
    
    # Create logs directory
    if ! mkdir -p logs; then
        echo -e "${YELLOW}[PERINGATAN] Gagal membuat direktori logs${NC}"
    fi
    
    log "Security measures applied successfully"
    echo -e "${GREEN}[BERHASIL] Security measures berhasil diterapkan${NC}"
}

# Verify installation
verify_installation() {
    log "Verifying installation"
    echo -e "${BLUE}[VERIFY] Memverifikasi instalasi...${NC}"
    
    # Check if main files exist
    local required_files=("slowhttp_c2.py" "requirements.txt" "start.sh" "update.sh" "uninstall.sh")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            error_exit "File penting tidak ditemukan: $file"
        fi
    done
    
    # Check virtual environment
    if [ ! -d "venv" ]; then
        error_exit "Virtual environment tidak ditemukan"
    fi
    
    # Test Python imports
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi
    
    echo -e "${BLUE}[TEST] Testing Python dependencies...${NC}"
    if ! python -c "import paramiko, cryptography, socket, threading, time, json, logging, argparse; print('✅ All dependencies OK')"; then
        error_exit "Python dependencies verification failed"
    fi
    
    # Test main script syntax
    if ! python -m py_compile slowhttp_c2.py; then
        error_exit "Main script syntax check failed"
    fi
    
    # Check permissions
    if [ ! -x "start.sh" ] || [ ! -x "update.sh" ] || [ ! -x "uninstall.sh" ]; then
        echo -e "${YELLOW}[FIX] Memperbaiki permissions script...${NC}"
        chmod +x start.sh update.sh uninstall.sh
    fi
    
    log "Installation verification completed successfully"
    echo -e "${GREEN}[BERHASIL] Verifikasi instalasi berhasil!${NC}"
}

# Final setup and configuration
final_setup() {
    log "Performing final setup"
    echo -e "${BLUE}[FINAL] Menyelesaikan setup...${NC}"
    
    # Create desktop shortcut (if desktop environment available)
    if [ -n "$DISPLAY" ] && [ -d "$HOME/Desktop" ]; then
        local shortcut_file="$HOME/Desktop/Slowhttp-C2.desktop"
        cat > "$shortcut_file" << EOF
[Desktop Entry]
Version=1.0
Name=Slowhttp C2
Comment=Distributed Slow HTTP Command & Control
Exec=$INSTALL_DIR/start.sh
Icon=network-wired
Terminal=true
Type=Application
Categories=Development;Security;Network;
Path=$INSTALL_DIR
EOF
        chmod +x "$shortcut_file"
        log "Desktop shortcut created"
    fi
    
    # Create configuration template
    if [ ! -f "config.ini.example" ]; then
        cat > config.ini.example << 'EOF'
[server]
host = 0.0.0.0
port = 8080
ssl_enabled = false
ssl_cert = 
ssl_key = 
max_connections = 1000
timeout = 30

[database]
type = sqlite
file = slowhttp_c2.db
host = localhost
port = 5432
name = slowhttp_c2
user = 
password = 

[logging]
level = INFO
file = logs/slowhttp_c2.log
max_size = 10MB
backup_count = 5

[security]
auth_required = true
api_key = 
rate_limiting = true
max_requests_per_minute = 60
allowed_ips = 

[features]
auto_cleanup = true
cleanup_interval = 3600
max_agents = 100
heartbeat_interval = 30
EOF
    fi
    
    # Create example target list
    if [ ! -f "targets.txt.example" ]; then
        cat > targets.txt.example << 'EOF'
# Example target configuration
# Format: host:port or host (default port 80)
# Lines starting with # are comments

# Examples:
# example.com
# test-site.com:8080
# 192.168.1.100
# subdomain.example.org:443

# Add your targets below (remove # to uncomment):
# target1.com
# target2.com:8080
EOF
    fi
    
    log "Final setup completed"
    echo -e "${GREEN}[BERHASIL] Final setup selesai${NC}"
}

# Show completion message
show_completion() {
    local install_time=$(($(date +%s) - START_TIME))
    
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                            INSTALASI BERHASIL!                              ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  📍 Lokasi Instalasi: ${WHITE}$(printf "%-46s" "$INSTALL_DIR")${GREEN} ║"
    echo -e "║  ⏱️  Waktu Instalasi: ${WHITE}$(printf "%-46s" "${install_time}s")${GREEN} ║"
    echo -e "║  🐍 Python Environment: ${WHITE}$(printf "%-42s" "$VIRTUAL_ENV")${GREEN} ║"
    echo "║                                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                            CARA PENGGUNAAN                                   ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  🚀 ${WHITE}Menjalankan:${GREEN}                                                        ║"
    echo -e "║     ${CYAN}cd $INSTALL_DIR${GREEN}"
    printf "║     %-70s║\n" ""
    echo -e "║     ${CYAN}./start.sh${GREEN}                                                          ║"
    echo -e "║     ${CYAN}# atau manual:${GREEN}                                                      ║"
    echo -e "║     ${CYAN}source venv/bin/activate && python slowhttp_c2.py${GREEN}                  ║"
    echo "║                                                                              ║"
    echo -e "║  🔧 ${WHITE}Konfigurasi:${GREEN}                                                       ║"
    echo -e "║     ${CYAN}cp config.ini.example config.ini${GREEN}                                   ║"
    echo -e "║     ${CYAN}nano config.ini${GREEN}                                                     ║"
    echo "║                                                                              ║"
    echo -e "║  🎯 ${WHITE}Target Setup:${GREEN}                                                      ║"
    echo -e "║     ${CYAN}cp targets.txt.example targets.txt${GREEN}                                 ║"
    echo -e "║     ${CYAN}nano targets.txt${GREEN}                                                    ║"
    echo "║                                                                              ║"
    echo -e "║  🔄 ${WHITE}Update:${GREEN}                                                            ║"
    echo -e "║     ${CYAN}./update.sh${GREEN}                                                         ║"
    echo "║                                                                              ║"
    echo -e "║  🗑️  ${WHITE}Uninstall:${GREEN}                                                        ║"
    echo -e "║     ${CYAN}./uninstall.sh${GREEN}                                                      ║"
    echo "║                                                                              ║"
    if [[ "$OS" == "debian" || "$OS" == "redhat" || "$OS" == "fedora" || "$OS" == "arch" ]] && [[ "$NO_SERVICE" != true ]]; then
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                            SYSTEMD SERVICE                                   ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  🔧 ${WHITE}Enable Service:${GREEN}                                                    ║"
    echo -e "║     ${CYAN}sudo systemctl enable slowhttp-c2${GREEN}                                  ║"
    echo -e "║     ${CYAN}sudo systemctl start slowhttp-c2${GREEN}                                   ║"
    echo "║                                                                              ║"
    echo -e "║  📊 ${WHITE}Monitor Service:${GREEN}                                                   ║"
    echo -e "║     ${CYAN}sudo systemctl status slowhttp-c2${GREEN}                                  ║"
    echo -e "║     ${CYAN}sudo journalctl -u slowhttp-c2 -f${GREEN}                                  ║"
    echo "║                                                                              ║"
    fi
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                            DOKUMENTASI                                       ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                              ║"
    echo -e "║  📚 ${WHITE}Repository:${GREEN} ${CYAN}https://github.com/YEHEZKIEL586/slowhttp-c2${GREEN}      ║"
    echo -e "║  🐛 ${WHITE}Issues:${GREEN} ${CYAN}https://github.com/YEHEZKIEL586/slowhttp-c2/issues${GREEN}  ║"
    echo -e "║  📖 ${WHITE}Log File:${GREEN} ${CYAN}$(printf "%-55s" "$LOG_FILE")${GREEN}║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${RED}${BOLD}⚠️  PERINGATAN PENTING:${NC}"
    echo -e "${RED}   • Tool ini HANYA untuk tujuan pendidikan dan testing yang diotorisasi${NC}"
    echo -e "${RED}   • Penggunaan tanpa izin pada sistem yang bukan milik Anda adalah ILEGAL${NC}"
    echo -e "${RED}   • Pengguna bertanggung jawab penuh atas penggunaan tool ini${NC}"
    echo -e "${RED}   • Pastikan untuk mengikuti hukum dan regulasi yang berlaku${NC}"
    echo ""
    
    log "Installation completed successfully in ${install_time}s"
}

# Main function
main() {
    local START_TIME
    START_TIME=$(date +%s)
    
    # Parse arguments
    local FORCE_INSTALL=false
    local QUIET_MODE=false
    local NO_SERVICE=false
    local CUSTOM_DIR=""
    
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
    log "Force Install: $FORCE_INSTALL"
    log "Quiet Mode: $QUIET_MODE"
    log "No Service: $NO_SERVICE"
    
    # Show banner
    print_banner
    
    # System checks
    check_user
    check_system_requirements
    detect_os
    
    # Software checks
    check_python
    check_required_tools
    
    # Installation steps
    echo -e "${BLUE}[INFO] Memulai proses instalasi...${NC}"
    install_dependencies
    download_repo
    setup_python_env
    create_launchers
    setup_security
    setup_service
    final_setup
    
    # Verification
    verify_installation
    
    # Completion
    show_completion
    
    log "=== Installation Completed Successfully ==="
}

# Error handling for script
set -e
trap 'error_exit "Unexpected error occurred at line $LINENO"' ERR

# Run main function with all arguments
main "$@"
