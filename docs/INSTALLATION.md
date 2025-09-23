# Installation Guide

Comprehensive installation guide for the Distributed Slow HTTP C2 system.

## 📋 **Prerequisites**

### **System Requirements**
- **Operating System**: Linux (Ubuntu/Debian/CentOS/Arch) or macOS
- **Python**: Version 3.6 or higher
- **Memory**: Minimum 512MB RAM, 1GB+ recommended
- **Storage**: 100MB free space
- **Network**: Internet connection for downloading dependencies

### **VPS Requirements**
- **SSH Access**: Username and password or SSH key
- **Operating System**: Any Linux distribution
- **Privileges**: Root or sudo access
- **Python**: Will be installed automatically if missing
- **Network**: Unrestricted outbound connections

## 🚀 **Quick Installation**

### **Method 1: One-Line Install (Recommended)**
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh | bash
```

### **Method 2: wget Install**
```bash
wget -qO- https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh | bash
```

### **Method 3: Manual Download**
```bash
# Download installer
curl -O https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh

# Make executable and run
chmod +x install.sh
./install.sh
```

## 📦 **Manual Installation**

### **Step 1: System Preparation**

#### **Ubuntu/Debian:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget
sudo apt install -y build-essential libffi-dev libssl-dev
```

#### **CentOS/RHEL:**
```bash
sudo yum update -y
sudo yum install -y python3 python3-pip git curl wget
sudo yum install -y gcc openssl-devel libffi-devel
```

#### **Arch Linux:**
```bash
sudo pacman -Sy
sudo pacman -S python python-pip git curl wget base-devel
```

#### **macOS:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 git curl wget
```

### **Step 2: Download Source Code**
```bash
# Clone repository
git clone https://github.com/yourusername/slowhttp-c2.git
cd slowhttp-c2
```

### **Step 3: Python Environment Setup**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows (if supported)

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### **Step 4: Verify Installation**
```bash
# Test main script
python3 -c "import slowhttp_c2; print('✅ Installation successful')"

# Test dependencies
python3 -c "import paramiko, cryptography; print('✅ Dependencies loaded')"
```

## 🔧 **Advanced Installation Options**

### **Custom Installation Directory**
```bash
# Set custom directory
export INSTALL_DIR="/opt/slowhttp-c2"

# Run installer with custom path
INSTALL_DIR="$INSTALL_DIR" ./install.sh
```

### **Offline Installation**
```bash
# Download all files first
git clone https://github.com/yourusername/slowhttp-c2.git
cd slowhttp-c2

# Install Python packages offline (if you have them cached)
pip install --no-index --find-links /path/to/packages -r requirements.txt
```

### **Development Installation**
```bash
# Clone repository
git clone https://github.com/yourusername/slowhttp-c2.git
cd slowhttp-c2

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate

# Install with development dependencies
pip install -r requirements.txt
pip install pytest black flake8 bandit

# Install in development mode
pip install -e .
```

## 🐳 **Docker Installation**

### **Using Docker**
```bash
# Build Docker image
docker build -t slowhttp-c2 .

# Run container
docker run -it --rm slowhttp-c2
```

### **Docker Compose**
```yaml
# docker-compose.yml
version: '3.8'
services:
  slowhttp-c2:
    build: .
    volumes:
      - ./data:/app/data
    environment:
      - PYTHONUNBUFFERED=1
```

## 🏢 **Enterprise Installation**

### **Multi-User Setup**
```bash
# Install system-wide
sudo mkdir -p /opt/slowhttp-c2
sudo chown $USER:$USER /opt/slowhttp-c2
git clone https://github.com/yourusername/slowhttp-c2.git /opt/slowhttp-c2

# Create shared virtual environment
sudo python3 -m venv /opt/slowhttp-c2/venv
sudo /opt/slowhttp-c2/venv/bin/pip install -r /opt/slowhttp-c2/requirements.txt

# Create launcher script
sudo tee /usr/local/bin/slowhttp-c2 > /dev/null << 'EOF'
#!/bin/bash
cd /opt/slowhttp-c2
source venv/bin/activate
python3 slowhttp_c2.py "$@"
EOF

sudo chmod +x /usr/local/bin/slowhttp-c2
```

### **Systemd Service Setup**
```bash
# Run the service setup script
./scripts/setup_service.sh

# Or manually create service
sudo tee /etc/systemd/system/slowhttp-c2.service > /dev/null << 'EOF'
[Unit]
Description=Distributed Slow HTTP C2 Server
After=network.target

[Service]
Type=simple
User=slowhttp-c2
Group=slowhttp-c2
WorkingDirectory=/opt/slowhttp-c2
ExecStart=/opt/slowhttp-c2/venv/bin/python /opt/slowhttp-c2/slowhttp_c2.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable slowhttp-c2
sudo systemctl start slowhttp-c2
```

## 🔍 **Verification & Testing**

### **Post-Installation Checks**
```bash
# Check installation
./start.sh --version

# Test VPS connectivity (example)
ssh root@your-vps-ip "echo 'Connection test successful'"

# Verify Python dependencies
python3 -c "
import sys
print(f'Python version: {sys.version}')

try:
    import paramiko
    print('✅ Paramiko available')
except ImportError:
    print('❌ Paramiko missing')

try:
    import cryptography
    print('✅ Cryptography available')
except ImportError:
    print('❌ Cryptography missing')
"
```

### **Integration Test**
```bash
# Run basic integration test
cd slowhttp-c2
python3 -c "
from slowhttp_c2 import SlowHTTPTUI
import sqlite3

# Test database creation
tui = SlowHTTPTUI()
print('✅ Database initialized')

# Test security manager
encrypted = tui.security_manager.encrypt_password('test')
decrypted = tui.security_manager.decrypt_password(encrypted)
assert decrypted == 'test'
print('✅ Encryption working')

print('🎉 Installation verified successfully!')
"
```

## 🐛 **Troubleshooting Installation**

### **Common Issues**

#### **Permission Denied Errors**
```bash
# Fix permissions
chmod +x install.sh start.sh
sudo chown -R $USER:$USER ~/slowhttp-c2
```

#### **Python Version Issues**
```bash
# Check Python version
python3 --version

# Install specific Python version (Ubuntu)
sudo apt install python3.9 python3.9-venv python3.9-pip
```

#### **Dependency Installation Fails**
```bash
# Update pip
pip install --upgrade pip

# Install dependencies individually
pip install paramiko
pip install cryptography

# Clear pip cache
pip cache purge
```

#### **Git Clone Fails**
```bash
# Try with different protocols
git clone https://github.com/yourusername/slowhttp-c2.git

# Or download as ZIP
curl -L https://github.com/yourusername/slowhttp-c2/archive/main.zip -o slowhttp-c2.zip
unzip slowhttp-c2.zip
```

#### **Virtual Environment Issues**
```bash
# Remove and recreate venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **System-Specific Fixes**

#### **macOS Issues**
```bash
# Install Xcode command line tools
xcode-select --install

# Fix OpenSSL issues
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
```

#### **CentOS 7 Issues**
```bash
# Enable EPEL repository
sudo yum install epel-release

# Install Python 3.6+
sudo yum install python36 python36-pip
```

## 📊 **Installation Verification Checklist**

- [ ] Python 3.6+ installed and accessible
- [ ] Virtual environment created successfully
- [ ] All dependencies installed without errors
- [ ] Main script runs without import errors
- [ ] SSH connectivity to test VPS confirmed
- [ ] File permissions set correctly
- [ ] Launcher scripts are executable
- [ ] Database creation works
- [ ] Encryption/decryption functions properly

## 🔄 **Updates and Maintenance**

### **Updating the Tool**
```bash
# Using update script
./update.sh

# Manual update
git pull origin main
source venv/bin/activate
pip install --upgrade -r requirements.txt
```

### **Backup Configuration**
```bash
# Backup important files
cp c2_database.db c2_database.db.backup
cp key.key key.key.backup
```

### **Clean Installation**
```bash
# Complete removal and reinstall
./uninstall.sh
curl -sSL https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh | bash
```

## 📞 **Support**

If you encounter issues during installation:

1. **Check the logs**: Look for error messages in the terminal
2. **Review requirements**: Ensure all prerequisites are met
3. **Try manual installation**: Use the step-by-step process
4. **Check GitHub issues**: Look for similar problems and solutions
5. **Create an issue**: Report the problem with full error details

## 🔗 **Useful Links**

- [Main Repository](https://github.com/yourusername/slowhttp-c2)
- [Usage Documentation](USAGE.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [Legal Guidelines](LEGAL.md)