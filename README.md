# 🎯 Distributed Slow HTTP C2

A powerful terminal-based command and control system for distributed slow HTTP testing and penetration testing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/yourusername/slowhttp-c2)

## ⚠️ **LEGAL DISCLAIMER**

This tool is for **EDUCATIONAL** and **AUTHORIZED PENETRATION TESTING** purposes only!

- ✅ Use only on systems you own
- ✅ Obtain written authorization before testing
- ✅ Follow responsible disclosure practices
- ❌ Unauthorized use is ILLEGAL and UNETHICAL

**By using this tool, you agree to use it responsibly and legally.**

## 🚀 **Quick Start**

### One-Line Installation
```bash
curl -sSL https://github.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash
```

### Manual Installation
```bash
git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
cd slowhttp-c2
chmod +x install.sh
./install.sh
```

### Start C2 System
```bash
cd slowhttp-c2
./start.sh
```

## ✨ **Features**

- 🖥️ **Terminal-based Interface** - Clean TUI for easy operation
- 🌐 **Multi-VPS Management** - Control unlimited VPS nodes via SSH
- ⚡ **Distributed Attacks** - Coordinate attacks from multiple sources
- 📊 **Real-time Monitoring** - Live statistics and status updates
- 🔒 **Secure Communication** - Encrypted password storage
- 🎯 **Multiple Attack Types** - Slowloris, Slow POST (R.U.D.Y)
- ⏱️ **Flexible Duration** - Timed or unlimited attacks
- 🧹 **Auto Cleanup** - Automatic cleanup after attacks
- 📋 **Session Management** - Track and manage attack sessions

## 🎮 **Attack Types**

### Slowloris (Slow Headers)
- Sends partial HTTP headers very slowly
- Effective against Apache, IIS servers
- Low bandwidth, high impact

### Slow POST (R.U.D.Y)
- Sends POST data extremely slowly  
- Targets form handlers and upload endpoints
- Effective against application layers

## 📋 **Requirements**

### Local System (C2 Server)
- Linux or macOS
- Python 3.6+
- SSH client
- Internet connection

### VPS Nodes
- Linux VPS with SSH access
- Root or sudo privileges
- Python 3 (auto-installed if missing)
- Unrestricted outbound connections

## 🛠️ **Installation**

### Automatic Installation
```bash
# Download and run installer
curl -sSL https://github.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

# Or with wget
wget -qO- https://github.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash
```

### Manual Installation
```bash
# Clone repository
git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
cd slowhttp-c2

# Run installer
chmod +x install.sh
./install.sh

# Or manual setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📖 **Usage**

### 1. Start the C2 System
```bash
./start.sh
```

### 2. Add VPS Nodes
```
Main Menu → [1] VPS Management → [1] Add VPS
```
Enter VPS details:
- IP Address: `1.2.3.4`
- Username: `root`
- Password: `your_password`
- Location: `US-East` (optional)

### 3. Deploy Agents
```
VPS Management → [3] Deploy Agents to All
```

### 4. Launch Attack
```
Main Menu → [2] Launch Attack
```
Configure:
- Target URL: `http://target-website.com`
- Attack Type: Slowloris or Slow POST
- VPS Selection: Choose nodes to use
- Parameters: Connections, delay, duration

### 5. Monitor Real-time
```
Main Menu → [3] Monitor Attacks
```

## 🎯 **Example Workflow**

```bash
# Install
curl -sSL https://github.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

# Start C2
cd ~/slowhttp-c2
./start.sh

# Add 3 VPS nodes through the interface
# Deploy agents to all VPS
# Launch Slowloris attack on target
# Monitor real-time statistics
# Stop attack when complete
```

## 📊 **Interface Screenshots**

### Main Menu
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                           Terminal Interface                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

MAIN MENU:
[1] VPS Management
[2] Launch Attack
[3] Monitor Active Attacks
[4] Attack History
[5] Exit
```

### Real-time Monitoring
```
VPS STATUS:
IP Address      Status       Processes  Last Update
1.2.3.4         ATTACKING    2          10:30:15
5.6.7.8         ATTACKING    2          10:30:15
9.10.11.12      ATTACKING    2          10:30:15

ATTACK STATISTICS:
Active VPS Nodes: 3/3
Total Attack Processes: 6
Estimated Connections: 6,000
```

## 🔧 **Configuration**

### VPS Requirements
```
Minimum: 1 CPU, 1GB RAM, 10GB storage
Recommended: 2+ CPU, 2GB+ RAM, 20GB+ storage
Network: Unrestricted outbound access
SSH: Root or sudo privileges required
```

### Attack Parameters
```
Connections per VPS: 100-5000 (recommended: 1000-2000)
Delay between packets: 1-60 seconds (recommended: 10-20)
Duration: 0 for unlimited, or specific seconds
```

## 🛡️ **Security Features**

- **Encrypted Storage** - VPS passwords encrypted with Fernet
- **Secure SSH** - Paramiko with proper key verification
- **Auto Cleanup** - Temporary files removed after attacks
- **Process Isolation** - Each attack runs independently
- **Session Management** - Complete audit trail

## 🐛 **Troubleshooting**

### Common Issues

**VPS Connection Failed**
```bash
# Check SSH connectivity
ssh root@your-vps-ip

# Verify credentials and firewall settings
```

**Python Dependencies Error**
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

**Attack Not Starting**
```bash
# Check target accessibility from VPS
ssh root@vps-ip "curl -I http://target.com"
```

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.

## 📚 **Documentation**

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Documentation](docs/USAGE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Legal Guidelines](docs/LEGAL.md)

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ **Legal Notice**

This tool is designed for:
- Educational purposes and learning
- Authorized penetration testing
- Security research in controlled environments
- Infrastructure resilience testing

**Important**: Always ensure you have explicit permission before testing any systems. Unauthorized access to computer systems is illegal in most jurisdictions.

## 🙏 **Acknowledgments**

- Built for cybersecurity education and authorized testing
- Inspired by legitimate security testing tools
- Thanks to the open-source security community

## 📞 **Support**

- Create an [Issue](https://github.com/yourusername/slowhttp-c2/issues) for bugs
- [Discussions](https://github.com/yourusername/slowhttp-c2/discussions) for questions
- Read [Documentation](docs/) for detailed guides

---


**Remember**: Use responsibly and legally. Always obtain proper authorization before testing.
