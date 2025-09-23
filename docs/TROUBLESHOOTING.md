# Troubleshooting Guide

Common issues and solutions for the Distributed Slow HTTP C2 system.

## 🚨 **Quick Diagnostics**

### **System Health Check**
```bash
cd ~/slowhttp-c2

# Check Python environment
source venv/bin/activate
python3 --version
python3 -c "import paramiko, cryptography; print('✅ Dependencies OK')"

# Check main script
python3 -c "import slowhttp_c2; print('✅ Main script OK')"

# Check database
ls -la c2_database.db 2>/dev/null && echo "✅ Database exists" || echo "❌ Database missing"

# Check permissions
ls -la slowhttp_c2.py start.sh install.sh
```

### **VPS Connectivity Test**
```bash
# Test SSH connectivity manually
ssh -o ConnectTimeout=10 root@your-vps-ip "echo 'SSH OK'"

# Test with specific port
ssh -p 22 -o ConnectTimeout=10 root@your-vps-ip "echo 'SSH OK'"

# Check if Python is available on VPS
ssh root@your-vps-ip "python3 --version"
```

## ❌ **Installation Issues**

### **Problem: Permission Denied During Installation**
```bash
# Error message:
bash: ./install.sh: Permission denied
```

**Solution:**
```bash
# Make installer executable
chmod +x install.sh

# Or run with bash directly
bash install.sh
```

### **Problem: Python Version Too Old**
```bash
# Error message:
[ERROR] Python 3.6+ required, found 3.5
```

**Solutions:**

**Ubuntu/Debian:**
```bash
# Install newer Python
sudo apt update
sudo apt install python3.8 python3.8-venv python3.8-pip

# Use specific version
python3.8 -m venv venv
```

**CentOS/RHEL:**
```bash
# Enable EPEL and install Python 3.6+
sudo yum install epel-release
sudo yum install python36 python36-pip

# Or compile from source
sudo yum groupinstall "Development Tools"
wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz
tar xzf Python-3.9.0.tgz
cd Python-3.9.0
./configure --enable-optimizations
make altinstall
```

### **Problem: Virtual Environment Creation Fails**
```bash
# Error message:
The virtual environment was not created successfully
```

**Solutions:**
```bash
# Install venv module
sudo apt install python3-venv  # Ubuntu/Debian
sudo yum install python3-venv  # CentOS/RHEL

# Or use virtualenv
pip3 install virtualenv
virtualenv venv

# Manual cleanup and retry
rm -rf venv
python3 -m venv venv --clear
```

### **Problem: Dependency Installation Fails**
```bash
# Error messages:
Failed building wheel for cryptography
error: Microsoft Visual C++ 14.0 is required
```

**Solutions:**

**Linux:**
```bash
# Install build dependencies
sudo apt install build-essential libffi-dev libssl-dev  # Ubuntu/Debian
sudo yum install gcc openssl-devel libffi-devel        # CentOS/RHEL

# Update pip and try again
pip install --upgrade pip
pip install --upgrade setuptools wheel
pip install -r requirements.txt
```

**macOS:**
```bash
# Install Xcode command line tools
xcode-select --install

# Set environment variables for OpenSSL
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip install cryptography
```

## 🔌 **VPS Connection Issues**

### **Problem: SSH Connection Refused**
```bash
# Error message:
[ERROR] Connection test failed: Connection refused
```

**Diagnostics:**
```bash
# Check if VPS is reachable
ping your-vps-ip

# Check if SSH port is open
nmap -p 22 your-vps-ip
# or
telnet your-vps-ip 22
```

**Solutions:**
1. **Verify VPS is running**
2. **Check SSH service status:**
   ```bash
   ssh root@your-vps-ip
   systemctl status ssh      # Ubuntu/Debian
   systemctl status sshd     # CentOS/RHEL
   ```
3. **Check firewall:**
   ```bash
   # Ubuntu/Debian
   sudo ufw status
   sudo ufw allow 22
   
   # CentOS/RHEL
   sudo firewall-cmd --list-all
   sudo firewall-cmd --add-service=ssh --permanent
   sudo firewall-cmd --reload
   ```

### **Problem: SSH Authentication Failed**
```bash
# Error message:
[ERROR] Connection test failed: Authentication failed
```

**Solutions:**
```bash
# Test credentials manually
ssh root@your-vps-ip

# Check if password authentication is enabled
ssh root@your-vps-ip "grep PasswordAuthentication /etc/ssh/sshd_config"

# Enable password authentication if needed
ssh root@your-vps-ip "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config"
ssh root@your-vps-ip "systemctl restart ssh"
```

### **Problem: SSH Timeout**
```bash
# Error message:
[ERROR] Connection test failed: timed out
```

**Solutions:**
```bash
# Increase SSH timeout
ssh -o ConnectTimeout=30 root@your-vps-ip

# Check network connectivity
traceroute your-vps-ip
mtr your-vps-ip

# Try different SSH port
ssh -p 2222 root@your-vps-ip  # if SSH runs on different port
```

### **Problem: Permission Denied (publickey)**
```bash
# Error message:
Permission denied (publickey)
```

**Solutions:**
```bash
# Use password authentication
ssh -o PreferredAuthentications=password root@your-vps-ip

# Or set up SSH keys properly
ssh-keygen -t rsa -b 4096
ssh-copy-id root@your-vps-ip

# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
chmod 700 ~/.ssh
```

## 🚀 **Agent Deployment Issues**

### **Problem: Agent Deployment Failed**
```bash
# Error message:
[DEPLOYING] 1.2.3.4... FAILED - /bin/sh: python3: command not found
```

**Solutions:**
```bash
# Install Python on VPS
ssh root@your-vps-ip "apt update && apt install -y python3"          # Ubuntu/Debian
ssh root@your-vps-ip "yum install -y python3"                        # CentOS/RHEL
ssh root@your-vps-ip "pacman -S python"                              # Arch Linux

# Verify Python installation
ssh root@your-vps-ip "python3 --version"
```

### **Problem: No Write Permission**
```bash
# Error message:
Failed to deploy agent: Permission denied
```

**Solutions:**
```bash
# Check directory permissions
ssh root@your-vps-ip "ls -la /tmp"

# Create directory with proper permissions
ssh root@your-vps-ip "mkdir -p /tmp/slowhttp_c2 && chmod 755 /tmp/slowhttp_c2"

# Check available space
ssh root@your-vps-ip "df -h /tmp"
```

### **Problem: Agent Script Won't Execute**
```bash
# Error message:
/tmp/slowhttp_c2/agent.py: line 1: #!/usr/bin/env: No such file or directory
```

**Solutions:**
```bash
# Check Python path on VPS
ssh root@your-vps-ip "which python3"

# Update shebang if needed
ssh root@your-vps-ip "sed -i '1s|.*|#!/usr/bin/python3|' /tmp/slowhttp_c2/agent.py"

# Make script executable
ssh root@your-vps-ip "chmod +x /tmp/slowhttp_c2/agent.py"
```

## ⚡ **Attack Launch Issues**

### **Problem: Attack Fails to Start**
```bash
# Error message:
[VPS] 1.2.3.4: Failed to launch attack - No module named 'socket'
```

**Solutions:**
```bash
# Check Python installation on VPS
ssh root@your-vps-ip "python3 -c 'import socket; print(\"Socket module OK\")'"

# Reinstall Python if needed
ssh root@your-vps-ip "apt reinstall python3"  # Ubuntu/Debian

# Check for missing modules
ssh root@your-vps-ip "python3 -c 'import random, string, threading, time'"
```

### **Problem: Target Unreachable from VPS**
```bash
# Error message:
[SLOWLORIS] Created 0 initial connections
```

**Diagnostics:**
```bash
# Test connectivity from VPS to target
ssh root@your-vps-ip "ping -c 3 target-website.com"
ssh root@your-vps-ip "curl -I http://target-website.com"
ssh root@your-vps-ip "telnet target-website.com 80"

# Check DNS resolution
ssh root@your-vps-ip "nslookup target-website.com"
```

**Solutions:**
1. **Verify target URL format**: Use `http://` or `https://`
2. **Check target accessibility**: Ensure target is publicly accessible
3. **Verify port**: Default is 80 for HTTP, 443 for HTTPS
4. **Check VPS firewall**: Ensure outbound connections allowed

### **Problem: Low Connection Count**
```bash
# Error message:
[SLOWLORIS] Created 150 initial connections (expected 1000)
```

**Causes and Solutions:**

1. **Rate Limiting:**
   ```bash
   # Reduce connections per VPS
   # Use: 500-800 instead of 1000+
   ```

2. **Resource Limits:**
   ```bash
   # Check VPS resources
   ssh root@your-vps-ip "free -m && ulimit -n"
   
   # Increase file descriptor limit
   ssh root@your-vps-ip "ulimit -n 65536"
   ```

3. **Target Protection:**
   ```bash
   # Try different attack parameters
   # Increase delay between connections
   # Reduce concurrent connections
   ```

## 📊 **Monitoring Issues**

### **Problem: Monitoring Shows No Active Processes**
```bash
# VPS Status shows 0 processes but attack should be running
```

**Diagnostics:**
```bash
# Check processes manually
ssh root@your-vps-ip "ps aux | grep python"
ssh root@your-vps-ip "ps aux | grep agent.py"

# Check if processes died
ssh root@your-vps-ip "cat /tmp/slowhttp_c2/attack.log"
```

**Solutions:**
```bash
# Restart attack if needed
# Stop monitoring, go to main menu, relaunch attack

# Check for process crashes
ssh root@your-vps-ip "dmesg | tail -20"
ssh root@your-vps-ip "journalctl -n 50"
```

### **Problem: Monitoring Freezes**
```bash
# Interface stops updating
```

**Solutions:**
```bash
# Press Ctrl+C to exit monitoring
# Restart the C2 system
# Check system resources:
top
free -m
df -h
```

## 💾 **Database Issues**

### **Problem: Database Corruption**
```bash
# Error message:
sqlite3.DatabaseError: database disk image is malformed
```

**Solutions:**
```bash
# Backup current database
cp c2_database.db c2_database.db.backup

# Try to repair
echo ".dump" | sqlite3 c2_database.db | sqlite3 c2_database_new.db
mv c2_database.db c2_database.db.old
mv c2_database_new.db c2_database.db

# Or reset database (loses all data)
rm c2_database.db
# Restart application to recreate
```

### **Problem: Permission Denied on Database**
```bash
# Error message:
sqlite3.OperationalError: attempt to write a readonly database
```

**Solutions:**
```bash
# Fix database permissions
chmod 644 c2_database.db
chown $USER:$USER c2_database.db

# Fix directory permissions
chmod 755 .
```

## 🔐 **Security and Encryption Issues**

### **Problem: Encryption Key Missing**
```bash
# Error message:
FileNotFoundError: [Errno 2] No such file or directory: 'key.key'
```

**Solutions:**
```bash
# Key will be auto-generated on first run
# If key is corrupted, delete and restart:
rm key.key
# Restart application - note: this will invalidate stored passwords
```

### **Problem: Cannot Decrypt Stored Passwords**
```bash
# Error message:
cryptography.fernet.InvalidToken
```

**Solutions:**
```bash
# This happens when encryption key changes
# Remove all VPS and re-add them:

# 1. Backup VPS list (if needed)
sqlite3 c2_database.db "SELECT ip_address, username, ssh_port, location FROM vps_nodes;"

# 2. Clear VPS table
sqlite3 c2_database.db "DELETE FROM vps_nodes;"

# 3. Re-add all VPS nodes through the interface
```

## 🌐 **Network and Firewall Issues**

### **Problem: Outbound Connections Blocked**
```bash
# Connections fail from VPS to target
```

**Diagnostics:**
```bash
# Test different protocols and ports
ssh root@your-vps-ip "curl -I http://target.com"
ssh root@your-vps-ip "curl -I https://target.com"
ssh root@your-vps-ip "wget --spider http://target.com"

# Check VPS firewall
ssh root@your-vps-ip "iptables -L -n"
ssh root@your-vps-ip "ufw status"
```

**Solutions:**
```bash
# Allow outbound HTTP/HTTPS
ssh root@your-vps-ip "ufw allow out 80"
ssh root@your-vps-ip "ufw allow out 443"

# For iptables
ssh root@your-vps-ip "iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT"
ssh root@your-vps-ip "iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT"
```

### **Problem: Too Many Open Files**
```bash
# Error message:
OSError: [Errno 24] Too many open files
```

**Solutions:**
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# For current session
ulimit -n 65536

# On VPS
ssh root@your-vps-ip "ulimit -n 65536"
ssh root@your-vps-ip "echo '* soft nofile 65536' >> /etc/security/limits.conf"
```

## 🖥️ **Interface and Display Issues**

### **Problem: Colors Not Displaying**
```bash
# Terminal shows raw color codes like \033[91m
```

**Solutions:**
```bash
# Check terminal compatibility
echo $TERM

# Force color support
export TERM=xterm-256color

# For Windows/WSL
export TERM=xterm-color

# Install colorama for better Windows support
pip install colorama
```

### **Problem: Interface Layout Broken**
```bash
# Text wrapping issues, columns misaligned
```

**Solutions:**
```bash
# Check terminal size
stty size

# Resize terminal window to at least 80x24
# Or run in fullscreen mode

# Force specific terminal size
stty rows 30 cols 100
```

## ⚙️ **Performance Issues**

### **Problem: High CPU Usage**
```bash
# System becomes slow during monitoring
```

**Solutions:**
```bash
# Increase monitoring interval (edit source code)
# Reduce number of simultaneous VPS monitoring
# Close other applications

# Check system resources
htop
iostat 1
```

### **Problem: Memory Issues**
```bash
# Error message:
MemoryError: Unable to allocate array
```

**Solutions:**
```bash
# Check available memory
free -m

# Reduce concurrent connections
# Use fewer VPS nodes simultaneously
# Restart the application periodically

# Increase swap space if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 🔧 **Emergency Procedures**

### **Complete System Reset**
```bash
# Stop all processes
pkill -f slowhttp_c2.py

# Clean all VPS nodes
for ip in $(sqlite3 c2_database.db "SELECT ip_address FROM vps_nodes;"); do
    ssh root@$ip "pkill -f 'python3 agent.py'; rm -rf /tmp/slowhttp_c2" &
done
wait

# Reset local database
rm c2_database.db key.key

# Restart application
./start.sh
```

### **VPS Emergency Cleanup**
```bash
# Script to clean all VPS nodes
#!/bin/bash
VPS_LIST="1.2.3.4 5.6.7.8 9.10.11.12"

for vps in $VPS_LIST; do
    echo "Cleaning $vps..."
    ssh -o ConnectTimeout=10 root@$vps "
        pkill -f 'python3 agent.py' 2>/dev/null || true
        rm -rf /tmp/slowhttp_c2 2>/dev/null || true
        echo 'Cleaned $vps'
    " &
done
wait
echo "Emergency cleanup completed"
```

## 📞 **Getting Additional Help**

### **Collecting Debug Information**
```bash
# System information
uname -a
python3 --version
pip list

# Application logs
cat logs/*.log 2>/dev/null

# Database status
sqlite3 c2_database.db ".tables"
sqlite3 c2_database.db "SELECT COUNT(*) FROM vps_nodes;"

# Network connectivity
ip route show
ping -c 3 8.8.8.8
```

### **Creating Effective Bug Reports**

Include the following information:
1. **Operating System**: `uname -a`
2. **Python Version**: `python3 --version`
3. **Installation Method**: Installer script vs manual
4. **Complete Error Message**: Copy exact text
5. **Steps to Reproduce**: Detailed sequence
6. **Expected Behavior**: What should happen
7. **Actual Behavior**: What actually happened
8. **Configuration**: Any custom settings

### **Community Support**
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share experiences
- **Documentation**: Check all documentation files
- **Search**: Look for similar issues first

### **Professional Support**
For enterprise deployments or complex issues:
- Consider professional cybersecurity consultation
- Engage with penetration testing professionals
- Review with legal and compliance teams

---

**Remember**: Always ensure you have proper authorization before testing any systems. If you encounter issues during authorized testing, document everything for your final report.