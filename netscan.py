# Hey there! Welcome to our awesome network scanner! ^_^
import argparse
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1, Scapy_Exception
import ipaddress
import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional
from time import time
from math import ceil
from datetime import datetime
import json
import csv
import os
from tqdm import tqdm
import colorama
from colorama import Fore, Style
import random
import re
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

# Making Windows users feel included! :D
colorama.init()

# Pretty colors to make our terminal happy! ^_^
COLORS = [
    Fore.GREEN,   # Forest green!
    Fore.BLUE,    # Ocean blue!
    Fore.MAGENTA, # Magic purple!
    Fore.CYAN,    # Sky blue!
    Fore.YELLOW   # Sunshine! :3
]

# All the cool ports that servers like to hang out on :)
COMMON_PORTS = [
    20, 21,           # FTP - File Transfer Party! :D
    22,               # SSH - Secure Shell Hideout
    23,               # Telnet - The old-school cool
    25,               # SMTP - Mail carrier at your service! ^^
    53,               # DNS - The internet's phone book :3
    80, 443,          # HTTP/HTTPS - World Wide Web, woo!
    110,              # POP3 - Mail collector extraordinaire
    111,              # RPC - Remote Procedure Caller
    135, 139,         # NetBIOS - Windows' best friend
    143,              # IMAP - Email's VIP lounge
    445,              # SMB - Sharing is caring! <3
    993,              # IMAPS - Secure mail party
    995,              # POP3S - Extra secure mail collection
    1723,             # PPTP - VPN tunnel of fun!
    3306,             # MySQL - Database paradise
    3389,             # RDP - Remote Desktop Party :D
    5900,             # VNC - Screen sharing spectacular
    8080, 8443,       # HTTP Alt - Web servers on vacation
    27017             # MongoDB - NoSQL hangout spot ^^
]

# Custom Exceptions
class ScannerError(Exception):
    """Base exception class for network scanner errors"""
    pass

class NetworkError(ScannerError):
    """Exception raised for network-related errors"""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

class InputError(ScannerError):
    """Exception raised for invalid input parameters"""
    pass

class PermissionError(ScannerError):
    """Exception raised when scanner lacks required privileges"""
    pass

# Output Handler Class
class OutputHandler:
    """Handle saving scan results in different formats"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ['.json', '.csv', '.txt']:
            raise ValueError("Output file must have .json, .csv, or .txt extension")
    
    def save_results(self, scan_results: Dict[str, Dict[str, List[int]]], 
                    scan_info: Dict = None) -> None:
        ext = os.path.splitext(self.filename)[1].lower()
        
        if ext == '.json':
            self._save_json(scan_results, scan_info)
        elif ext == '.csv':
            self._save_csv(scan_results)
        else:  # .txt
            self._save_txt(scan_results, scan_info)
    
    def _save_json(self, results: Dict, scan_info: Dict) -> None:
        output = {
            "scan_info": {
                "timestamp": self.timestamp,
                "configuration": scan_info or {}
            },
            "results": results
        }
        
        with open(self.filename, 'w') as f:
            json.dump(output, f, indent=4)
    
    def _save_csv(self, results: Dict) -> None:
        with open(self.filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "State", "Protocol"])
            
            for host, states in results.items():
                for state, ports in states.items():
                    for port in ports:
                        writer.writerow([host, port, state, "tcp"])
    
    def _save_txt(self, results: Dict, scan_info: Dict) -> None:
        with open(self.filename, 'w') as f:
            f.write(f"Network Scan Results\n")
            f.write(f"===================\n")
            f.write(f"Scan completed at: {self.timestamp}\n\n")
            
            if scan_info:
                f.write("Scan Configuration:\n")
                f.write("-----------------\n")
                for key, value in scan_info.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
            
            f.write("Scan Results:\n")
            f.write("------------\n")
            for host, states in results.items():
                f.write(f"\nHost: {host}\n")
                
                if states["open"]:
                    f.write("  Open ports: ")
                    f.write(", ".join(map(str, sorted(states["open"]))))
                    f.write("\n")
                
                if states["filtered"]:
                    f.write("  Filtered ports: ")
                    f.write(", ".join(map(str, sorted(states["filtered"]))))
                    f.write("\n")
                
                if states["closed"]:
                    f.write("  Closed ports: ")
                    f.write(", ".join(map(str, sorted(states["closed"]))))
                    f.write("\n")

# Validation Functions
def validate_target(target: str) -> None:
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        raise InputError(f"Invalid target format: {str(e)}")

def validate_ports(ports: str) -> None:
    try:
        if ports.lower() == "common":
            return
            
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 <= start <= 65535 and 0 <= end <= 65535):
                    raise InputError("Port numbers must be between 0 and 65535")
                if start > end:
                    raise InputError("Invalid port range: start port greater than end port")
            else:
                port = int(part)
                if not 0 <= port <= 65535:
                    raise InputError("Port numbers must be between 0 and 65535")
    except ValueError:
        raise InputError("Invalid port format. Use comma-separated numbers or ranges (e.g., '80,443' or '1-1024')")

def check_root_privileges() -> None:
    import os
    if os.name == 'posix' and os.geteuid() != 0:
        raise PermissionError("Root privileges required for raw socket operations. Try running with sudo.")

def handle_scan_error(error: Exception, verbose: bool = False) -> str:
    if isinstance(error, Scapy_Exception):
        return f"Network error: {str(error)}"
    elif isinstance(error, socket.error):
        return f"Socket error: {str(error)}"
    elif isinstance(error, ScannerError):
        return str(error)
    else:
        if verbose:
            import traceback
            return f"Unexpected error: {str(error)}\n{traceback.format_exc()}"
        return f"Unexpected error: {str(error)}"

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetScan - A friendly network discovery and security auditing tool ^_^",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "target",
        help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24)"
    )
    
    # Optional arguments
    parser.add_argument(
        "-p", "--ports",
        help="Port range to scan (e.g., 80,443 or 1-1000). If not specified, scans common ports",
        default="common"
    )
    
    parser.add_argument(
        "-s", "--scan-type",
        choices=["syn", "connect", "udp"],
        default="syn",
        help="Type of scan to perform (default: syn)"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of threads to use (default: 10)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Save results to a file (supported formats: json, csv, txt)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    # Add new argument for discovery method
    parser.add_argument(
        "-d", "--discovery",
        choices=["arp", "tcp"],
        help="Host discovery method (default: auto-detect based on target)"
    )

    args = parser.parse_args()
    
    # Validate input parameters
    try:
        validate_target(args.target)
        validate_ports(args.ports)
        if args.scan_type in ["syn", "udp"]:
            check_root_privileges()
    except (InputError, PermissionError) as e:
        parser.error(str(e))
    
    return args

def is_local_network(target: str) -> bool:
    """
    Check if target is in local network ranges
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.is_private or network.is_loopback:
            return True
        return False
    except ValueError:
        return False

def discover_hosts_arp(target, verbose=False, threads=10):
    """
    Perform ARP ping sweep to discover live hosts on the network
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        
        if verbose:
            print(f"\n[*] Starting host discovery on {network}")
            print("[*] Sending ARP requests...")
        
        # Split network into chunks for parallel processing
        hosts = list(network.hosts())
        chunk_size = ceil(len(hosts) / threads)
        chunks = [hosts[i:i + chunk_size] for i in range(0, len(hosts), chunk_size)]
        
        discovered_hosts = []
        
        def scan_chunk(chunk):
            chunk_hosts = []
            for ip in chunk:
                arp = ARP(pdst=str(ip))
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                result = srp(packet, timeout=1, verbose=0)[0]
                if result:
                    received = result[0][1]
                    chunk_hosts.append(received.psrc)
                    if verbose:
                        print(f"[+] Host discovered: {received.psrc} ({received.hwsrc})")
            return chunk_hosts
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_chunk, chunk) for chunk in chunks]
            for future in as_completed(futures):
                discovered_hosts.extend(future.result())
        
        return discovered_hosts

    except Exception as e:
        print(f"Error during ARP discovery: {str(e)}")
        sys.exit(1)

def discover_hosts_tcp(target, verbose=False, threads=10):
    """
    Perform TCP ping sweep to discover hosts
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        
        if verbose:
            print(f"\n[*] Starting TCP ping sweep on {network}")
            print("[*] Sending TCP SYN packets to ports 80,443...")
        
        hosts = list(network.hosts())
        discovered_hosts = []
        common_ports = [80, 443]
        
        def check_host(ip):
            ip_str = str(ip)
            for port in common_ports:
                try:
                    # Try socket connection first (faster)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_str, port))
                    sock.close()
                    
                    if result == 0:
                        if verbose:
                            print(f"[+] Host discovered: {ip_str}")
                        return ip_str
                except:
                    # Fall back to TCP SYN if socket fails
                    try:
                        syn_packet = IP(dst=ip_str)/TCP(dport=port, flags="S")
                        response = sr1(syn_packet, timeout=1, verbose=0)
                        
                        if response is not None and response.haslayer(TCP):
                            tcp_flags = response.getlayer(TCP).flags
                            if tcp_flags == 0x12 or tcp_flags == 0x14:
                                if verbose:
                                    print(f"[+] Host discovered: {ip_str}")
                                return ip_str
                    except:
                        continue
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_host, ip) for ip in hosts]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered_hosts.append(result)
        
        return discovered_hosts

    except Exception as e:
        print(f"Error during TCP discovery: {str(e)}")
        sys.exit(1)

def discover_hosts(target, method=None, verbose=False):
    """
    Discover live hosts using the specified method
    
    Args:
        target: IP address or network range
        method: Discovery method ('arp' or 'tcp', None for auto-detect)
        verbose: Enable verbose output
    """
    # Auto-detect method if not specified
    if method is None:
        method = "arp" if is_local_network(target) else "tcp"
        if verbose:
            print(f"[*] Auto-selected {method.upper()} discovery method")
    
    if method == "arp":
        return discover_hosts_arp(target, verbose)
    else:
        return discover_hosts_tcp(target, verbose)

def parse_port_range(port_arg: str) -> List[int]:
    """
    Parse port argument string into a list of ports
    
    Args:
        port_arg: String like "80,443" or "1-1024" or "common"
    Returns:
        List of port numbers
    """
    if port_arg.lower() == "common":
        return sorted(COMMON_PORTS)
    
    ports = []
    for part in port_arg.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(ports)

def tcp_syn_scan(target: str, port: int, timeout: float = 1) -> Tuple[int, str]:
    """
    Perform a TCP SYN scan on a specific port
    """
    try:
        syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=timeout, verbose=0)
        
        if response is None:
            return port, "filtered"
        
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if flags == 0x12:  # SYN-ACK
                # Send RST packet to close connection
                rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                sr1(rst_packet, timeout=timeout, verbose=0)
                return port, "open"
            elif flags == 0x14:  # RST-ACK
                return port, "closed"
        
        return port, "filtered"
    except Scapy_Exception as e:
        raise NetworkError(f"Network error during SYN scan: {str(e)}", e)
    except Exception as e:
        raise NetworkError(f"Error scanning port {port}: {str(e)}", e)

def tcp_connect_scan(target: str, port: int, timeout: float = 1) -> Tuple[int, str]:
    """
    Perform a TCP Connect scan on a specific port
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            return port, "open"
        elif result == 111:  # Connection refused
            return port, "closed"
        else:
            return port, "filtered"
    except socket.timeout:
        return port, "filtered"
    except socket.error as e:
        raise NetworkError(f"Socket error during connect scan: {str(e)}", e)
    except Exception as e:
        raise NetworkError(f"Error scanning port {port}: {str(e)}", e)

def udp_scan(target: str, port: int, timeout: float = 2) -> Tuple[int, str]:
    """
    Perform a UDP scan on a specific port
    """
    try:
        udp_packet = IP(dst=target)/UDP(dport=port)
        response = sr1(udp_packet, timeout=timeout, verbose=0)
        
        if response is None:
            return port, "open|filtered"
        
        if response.haslayer(UDP):
            return port, "open"
        elif response.haslayer("ICMP"):
            if int(response.getlayer("ICMP").type) == 3 and \
               int(response.getlayer("ICMP").code) == 3:
                return port, "closed"
            elif int(response.getlayer("ICMP").type) == 3 and \
                 int(response.getlayer("ICMP").code) in [1, 2, 9, 10, 13]:
                return port, "filtered"
        
        return port, "open|filtered"
    except Exception as e:
        return port, "error"

def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """Get common service name for a port"""
    common_ports = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'domain',
        80: 'http',
        110: 'pop3',
        111: 'rpcbind',
        135: 'msrpc',
        139: 'netbios-ssn',
        143: 'imap',
        443: 'https',
        445: 'microsoft-ds',
        993: 'imaps',
        995: 'pop3s',
        1723: 'pptp',
        3306: 'mysql',
        3389: 'ms-wbt-server',
        5900: 'vnc',
        8080: 'http-proxy',
        8443: 'https-alt',
        27017: 'mongodb'
    }
    return common_ports.get(port, 'unknown')

def get_service_version(target: str, port: int, protocol: str = 'tcp', timeout: float = 2) -> str:
    """
    Time to play 'Guess That Service'! :D
    We'll try to figure out what's running on each port
    """
    service_probes = {
        'http': b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n',  # Knock knock! Anyone home? :3
        'smtp': b'EHLO scanner.local\r\n',              # Mail server, you there? ^^
        'ftp': b'',    # FTP servers are chatty - they'll speak first! :)
        'ssh': b'',    # SSH is shy but will tell us who they are <3
        'pop3': b'',   # Another chatty one!
        'imap': b'',   # Mail server VIP room
        'telnet': b''  # The classic connection
    }
    
    # Let's see who answers our call! ^_^
    try:
        if protocol == 'tcp':
            sock = socket.socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket.socket(AF_INET, SOCK_DGRAM)
        
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # First, let's see if they say hi! :D
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            banner = ''
        
        service = get_service_name(port, protocol)
        
        # If they're shy, maybe we should start the conversation! ^^
        if not banner and service in service_probes:
            if service == 'http':
                probe = service_probes[service] % target.encode()
            else:
                probe = service_probes[service]
            
            if probe:
                sock.send(probe)
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    banner = ''
        
        sock.close()
        
        # Time to decode their response! :3
        if banner:
            # SSH version - they're usually very clear about who they are!
            if 'SSH' in banner:
                match = re.search(r'SSH-\d+\.\d+-([^\s]+)', banner)
                if match:
                    return f"SSH {match.group(1)}"
            
            # Web servers love to chat about themselves ^^
            elif 'HTTP' in banner:
                match = re.search(r'Server: ([^\r\n]+)', banner)
                if match:
                    return match.group(1)
            
            # FTP servers are friendly greeters :D
            elif 'FTP' in banner.upper():
                match = re.search(r'^([^\n]+)', banner)
                if match:
                    return match.group(1)
            
            # SMTP servers are very formal with their introductions!
            elif 'SMTP' in banner.upper():
                match = re.search(r'^([^\n]+)', banner)
                if match:
                    return match.group(1)
            
            return banner.split('\n')[0]
        
        return ""
    except Exception:
        return ""

def scan_target(target: str, ports: List[int], scan_type: str, 
                threads: int = 10, verbose: bool = False) -> dict:
    """Scan a target host for open ports"""
    results = {"open": [], "closed": [], "filtered": [], "error": []}
    scan_function = {
        "syn": tcp_syn_scan,
        "connect": tcp_connect_scan,
        "udp": udp_scan
    }[scan_type]
    
    pbar = tqdm(
        total=len(ports),
        desc=f"{Fore.CYAN}Scanning {target}{Style.RESET_ALL}",
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        ncols=100,
        colour='green'
    )
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_function, target, port): port 
            for port in ports
        }
        
        for future in as_completed(future_to_port):
            try:
                port, status = future.result()
                results[status].append(port)
                pbar.update(1)
            except Exception as e:
                results["error"].append(future_to_port[future])
                if verbose:
                    tqdm.write(f"{Fore.RED}[-] Error scanning port {future_to_port[future]}: {str(e)}{Style.RESET_ALL}")
    
    pbar.close()
    
    # Add version detection progress bar for open ports
    if results["open"]:
        print(f"\n{Fore.CYAN}Performing service detection...{Style.RESET_ALL}")
    
    return results

def print_nmap_style_results(host: str, results: dict, scan_type: str, show_versions: bool = True):
    """Print scan results in nmap-like format"""
    protocol = 'udp' if scan_type == 'udp' else 'tcp'
    
    # Print host header
    print(f"\nNmap scan report for {host}")
    print(f"Host is up")
    
    if not results["open"]:
        print("All scanned ports are closed or filtered")
        return
    
    # Print port table header
    if show_versions:
        print(f"\nPORT      STATE   SERVICE         VERSION")
    else:
        print(f"\nPORT      STATE   SERVICE")
    
    # Print open ports
    for port in sorted(results["open"]):
        service = get_service_name(port, protocol)
        port_str = f"{port}/{protocol}".ljust(9)
        state = "open".ljust(7)
        
        if show_versions:
            version = get_service_version(host, port, protocol)
            service_str = service.ljust(14)
            if version:
                print(f"{Fore.GREEN}{port_str}{state}{service_str}{version}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}{port_str}{state}{service_str}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}{port_str}{state}{service}{Style.RESET_ALL}")
    
    # Print filtered ports if verbose
    if results["filtered"]:
        filtered_count = len(results["filtered"])
        print(f"\nNot shown: {filtered_count} filtered port{'s' if filtered_count > 1 else ''}")

def main():
    """
    Main function that combines all scanner components
    """
    try:
        args = parse_arguments()
        
        # Create scan configuration dictionary
        scan_info = {
            "target": args.target,
            "discovery_method": args.discovery,
            "ports": args.ports,
            "scan_type": args.scan_type,
            "threads": args.threads,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Print banner
        print(f"\n{Fore.CYAN}NetScan v1.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}============{Style.RESET_ALL}")
        print("Your friendly neighborhood port scanner! :D\n")
        
        if args.verbose:
            print("\nScan Configuration:")
            print("-----------------")
            for key, value in scan_info.items():
                print(f"{key}: {value}")
        
        # Initialize output handler if output file specified
        output_handler = None
        if args.output:
            try:
                output_handler = OutputHandler(args.output)
                if args.verbose:
                    print(f"\n[*] Output will be saved to: {args.output}")
            except ValueError as e:
                print(f"\nError: {str(e)}")
                sys.exit(1)
        
        # Perform host discovery
        print("\n[*] Starting host discovery...")
        start_time = time()
        live_hosts = discover_hosts(args.target, args.discovery, args.verbose)
        
        if not live_hosts:
            print("\n[-] No live hosts found")
            sys.exit(0)
        
        print(f"\n[+] Found {len(live_hosts)} live hosts in {time() - start_time:.1f} seconds")
        
        # Parse ports
        try:
            ports = parse_port_range(args.ports)
            if args.verbose:
                print(f"\n[*] Scanning ports: {args.ports} ({len(ports)} ports)")
        except ValueError as e:
            print(f"\nError parsing port range: {str(e)}")
            sys.exit(1)
        
        # Scan each live host
        all_results = {}
        total_open_ports = 0
        scan_start_time = time()
        
        print(f"\n{Fore.CYAN}Starting port scan...{Style.RESET_ALL}")
        print("================================================================")
        
        for host in live_hosts:
            results = scan_target(host, ports, args.scan_type, args.threads, args.verbose)
            all_results[host] = results
            total_open_ports += len(results["open"])
            print_nmap_style_results(host, results, args.scan_type, True)
        
        # Print scan timing
        total_time = time() - scan_start_time
        print("\nScan completed in %.2f seconds" % total_time)
        print(f"Scanned {len(live_hosts)} host{'s' if len(live_hosts) > 1 else ''}")
        print(f"Found {total_open_ports} open port{'s' if total_open_ports > 1 else ''}")
        
        # Save results if output file specified
        if output_handler:
            try:
                output_handler.save_results(all_results, scan_info)
                print(f"\n[+] Results saved to {args.output}")
            except Exception as e:
                print(f"\nError saving results: {str(e)}")
                sys.exit(1)
        
        print("\nScan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        error_msg = handle_scan_error(e, args.verbose)
        print(f"\nError: {error_msg}")
        sys.exit(1)

if __name__ == "__main__":
    main() 