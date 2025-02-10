==NETSCAN==
# NetScan, a Network Scanner

A Python-based network scanner similar to Nmap. This tool allows you to discover live hosts, scan open ports, and detect services running on a network.

## Features
- **Host Discovery**: Identify live hosts using ARP and ICMP.
- **Port Scanning**: Scan TCP and UDP ports.
- **Multi-threading**: Speed up scans using multiple threads.
- **Output Options**: Save results in JSON, CSV, or plain text.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd netscan
   python3 netscan.py

   usage: network_scanner.py [-h] [-p PORTS] [-s {syn,connect,udp}] [-t THREADS] [-o OUTPUT] [-v] [-d {arp,tcp}]
                          target
  positional arguments:
  target                Target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24)

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Port range to scan (e.g., 80,443 or 1-1000). If not specified, scans common ports
  -s {syn,connect,udp}, --scan-type {syn,connect,udp}
                        Type of scan to perform (default: syn)
  -t THREADS, --threads THREADS
                        Number of threads to use (default: 10)
  -o OUTPUT, --output OUTPUT
                        Save results to a file (supported formats: json, csv, txt)
  -v, --verbose         Enable verbose output
  -d {arp,tcp}, --discovery {arp,tcp}
                        Host discovery method (default: auto-detect based on target)


