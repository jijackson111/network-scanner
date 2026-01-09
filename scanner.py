from scapy.all import *
import time
import sys
from concurrent.futures import ThreadPoolExecutor 
from itertools import repeat

def scan_port(task):
    ip, port = task
    # Define source port
    sport = RandShort() 
    # Create TCP SYN packet
    packet = IP(dst=ip)/TCP(sport=sport, dport=port, flags="S")
    # Send the packet and wait for response
    response = sr1(packet, timeout=1, verbose=0)
    # Check if we got packet back
    if response is None:
        return None
    # Check if response has TCP layer
    if response.haslayer(TCP):
        # Use string comparison "SA" for SYN-ACK or "RA" for RST-ACK
        if response[TCP].flags == "SA":
            # Send RST to be close the connection
            send(IP(dst=ip)/TCP(sport=sport, dport=port, flags="R"), verbose=0)
            return(ip, port)      
    return None

def run_port_scan(ip_list, port_range):
    # Create list of port range
    port_start, port_end = port_range.split('-')
    port_list = list(range(int(port_start), int(port_end)+1))
    # Scan ports in port range
    tasks = list(itertools.product(ip_list, port_list))
    print(f"[*] Scanning {len(ip_list)} hosts across {len(port_list)} ports...")
    with ThreadPoolExecutor(max_workers = 100) as executor:
        results = list(filter(None, executor.map(scan_port, tasks)))
    return results

#print(run_port_scan(sys.argv[1], sys.argv[2]))