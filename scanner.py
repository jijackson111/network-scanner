from scapy.all import *
import time
import sys
from concurrent.futures import ThreadPoolExecutor 
from itertools import repeat

# Define target and source port, create TCP SYN packet, send packet and wait for response
# If packet has returned, check if it has TCP layer and if SYN-ACK, then close connection
def scan_port(task):
    ip, port = task
    sport = RandShort() 
    packet = IP(dst=ip)/TCP(sport=sport, dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response is None:
        return None
    if response.haslayer(TCP):
        if response[TCP].flags == "SA":
            send(IP(dst=ip)/TCP(sport=sport, dport=port, flags="R"), verbose=0)
            return(ip, port)      
    return None

# Sort list 
def sort_list(plist):
    ip_port_dict = {}
    for elem in plist:
        if elem[0] in ip_port_dict:
            ip_port_dict[elem[0]].append(elem[1])
        else:
            ip_port_dict[elem[0]] = [elem[1]]
    return ip_port_dict

# Create list of port range then scan ports in said range
def run_port_scan(ip_list, port_range):
    port_start, port_end = port_range.split('-')
    port_list = list(range(int(port_start), int(port_end)+1))
    tasks = list(itertools.product(ip_list, port_list))
    print(f"[*] Scanning {len(ip_list)} hosts across {len(port_list)} ports...")
    with ThreadPoolExecutor(max_workers = 100) as executor:
        results = list(filter(None, executor.map(scan_port, tasks)))
    sorted_list = sort_list(results)
    return sorted_list
