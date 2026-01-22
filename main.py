import argparse
import os 
import sys
import discovery
import scanner
import fingerprint

# Check if run with sudo
if os.geteuid() != 0:
    sys.exit("This script requires root privileges. Please run with sudo.")

# Initialise parser and take arguments
parser = argparse.ArgumentParser(description="Take arguments for port scan")
parser.add_argument("-t")
parser.add_argument('-p')
parser.add_argument('-o')
args = parser.parse_args()
target_range = args.t
port_range = args.p
output_file = args.o

# Get list of client IP addresses that are up if range
active_clients = discovery.scan(target_range)
ip_list = [client['ip'] for client in active_clients]
mac_list = [client['mac'] for client in active_clients]
if not ip_list:
    sys.exit("No active hosts found") 
print(f"{len(ip_list)} hosts found")
print(ip_list)

# Check if all ips want to be scanned
all_ips = input("\nDo you want all IP addresses to be scan [y/n]: ")
if all_ips == 'y':
    ip_list_updated = ip_list
elif all_ips == "n":
    selected_ips = input("Please enter the index of the IP addresses you would like to use: ")
    if " " not in selected_ips:
        ip_list_updated = [ip_list[int(selected_ips)]]
    else:
        sips_list = selected_ips.split(" ")
        ip_list_updated = [ip_list[int(i)] for i in sips_list]

# Send list for scanning
found_ports = scanner.run_port_scan(ip_list_updated, port_range)
print(found_ports)

# Retrieve banner