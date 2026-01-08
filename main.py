import argparse
import os 
import sys
import discovery

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

# Get list of clients that are up
active_clients = discovery.scan(target_range)
print(active_clients)
