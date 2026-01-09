import scapy.all as scapy

def scan(ip_range):
    # Create an ARP request packet for the target range
    arp_request = scapy.ARP(pdst=ip_range)

    # Create an Ethernet frame to wrap the ARP request using the Broadcast MAC address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine them
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and wait for responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=1, retry=2)[0]

    # Parse the results
    clients = []
    for sent, received in answered_list:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    
    return clients
