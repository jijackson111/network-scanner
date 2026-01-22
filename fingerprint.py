import socket

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner.decode(errors='ignore').strip()
    
    except (socket.timeout, ConnectionRefusedError, socket.error):
        return None
    
    finally:
        s.close()

def get_standard(port):
    try:
        return socket.getservbyport(port, "tcp").upper()
    except:
        return "Unknown"
    
def get_service(found_ports):
    ip_port_service_dict = {}
    for k, v in found_ports.items():
        port_service_dict = {}
        for port in v:
            service = get_standard(port)
            port_service_dict[port] = service
        ip_port_service_dict[k] = port_service_dict
    return ip_port_service_dict
