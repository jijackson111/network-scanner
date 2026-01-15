import socket

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        if port == 80:
            s.send(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
        banner = s.recv(1024)
        return banner.decode(errors='ignore').strip()
    
    except (socket.timeout, ConnectionRefusedError, socket.error):
        return None
    
    finally:
        s.close()
