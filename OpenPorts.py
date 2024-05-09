//Everlyn Leon

import socket
import threading
from scapy.all import *

# Set target IP address
target_ip = "192.168.1.1"  # Replace with the desired IP address

# Define a range of ports to scan
port_range = range(1, 1024)

# List to store open ports
open_ports = []

# Function to scan a single port
def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        open_ports.append(port)
    sock.close()

# Create threads for each port
threads = []
for port in port_range:
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Display open ports
if open_ports:
    print(f"Open ports at {target_ip}: {sorted(open_ports)}")
else:
    print(f"No open ports found at {target_ip}.")
