from scapy.all import *

# Set target
target = "10.0.0.141"

# Function to send ICMP Packets (ping)
def ping_sweep(target):
    responses, _ = sr(IP(dst=target)/ICMP(), timeout=2, verbose=True)
    for send, response in responses:
        print(f"Host {response.src} is active")

# Call the function 
ping_sweep(target)
