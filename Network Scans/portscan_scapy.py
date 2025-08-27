from scapy.all import *

target = "10.0.0.141"
ports = [22, 80, 443]

def scan_ports(target, ports):
    for port in ports:
        # 1) Build a TCP SYN ("S") packet to this port
        pkt = IP(dst=target) / TCP(dport=port, flags="S")

        # 2) Send it and wait for a single reply
        resp = sr1(pkt, timeout=2, verbose=0)
        
        #Show raw port scan results 
        resp.show() 

        # 3) Decide what happened
        if resp is None:
            print(f"Port {port}: no response (filtered or dropped)")
            continue

        if resp.haslayer(TCP):
            # SYN+ACK (0x12) means "open"
            if resp[TCP].flags == 0x12:
                print(f"Port {port}: OPEN")
                # Be polite: send RST to close the half-open connection
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)

            # RST+ACK (0x14) means "closed"
            elif resp[TCP].flags == 0x14:
                print(f"Port {port}: CLOSED")
            else:
                print(f"Port {port}: unexpected TCP flags={resp[TCP].flags}")

        else:
            # Some firewalls reply with non-TCP messages
            print(f"Port {port}: non-TCP response (likely filtered)")

# Run it
scan_ports(target, ports)
