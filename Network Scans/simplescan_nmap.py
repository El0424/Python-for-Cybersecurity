import nmap   # import the python-nmap library (wrapper for Nmap tool)

# Create a scanner object we’ll use to run scans
scanner = nmap.PortScanner()

# Define the host we want to scan
host = "10.0.0.8"

# Run a scan:
# -Pn  → assume host is up (don’t rely on ping)
# -sT  → TCP connect scan (works without root)
# -p   → specify ports to scan (22=SSH, 80=HTTP, 443=HTTPS)
scanner.scan(hosts=host, arguments="-Pn -sT -p 22,80,443")

# Loop through all discovered hosts (usually just one here)
for h in scanner.all_hosts():
    # Print host IP and its DNS name (if any)
    print(f"Host: {h} ({scanner[h].hostname()})")

    # Print whether host is up/down
    print(f"Status: {scanner[h].state()}")

    # Get all detected protocols (like 'tcp' or 'udp')
    protos = scanner[h].all_protocols()

    if not protos:
        # If empty, no port results (maybe filtered or blocked)
        print("No protocol/port results recorded.")
    
    # For each protocol (e.g., tcp)
    for proto in protos:
        print(f"Protocol: {proto}")

        # For each port inside that protocol
        for port in sorted(scanner[h][proto].keys()):
            # Extract port state (open/closed/filtered)
            state = scanner[h][proto][port]["state"]
            print(f"Port: {port}\tState: {state}")
