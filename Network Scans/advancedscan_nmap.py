import nmap   # import the python-nmap library (wrapper for Nmap tool)

scanner = nmap.PortScanner()   # create a scanner object

target = "google.com"          # target host (domain or IP)
options = "-sS -O -Pn"         # Nmap options:
                               # -sS = SYN scan (stealth scan, needs root for full effect)
                               # -O  = OS detection (requires root/admin)
                               # -Pn = treat host as up (skip ping)

# Run the scan on the target with the given options
scanner.scan(target, arguments=options)

# Loop through all discovered hosts (usually just one: google.com)
for host in scanner.all_hosts():
    print(f"Host: {host} ({scanner[host].hostname()})")  # IP + resolved DNS name
    print(f"Status: {scanner[host].state()}")            # host state: up/down

    # If OS detection worked, print OS family and version (osclass info)
    if 'osclass' in scanner[host]:
        for osclass in scanner[host]['osclass']:
            print(f"OS Class: {osclass['osfamily']} - {osclass['osgen']}")

    # Loop through each protocol found (usually 'tcp')
    for protocol in scanner[host].all_protocols():
        print(f"Protocol: {protocol}")

        # Get all ports scanned under this protocol
        doors = scanner[host][protocol].keys()

        # Loop through ports and print their state (open/closed/filtered)
        for door in doors:
            print(f"Port: {door}\tState: {scanner[host][protocol][door]['state']}")
