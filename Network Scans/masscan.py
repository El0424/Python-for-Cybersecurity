import subprocess   # lets Python run external system commands

target = "10.0.0.1"      # the IP address you want to scan
ports = "80,443,22"      # the ports to check (HTTP, HTTPS, SSH)

# build the masscan command string
command = f"masscan {target} -p{ports} --rate=1000"

# start the masscan process (split turns the string into list for Popen)
process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)

# wait for the process to finish and capture its output
output, error = process.communicate()

# print the scan results as text
print(output.decode())
