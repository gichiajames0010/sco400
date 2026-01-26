import subprocess
from core.parsers.iptables_parser import IptablesParser

# Get real iptables rules from the system
try:
    result = subprocess.run(
        ["sudo", "iptables-save"],
        capture_output=True,
        text=True,
        check=True
    )
    iptables_output = result.stdout
except subprocess.CalledProcessError as e:
    print(f"Error running iptables-save: {e}")
    iptables_output = ""
except FileNotFoundError:
    print("iptables-save not found or sudo not available")
    iptables_output = ""

parser = IptablesParser()
rules = parser.parse(iptables_output)

print(f"Total rules parsed: {len(rules)}\n")
for r in rules:
    print(r)
