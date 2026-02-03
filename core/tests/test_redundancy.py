from core.parsers.iptables_parser import IptablesParser
from core.anomalies.redundancy import detect_redundant_rules

sample = """
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

redundant = detect_redundant_rules(rules)

print("Redundant rules:")
for r in redundant:
    print(r)
