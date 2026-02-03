from core.parsers.iptables_parser import IptablesParser
from core.anomalies.shadowing import detect_shadowed_rules

sample = """
*filter
-A INPUT -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

shadowed = detect_shadowed_rules(rules)

print("Shadowed rules:")
for r in shadowed:
    print(r)
