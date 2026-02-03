from core.parsers.iptables_parser import IptablesParser
from core.anomalies.conflicts import detect_conflicting_rules

sample = """
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --sport 22 -j DROP
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

conflicts = detect_conflicting_rules(rules)

print("Conflicting rules:")
for r1, r2 in conflicts:
    print(r1)
    print(r2)
    print("----")
