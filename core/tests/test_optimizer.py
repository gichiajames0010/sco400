from core.parsers.iptables_parser import IptablesParser
from core.optimizer.rule_optimizer import optimize_rules

sample = """
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

optimized = optimize_rules(rules)

print("Optimized rules:")
for r in optimized:
    print(r)
