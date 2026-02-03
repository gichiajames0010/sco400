from core.parsers.iptables_parser import IptablesParser
from core.optimizer.metrics import compute_metrics

sample = """
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

metrics = compute_metrics(rules)

print(metrics)
