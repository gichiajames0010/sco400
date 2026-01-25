from core.parsers.iptables_parser import IptablesParser

sample = """
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

parser = IptablesParser()
rules = parser.parse(sample)

for r in rules:
    print(r)
