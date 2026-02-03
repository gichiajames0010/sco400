from typing import List
from core.models.firewall_rule import FirewallRule

def detect_redundant_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    redundant = []
    seen = {}

    for rule in rules:
        key = (
            rule.table,
            rule.chain,
            rule.protocol,
            rule.src,
            rule.dst,
            rule.src_port,
            rule.dst_port,
            rule.in_iface,
            rule.out_iface,
            rule.action
        )

        if key in seen:
            redundant.append(rule)
        else:
            seen[key] = rule

    return redundant
