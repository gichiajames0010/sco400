from typing import List
from core.models.firewall_rule import FirewallRule
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules

def optimize_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    redundant = {id(r) for r in detect_redundant_rules(rules)}
    shadowed = {id(r) for r in detect_shadowed_rules(rules)}

    optimized = [
        rule for rule in rules
        if id(rule) not in redundant and id(rule) not in shadowed
    ]

    return optimized
