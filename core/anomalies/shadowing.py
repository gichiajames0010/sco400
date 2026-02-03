from typing import List
from core.models.firewall_rule import FirewallRule

def rule_covers(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        val_a = getattr(rule_a, field)
        val_b = getattr(rule_b, field)

        if val_a is not None and val_a != val_b:
            return False

    return True


def detect_shadowed_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    shadowed = []

    for i, current in enumerate(rules):
        for previous in rules[:i]:
            if (
                current.table == previous.table
                and current.chain == previous.chain
                and previous.action != current.action
                and rule_covers(previous, current)
            ):
                shadowed.append(current)
                break

    return shadowed
