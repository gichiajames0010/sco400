from typing import List, Tuple
from core.models.firewall_rule import FirewallRule

def rules_overlap(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        a = getattr(rule_a, field)
        b = getattr(rule_b, field)

        if a is not None and b is not None and a != b:
            return False

    return True


def rule_covers(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        a = getattr(rule_a, field)
        b = getattr(rule_b, field)

        if a is not None and a != b:
            return False

    return True


def detect_conflicting_rules(
    rules: List[FirewallRule]
) -> List[Tuple[FirewallRule, FirewallRule]]:
    conflicts = []

    for i, r1 in enumerate(rules):
        for r2 in rules[i + 1:]:
            if (
                r1.table == r2.table
                and r1.chain == r2.chain
                and r1.action != r2.action
                and rules_overlap(r1, r2)
                and not rule_covers(r1, r2)
                and not rule_covers(r2, r1)
            ):
                conflicts.append((r1, r2))

    return conflicts
