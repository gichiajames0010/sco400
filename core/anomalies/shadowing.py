"""Detect rules that are shadowed by earlier rules, with subnet awareness."""

from typing import List
from core.models.firewall_rule import FirewallRule
import ipaddress


def field_covers(val_a, val_b) -> bool:
    """Check if field in rule_a covers the field in rule_b.

    - For IP networks, rule_a covers rule_b if rule_b is a subnet of rule_a.
    - For other fields, coverage means either wildcard (None) or exact match.
    """
    if isinstance(val_a, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if val_b is None:
            # a specific network cannot cover a wildcard
            return False
        return val_b.subnet_of(val_a)
    # If rule_a does not specify the field, it covers any value
    if val_a is None:
        return True
    # Otherwise, coverage requires exact match
    return val_a == val_b


def rule_covers(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if `rule_a` covers `rule_b`.

    Coverage here means that for every match field, either `rule_a` leaves
    the field unspecified (wildcard) or the value in `rule_a` covers the
    value in `rule_b`.
    """
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    return all(field_covers(getattr(rule_a, f), getattr(rule_b, f)) for f in fields)


def detect_shadowed_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Return the list of rules that are shadowed by earlier rules.

    For each rule, checks previous rules in the same table/chain that have
    a different action. If any such previous rule covers the current rule,
    the current rule is shadowed.
    """
    shadowed: List[FirewallRule] = []

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
