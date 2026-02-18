"""Detect rules that are shadowed by earlier rules, with subnet awareness."""

from typing import List
from core.models.firewall_rule import FirewallRule
import ipaddress


def port_covers(val_a, val_b) -> bool:
    """Return True if port/range val_a covers port/range val_b."""
    if val_a is None:
        return True  # wildcard covers everything
    if val_b is None:
        return False # specific cannot cover wildcard

    # Normalize to tuple (start, end)
    range_a = (val_a, val_a) if isinstance(val_a, int) else val_a
    range_b = (val_b, val_b) if isinstance(val_b, int) else val_b

    return range_a[0] <= range_b[0] and range_a[1] >= range_b[1]


def field_covers(val_a, val_b) -> bool:
    """Check if field in rule_a covers the field in rule_b.

    - For IP networks, rule_a covers rule_b if rule_b is a subnet of rule_a.
    - For ports, check range inclusion.
    - For other fields, coverage means either wildcard (None) or exact match.
    """
    if isinstance(val_a, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if val_b is None:
            # a specific network cannot cover a wildcard
            return False
        return val_b.subnet_of(val_a)
    
    # Check for ports/ranges (int or tuple)
    if isinstance(val_a, (int, tuple)) or isinstance(val_b, (int, tuple)):
        return port_covers(val_a, val_b)

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
