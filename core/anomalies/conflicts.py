"""Detect conflicting firewall rules.

Two rules conflict if they overlap in match criteria (IP/network,
ports, protocol, interfaces) but have different actions, and neither
fully shadows the other.
"""

from typing import List, Tuple, Union
import ipaddress
from core.models.firewall_rule import FirewallRule
from core.anomalies import shadowing


def ip_overlap(net_a: Union[ipaddress.IPv4Network, None],
               net_b: Union[ipaddress.IPv4Network, None]) -> bool:
    """Return True if two networks overlap or either is unspecified."""
    if net_a is None or net_b is None:
        return True  # unspecified matches anything
    return net_a.overlaps(net_b)


def port_overlap(port_a: Union[int, Tuple[int, int], None],
                 port_b: Union[int, Tuple[int, int], None]) -> bool:
    """Return True if two ports or port ranges overlap or either is unspecified."""
    if port_a is None or port_b is None:
        return True

    # Normalize single port to range
    if isinstance(port_a, int):
        port_a = (port_a, port_a)
    if isinstance(port_b, int):
        port_b = (port_b, port_b)

    start_a, end_a = port_a
    start_b, end_b = port_b

    return not (end_a < start_b or end_b < start_a)


def interfaces_overlap(iface_a: Union[str, None],
                       iface_b: Union[str, None]) -> bool:
    """Return True if interfaces overlap or either is unspecified."""
    return iface_a is None or iface_b is None or iface_a == iface_b


def rules_overlap(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if two rules overlap in match criteria."""
    return (
        ip_overlap(rule_a.src, rule_b.src) and
        ip_overlap(rule_a.dst, rule_b.dst) and
        port_overlap(rule_a.src_port, rule_b.src_port) and
        port_overlap(rule_a.dst_port, rule_b.dst_port) and
        (rule_a.protocol is None or rule_b.protocol is None or rule_a.protocol == rule_b.protocol) and
        interfaces_overlap(rule_a.in_iface, rule_b.in_iface) and
        interfaces_overlap(rule_a.out_iface, rule_b.out_iface)
    )


def rule_conflicts(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if two rules conflict: they overlap but have different actions."""
    if rule_a.action == rule_b.action:
        return False  # same action is not a conflict
    if shadowing.rule_covers(rule_a, rule_b) or shadowing.rule_covers(rule_b, rule_a):
        return False  # shadowed rules are not counted as conflicts
    return rules_overlap(rule_a, rule_b)


def detect_conflicting_rules(rules: List[FirewallRule]) -> List[Tuple[FirewallRule, FirewallRule]]:
    """Return a list of all pairs of conflicting rules."""
    conflicts_list: List[Tuple[FirewallRule, FirewallRule]] = []

    n = len(rules)
    for i in range(n):
        for j in range(i + 1, n):
            r1 = rules[i]
            r2 = rules[j]

            # Only check rules in the same table/chain
            if r1.table != r2.table or r1.chain != r2.chain:
                continue

            if rule_conflicts(r1, r2):
                conflicts_list.append((r1, r2))

    return conflicts_list
