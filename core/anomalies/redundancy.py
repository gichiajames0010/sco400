"""Utilities to detect redundant firewall rules with subnet awareness."""

from typing import List, Tuple
from core.models.firewall_rule import FirewallRule
import ipaddress


def is_field_equal(a, b):
    """Compare non-IP fields; None matches only None."""
    return a == b


def is_network_redundant(new_net: ipaddress.IPv4Network, existing_net: ipaddress.IPv4Network) -> bool:
    """Check if `new_net` is fully contained within `existing_net`."""
    if new_net is None and existing_net is None:
        return True
    if new_net is None or existing_net is None:
        return False
    return new_net.subnet_of(existing_net)


def rules_match(new_rule: FirewallRule, existing_rule: FirewallRule) -> bool:
    """Check if two rules are redundant."""
    return (
        is_field_equal(new_rule.table, existing_rule.table) and
        is_field_equal(new_rule.chain, existing_rule.chain) and
        is_field_equal(new_rule.protocol, existing_rule.protocol) and
        is_network_redundant(new_rule.src, existing_rule.src) and
        is_network_redundant(new_rule.dst, existing_rule.dst) and
        is_field_equal(new_rule.src_port, existing_rule.src_port) and
        is_field_equal(new_rule.dst_port, existing_rule.dst_port) and
        is_field_equal(new_rule.in_iface, existing_rule.in_iface) and
        is_field_equal(new_rule.out_iface, existing_rule.out_iface) and
        is_field_equal(new_rule.action, existing_rule.action)
    )


def detect_redundant_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Return the list of rules that are duplicates (redundant) of earlier rules.

    A rule is treated as redundant if it is fully contained in a previous
    rule considering network subnets for src/dst.
    """
    redundant: List[FirewallRule] = []
    seen: List[FirewallRule] = []

    for rule in rules:
        # If any previously seen rule fully covers this rule, it's redundant
        if any(rules_match(rule, r) for r in seen):
            redundant.append(rule)
        else:
            seen.append(rule)

    return redundant
