"""Simple rule optimizer helpers.

This module provides a lightweight optimizer that removes rules flagged as
redundant or shadowed by the analyzer modules. The optimizer preserves the
original rule order and performs a conservative filter: it only removes
rules that are exact duplicates or are shadowed by earlier rules. It does
not attempt to resolve conflicts or reorder rules.
"""

from typing import List
from core.models.firewall_rule import FirewallRule
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules


def optimize_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Return a new list with redundant and shadowed rules removed.

    The function asks the analyzers for redundant and shadowed rules and
    then filters the original list, preserving order. We use `id()` to
    compare identity because the analyzers return rule objects from the
    original input; comparing identities avoids depending on equality
    implementations and ensures the correct instances are filtered out.

    Note: This optimizer is intentionally simple and conservative. It does
    not attempt to fix conflicts or perform rule merging/reordering.
    """
    # Build a set of identities for rules to remove for O(1) membership
    # tests while preserving the original order in the final list.
    redundant = {id(r) for r in detect_redundant_rules(rules)}
    shadowed = {id(r) for r in detect_shadowed_rules(rules)}

    # Keep only rules that are not marked as redundant or shadowed. Using
    # `id(rule)` here ensures we are filtering the exact instances
    # identified by the analyzers.
    optimized = [
        rule for rule in rules
        if id(rule) not in redundant and id(rule) not in shadowed
    ]

    return optimized
