"""Utilities to detect redundant firewall rules.

The redundancy detector identifies exact duplicate rules — rules that
match on the same table/chain, the same match fields and the same action.
The first occurrence of a rule is treated as authoritative and later
identical rules are considered redundant (they are returned by
`detect_redundant_rules`).
"""

from typing import List
from core.models.firewall_rule import FirewallRule


def detect_redundant_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Return the list of rules that are duplicates of earlier rules.

    A rule is treated as a duplicate if it has identical values for the
    following attributes: `table`, `chain`, `protocol`, `src`, `dst`,
    `src_port`, `dst_port`, `in_iface`, `out_iface`, and `action`.

    The function preserves the first-seen rule and collects later identical
    rules in the order they appear in the input list.
    """
    redundant: List[FirewallRule] = []
    # `seen` maps a tuple key describing the rule to the first-seen rule
    seen = {}

    for rule in rules:
        # Compose a key that represents the rule's identity for redundancy
        # checking. Fields left as None are treated as literal values here;
        # two rules are considered identical only if their attributes match
        # exactly.
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

        # If we've encountered this exact key before, the current rule is
        # redundant; otherwise record it as the first occurrence.
        if key in seen:
            redundant.append(rule)
        else:
            seen[key] = rule

    return redundant
