"""Detect rules that are shadowed by earlier rules.

This module provides a small utility to determine if a rule is "shadowed"
by a previously-occurring rule in the same table/chain. A later rule is
considered shadowed when an earlier rule with a different action covers
it (i.e., the earlier rule matches every packet the later rule would
match), meaning the later rule will never be reached.
"""

from typing import List
from core.models.firewall_rule import FirewallRule


def rule_covers(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if `rule_a` covers `rule_b`.

    Coverage here means that for every considered match field, either
    `rule_a` leaves the field unspecified (wildcard) or the value in
    `rule_a` equals the value in `rule_b`. If `rule_a` specifies a value
    that differs from `rule_b` for any field, then `rule_a` does not cover
    `rule_b`.
    """
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        val_a = getattr(rule_a, field)
        val_b = getattr(rule_b, field)

        # If rule_a explicitly specifies a value for this field and that
        # value differs from rule_b's value, then rule_a cannot cover
        # rule_b.
        if val_a is not None and val_a != val_b:
            return False

    return True


def detect_shadowed_rules(rules: List[FirewallRule]) -> List[FirewallRule]:
    """Return the list of rules that are shadowed by earlier rules.

    For each rule, the function checks previous rules in the list to see
    if any of them are in the same `table` and `chain`, have a different
    `action`, and cover the current rule. If such a previous rule exists,
    the current rule is considered shadowed and added to the result.
    """
    shadowed: List[FirewallRule] = []

    for i, current in enumerate(rules):
        # Only previous rules (earlier in the list) can shadow the current
        # rule; iterate over them and stop at the first shadower found.
        for previous in rules[:i]:
            if (
                current.table == previous.table
                and current.chain == previous.chain
                # A shadower must have a different action (e.g., DROP vs
                # ACCEPT) so that the earlier rule prevents the later from
                # ever executing.
                and previous.action != current.action
                # And it must cover the current rule (match superset).
                and rule_covers(previous, current)
            ):
                shadowed.append(current)
                break

    return shadowed
