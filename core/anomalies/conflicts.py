"""Utilities for detecting conflicting firewall rules.

This module defines simple functions used to determine whether two
`FirewallRule` objects may match the same packets and whether one rule
logically covers another. The main exported helper is
`detect_conflicting_rules`, which returns pairs of rules that are in the
same table/chain, have different actions, and whose match sets overlap
but neither rule fully covers the other (a likely conflict).
"""

from typing import List, Tuple
from core.models.firewall_rule import FirewallRule


def rules_overlap(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if the two rules can match at least one common packet.

    Two rules overlap if, for every relevant matching field, the values are
    compatible. A field is compatible when at least one of the rules leaves
    it unspecified (treated as a wildcard) or both rules specify the same
    value for that field.
    """
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        a = getattr(rule_a, field)
        b = getattr(rule_b, field)

        # If both rules specify this field and the values differ then the
        # rules cannot match the same packet for this attribute.
        if a is not None and b is not None and a != b:
            return False

    # No conflicting field was found, so there exists at least one packet
    # that both rules could match (i.e., they overlap).
    return True


def rule_covers(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    """Return True if `rule_a` covers `rule_b`.

    A rule A "covers" rule B when every field specified in A equals the
    corresponding field in B. Fields unspecified (None) in A are treated as
    wildcards and therefore are compatible with any value in B. In other
    words, A's match set is a superset (or equal) of B's match set.
    """
    fields = [
        "protocol", "src", "dst",
        "src_port", "dst_port",
        "in_iface", "out_iface"
    ]

    for field in fields:
        a = getattr(rule_a, field)
        b = getattr(rule_b, field)

        # If rule A specifies a value for this field and it does not equal
        # the corresponding value in rule B, then A does not cover B.
        if a is not None and a != b:
            return False

    return True


def detect_conflicting_rules(
    rules: List[FirewallRule]
) -> List[Tuple[FirewallRule, FirewallRule]]:
    """Detect pairs of rules that are likely in conflict.

    Two rules are considered conflicting if all of the following hold:
    - they belong to the same `table` and `chain`,
    - they have different `action` (e.g., ACCEPT vs DROP),
    - their match sets overlap (`rules_overlap`), and
    - neither rule covers the other (preventing simple shadowing/ordering
      differences from being reported as conflicts).

    Returns a list of tuples (rule1, rule2) for each detected conflict.
    """
    conflicts = []

    for i, r1 in enumerate(rules):
        for r2 in rules[i + 1:]:
            # Check same context (table and chain) and differing actions.
            if (
                r1.table == r2.table
                and r1.chain == r2.chain
                and r1.action != r2.action
                # Rules must be able to match the same packet(s).
                and rules_overlap(r1, r2)
                # Exclude cases where one rule logically covers the other
                # (these are handled as shadowing/redundancy elsewhere).
                and not rule_covers(r1, r2)
                and not rule_covers(r2, r1)
            ):
                conflicts.append((r1, r2))

    return conflicts
