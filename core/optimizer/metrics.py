"""Metrics used by the optimizer to quantify rulebase quality.

This module provides simple metrics that count redundant, shadowed and
conflicting rules and compute a small optimization summary. These metrics
are intentionally straightforward and designed for reporting and
regression tests rather than as a comprehensive scoring function.
"""

from typing import Dict, List
from core.models.firewall_rule import FirewallRule
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules
from core.anomalies.conflicts import detect_conflicting_rules


def compute_metrics(rules: List[FirewallRule]) -> Dict:
    """Compute a set of metrics describing the given rule list.

    Returns a dictionary containing:
      - total_rules: total number of rules provided
      - redundant_rules: number of exact duplicates found (later duplicates)
      - shadowed_rules: number of rules shadowed by earlier rules
      - conflicting_pairs: number of conflicting rule pairs
      - optimized_rule_count: number of rules remaining after removing
        redundant and shadowed rules (a simple optimistic estimate)
      - reduction_ratio: fraction of rules that could be removed based on
        redundancy/shadowing (value between 0 and 1). Zero is returned if
        the input list is empty to avoid a division-by-zero error.
    """
    # Detect specific anomaly types using helper analyzers.
    redundant = detect_redundant_rules(rules)
    shadowed = detect_shadowed_rules(rules)
    conflicts = detect_conflicting_rules(rules)

    # A simple optimistic estimate of rules remaining after optimization:
    # treat all redundant and shadowed rules as removable. Note that this
    # does not attempt to resolve conflicts or consider rule reordering.
    optimized_count = len(rules) - len(redundant) - len(shadowed)

    # Compute the reduction ratio safely; when `rules` is empty return 0.
    reduction_ratio = (
        (len(rules) - optimized_count) / len(rules)
        if rules else 0
    )

    return {
        "total_rules": len(rules),
        "redundant_rules": len(redundant),
        "shadowed_rules": len(shadowed),
        "conflicting_pairs": len(conflicts),
        "optimized_rule_count": optimized_count,
        "reduction_ratio": reduction_ratio,
    }