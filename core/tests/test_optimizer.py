"""
Tests for the rule optimizer.

Covers: redundant rule removal, shadowed rule removal, conflict preservation
(conflicts are NOT removed), and preservation of original rule order.
"""

import pytest
from core.parsers.iptables_parser import IptablesParser
from core.optimizer.rule_optimizer import optimize_rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse(text: str):
    return IptablesParser().parse(text)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestOptimizeRules:
    def test_redundant_rule_removed(self):
        """The duplicate rule must be absent from the optimized output."""
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT"
        )
        optimized = optimize_rules(rules)
        assert len(optimized) == 1

    def test_shadowed_rule_removed(self):
        """A rule shadowed by a preceding DROP-all must not appear in the result."""
        rules = parse(
            "*filter\n"
            "-A INPUT -j DROP\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT"
        )
        optimized = optimize_rules(rules)
        assert len(optimized) == 1
        assert optimized[0].action == "DROP"

    def test_conflicting_rules_preserved(self):
        """Conflicting rules are NOT removed by the optimizer — only anomalies are."""
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 443 -j DROP\n"
            "COMMIT"
        )
        # No redundancy or shadowing — all rules must survive
        optimized = optimize_rules(rules)
        assert len(optimized) == 2

    def test_order_preserved(self):
        """Rules that survive must retain their original relative order."""
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
            "COMMIT"
        )
        optimized = optimize_rules(rules)
        orders = [r.order for r in optimized]
        assert orders == sorted(orders)

    def test_empty_input(self):
        assert optimize_rules([]) == []

    def test_single_rule_preserved(self):
        rules = parse("*filter\n-A INPUT -j DROP\nCOMMIT")
        assert len(optimize_rules(rules)) == 1

    def test_all_rules_unique_preserved(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j DROP\n"
            "COMMIT"
        )
        optimized = optimize_rules(rules)
        assert len(optimized) == len(rules)
