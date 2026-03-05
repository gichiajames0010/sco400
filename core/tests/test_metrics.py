"""
Tests for compute_metrics.

Covers: correct counts for known inputs, empty ruleset (zero division guard),
and presence of all expected keys in the returned dict.
"""

import pytest
from core.models.firewall_rule import FirewallRule
from core.parsers.iptables_parser import IptablesParser
from core.optimizer.metrics import compute_metrics


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse(text: str):
    return IptablesParser().parse(text)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    def test_all_keys_present(self):
        """The returned dict must always contain every expected key."""
        metrics = compute_metrics([])
        expected_keys = {
            "total_rules", "redundant_rules", "shadowed_rules",
            "conflicting_pairs", "optimized_rule_count", "reduction_ratio",
        }
        assert expected_keys == set(metrics.keys())

    def test_empty_input_zero_counts(self):
        metrics = compute_metrics([])
        assert metrics["total_rules"] == 0
        assert metrics["redundant_rules"] == 0
        assert metrics["shadowed_rules"] == 0
        assert metrics["conflicting_pairs"] == 0
        assert metrics["optimized_rule_count"] == 0

    def test_empty_input_zero_ratio(self):
        """reduction_ratio must be 0 for empty input — no division by zero."""
        metrics = compute_metrics([])
        assert metrics["reduction_ratio"] == 0.0

    def test_total_rules_count(self):
        rules = parse("*filter\n-A INPUT -j ACCEPT\n-A INPUT -j DROP\nCOMMIT")
        metrics = compute_metrics(rules)
        assert metrics["total_rules"] == 2

    def test_redundant_count(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"  # duplicate
            "COMMIT"
        )
        metrics = compute_metrics(rules)
        assert metrics["redundant_rules"] == 1

    def test_shadowed_count(self):
        """A general DROP before a specific ACCEPT — one shadowed rule."""
        rules = parse(
            "*filter\n"
            "-A INPUT -j DROP\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT"
        )
        metrics = compute_metrics(rules)
        assert metrics["shadowed_rules"] == 1

    def test_optimized_count_reduces_by_redundant_and_shadowed(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -j DROP\n"                           # rule 1
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"       # rule 2 — shadowed
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"       # rule 3 — shadowed
            "COMMIT"
        )
        metrics = compute_metrics(rules)
        # 3 total — 2 shadowed = 1 optimized
        assert metrics["optimized_rule_count"] == metrics["total_rules"] - metrics["shadowed_rules"] - metrics["redundant_rules"]

    def test_reduction_ratio_between_0_and_1(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "COMMIT"
        )
        ratio = compute_metrics(rules)["reduction_ratio"]
        assert 0.0 <= ratio <= 1.0

    def test_no_anomalies_zero_reduction(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 80 -j ACCEPT\n"
            "COMMIT"
        )
        metrics = compute_metrics(rules)
        assert metrics["redundant_rules"] == 0
        assert metrics["shadowed_rules"] == 0
        assert metrics["reduction_ratio"] == 0.0
