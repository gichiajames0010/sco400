"""
Tests for redundancy detection logic.

Covers: exact duplicates, subnet redundancy, port range redundancy,
and cases that must NOT be flagged as redundant (different actions, etc.).
"""

import ipaddress
import pytest
from core.models.firewall_rule import FirewallRule
from core.anomalies.redundancy import detect_redundant_rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_rule(
    table="filter", chain="INPUT", action="ACCEPT",
    protocol=None, src=None, dst=None,
    src_port=None, dst_port=None,
    in_iface=None, out_iface=None,
    order=1, raw=""
) -> FirewallRule:
    return FirewallRule(
        table=table, chain=chain, action=action,
        protocol=protocol,
        src=ipaddress.ip_network(src, strict=False) if src else None,
        dst=ipaddress.ip_network(dst, strict=False) if dst else None,
        src_port=src_port, dst_port=dst_port,
        in_iface=in_iface, out_iface=out_iface,
        raw=raw, order=order
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRedundantRules:
    def test_exact_duplicate_flagged(self):
        """The second identical rule is redundant."""
        r1 = make_rule(protocol="tcp", dst_port=22, order=1)
        r2 = make_rule(protocol="tcp", dst_port=22, order=2)
        redundant = detect_redundant_rules([r1, r2])
        assert r2 in redundant
        assert r1 not in redundant

    def test_no_duplicates_not_flagged(self):
        r1 = make_rule(protocol="tcp", dst_port=22, order=1)
        r2 = make_rule(protocol="tcp", dst_port=80, order=2)
        assert detect_redundant_rules([r1, r2]) == []

    def test_different_actions_not_redundant(self):
        """Same match but different actions — this is a conflict, not redundancy."""
        r1 = make_rule(action="ACCEPT", protocol="tcp", dst_port=22, order=1)
        r2 = make_rule(action="DROP",   protocol="tcp", dst_port=22, order=2)
        assert detect_redundant_rules([r1, r2]) == []

    def test_subnet_redundancy(self):
        """A narrower subnet rule is redundant if a broader same-action rule precedes it."""
        r1 = make_rule(action="ACCEPT", src="10.0.0.0/8",   order=1)
        r2 = make_rule(action="ACCEPT", src="10.1.0.0/16",  order=2)
        redundant = detect_redundant_rules([r1, r2])
        assert r2 in redundant

    def test_different_subnets_not_redundant(self):
        r1 = make_rule(action="ACCEPT", src="10.0.0.0/8",    order=1)
        r2 = make_rule(action="ACCEPT", src="192.168.0.0/16", order=2)
        assert detect_redundant_rules([r1, r2]) == []

    def test_port_range_redundancy(self):
        """A single port rule is redundant when a covering port-range same-action rule precedes it."""
        r1 = make_rule(action="ACCEPT", protocol="tcp", dst_port=(80, 90),  order=1)
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=85,         order=2)
        redundant = detect_redundant_rules([r1, r2])
        assert r2 in redundant

    def test_port_range_not_redundant_when_partially_covered(self):
        """A range that extends beyond the covering range is NOT redundant."""
        r1 = make_rule(action="ACCEPT", protocol="tcp", dst_port=(80, 90),  order=1)
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=(85, 100), order=2)
        assert detect_redundant_rules([r1, r2]) == []

    def test_different_chains_not_redundant(self):
        r1 = make_rule(chain="INPUT",   protocol="tcp", dst_port=22, order=1)
        r2 = make_rule(chain="OUTPUT",  protocol="tcp", dst_port=22, order=2)
        assert detect_redundant_rules([r1, r2]) == []

    def test_empty_input(self):
        assert detect_redundant_rules([]) == []

    def test_single_rule_not_redundant(self):
        assert detect_redundant_rules([make_rule()]) == []
