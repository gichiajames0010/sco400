"""
Tests for shadowing detection logic.

Covers: basic shadowing, port range shadowing (the bug we fixed),
same-action rules (should NOT be shadowed), and the port_covers helper.
"""

import ipaddress
import pytest
from core.models.firewall_rule import FirewallRule
from core.anomalies.shadowing import detect_shadowed_rules, port_covers, rule_covers


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
# port_covers helper
# ---------------------------------------------------------------------------

class TestPortCovers:
    def test_wildcard_covers_everything(self):
        assert port_covers(None, 80) is True
        assert port_covers(None, (80, 90)) is True
        assert port_covers(None, None) is True

    def test_specific_does_not_cover_wildcard(self):
        assert port_covers(80, None) is False

    def test_range_covers_single_port(self):
        assert port_covers((80, 90), 85) is True

    def test_range_covers_sub_range(self):
        assert port_covers((80, 100), (85, 95)) is True

    def test_range_does_not_cover_outside(self):
        assert port_covers((80, 90), 91) is False

    def test_range_does_not_cover_overlapping_range(self):
        assert port_covers((80, 90), (85, 100)) is False

    def test_single_port_covers_itself(self):
        assert port_covers(80, 80) is True

    def test_single_port_does_not_cover_different_port(self):
        assert port_covers(80, 81) is False


# ---------------------------------------------------------------------------
# detect_shadowed_rules
# ---------------------------------------------------------------------------

class TestShadowedRules:
    def test_basic_shadowing(self):
        """A general DROP before a specific ACCEPT shadows the ACCEPT."""
        r1 = make_rule(action="DROP", order=1)   # wildcard — drops everything
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=22, order=2)
        shadowed = detect_shadowed_rules([r1, r2])
        assert r2 in shadowed
        assert r1 not in shadowed

    def test_same_action_not_shadowed(self):
        """Same action → redundant, not shadowed."""
        r1 = make_rule(action="ACCEPT", order=1)
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=22, order=2)
        shadowed = detect_shadowed_rules([r1, r2])
        assert shadowed == []

    def test_port_range_shadows_single_port(self):
        """DROP TCP 80:90 should shadow ACCEPT TCP 85."""
        r1 = make_rule(action="DROP", protocol="tcp", dst_port=(80, 90), order=1)
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=85, order=2)
        shadowed = detect_shadowed_rules([r1, r2])
        assert r2 in shadowed

    def test_no_shadowing_different_chains(self):
        """Rules in different chains cannot shadow each other."""
        r1 = make_rule(chain="INPUT", action="DROP", order=1)
        r2 = make_rule(chain="OUTPUT", action="ACCEPT", order=2)
        assert detect_shadowed_rules([r1, r2]) == []

    def test_no_shadowing_when_later_is_broader(self):
        """A specific rule followed by a general one — the general one is NOT shadowed."""
        r1 = make_rule(action="DROP", protocol="tcp", dst_port=22, order=1)
        r2 = make_rule(action="ACCEPT", order=2)  # broad rule
        shadowed = detect_shadowed_rules([r1, r2])
        # r2 is broader than r1 so r1 does not cover r2
        assert r2 not in shadowed

    def test_subnet_shadowing(self):
        """A broader subnet DROP shadows a narrower subnet ACCEPT."""
        r1 = make_rule(action="DROP", src="10.0.0.0/8", order=1)
        r2 = make_rule(action="ACCEPT", src="10.1.0.0/16", order=2)
        shadowed = detect_shadowed_rules([r1, r2])
        assert r2 in shadowed

    def test_empty_input(self):
        assert detect_shadowed_rules([]) == []
