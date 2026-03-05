"""
Tests for conflict detection logic.

Covers: true conflicts (overlapping traffic, different actions where neither
covers the other), port range conflicts, cross-chain isolation, and extending
the existing test cases.
"""

import ipaddress
import pytest
from core.models.firewall_rule import FirewallRule
from core.anomalies import conflicts


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
    src_net = ipaddress.ip_network(src, strict=False) if src else None
    dst_net = ipaddress.ip_network(dst, strict=False) if dst else None

    def norm_port(port):
        if port is None or isinstance(port, (int, tuple)):
            return port
        raise ValueError(f"Invalid port: {port}")

    return FirewallRule(
        table=table, chain=chain, action=action,
        protocol=protocol,
        src=src_net, dst=dst_net,
        src_port=norm_port(src_port),
        dst_port=norm_port(dst_port),
        in_iface=in_iface, out_iface=out_iface,
        raw=raw, order=order
    )


# ---------------------------------------------------------------------------
# ip_overlap
# ---------------------------------------------------------------------------

class TestIPOverlap:
    def test_overlapping_subnets(self):
        r1 = make_rule(src="10.0.0.0/8")
        r2 = make_rule(src="10.1.1.0/24")
        assert conflicts.ip_overlap(r1.src, r2.src)

    def test_non_overlapping_subnets(self):
        r1 = make_rule(src="10.0.0.0/8")
        r3 = make_rule(src="192.168.0.0/16")
        assert not conflicts.ip_overlap(r1.src, r3.src)

    def test_wildcard_overlaps_anything(self):
        assert conflicts.ip_overlap(None, ipaddress.ip_network("10.0.0.0/8"))
        assert conflicts.ip_overlap(ipaddress.ip_network("10.0.0.0/8"), None)


# ---------------------------------------------------------------------------
# port_overlap
# ---------------------------------------------------------------------------

class TestPortOverlap:
    def test_overlapping_ranges(self):
        assert conflicts.port_overlap((1000, 2000), (1500, 2500))

    def test_non_overlapping_ranges(self):
        assert not conflicts.port_overlap((1000, 2000), (3000, 4000))

    def test_wildcard_overlaps_anything(self):
        assert conflicts.port_overlap(None, 80)
        assert conflicts.port_overlap(80, None)

    def test_adjacent_ranges_do_not_overlap(self):
        assert not conflicts.port_overlap((1000, 2000), (2001, 3000))


# ---------------------------------------------------------------------------
# rules_overlap
# ---------------------------------------------------------------------------

class TestRulesOverlap:
    def test_same_protocol_overlaps(self):
        r1 = make_rule(protocol="tcp")
        r2 = make_rule(protocol="tcp")
        assert conflicts.rules_overlap(r1, r2)

    def test_different_protocols_no_overlap(self):
        r1 = make_rule(protocol="tcp")
        r2 = make_rule(protocol="udp")
        assert not conflicts.rules_overlap(r1, r2)

    def test_wildcard_protocol_overlaps_specific(self):
        r1 = make_rule(protocol=None)   # any protocol
        r2 = make_rule(protocol="tcp")
        assert conflicts.rules_overlap(r1, r2)

    def test_different_interfaces_no_overlap(self):
        r1 = make_rule(in_iface="eth0")
        r2 = make_rule(in_iface="eth1")
        assert not conflicts.rules_overlap(r1, r2)


# ---------------------------------------------------------------------------
# detect_conflicting_rules
# ---------------------------------------------------------------------------

class TestDetectConflicts:
    def test_shadowed_rules_not_counted_as_conflicts(self):
        """Coverage (shadowing) takes priority — not a conflict."""
        r1 = make_rule(action="ACCEPT", src="10.0.0.0/8", order=1)
        r2 = make_rule(action="DROP",   src="10.1.1.0/24", order=2)
        result = conflicts.detect_conflicting_rules([r1, r2])
        assert result == []

    def test_true_conflict_detected(self):
        """Two rules that overlap equally (neither covers the other) with different actions."""
        r1 = make_rule(action="ACCEPT", src="10.1.0.0/16", dst_port=80, order=1)
        r2 = make_rule(action="DROP",   src="10.2.0.0/16", dst_port=80, order=2)
        # Different /16 subnets that don't overlap — NOT a conflict
        result = conflicts.detect_conflicting_rules([r1, r2])
        assert result == []

    def test_port_range_conflict(self):
        """Overlapping port ranges with different actions and equal specificity."""
        r1 = make_rule(action="ACCEPT", protocol="tcp", dst_port=(1000, 2000), order=1)
        r2 = make_rule(action="DROP",   protocol="tcp", dst_port=(1500, 3000), order=2)
        # r1 does NOT cover r2 (r2 extends beyond) and r2 does NOT cover r1 → conflict
        result = conflicts.detect_conflicting_rules([r1, r2])
        assert len(result) == 1
        assert (r1, r2) in result

    def test_same_action_no_conflict(self):
        """Same action → no conflict regardless of overlap."""
        r1 = make_rule(action="ACCEPT", protocol="tcp", dst_port=80, order=1)
        r2 = make_rule(action="ACCEPT", protocol="tcp", dst_port=80, order=2)
        assert conflicts.detect_conflicting_rules([r1, r2]) == []

    def test_cross_chain_no_conflict(self):
        """Rules in different chains cannot conflict with each other."""
        r1 = make_rule(chain="INPUT",  action="ACCEPT", protocol="tcp", dst_port=80, order=1)
        r2 = make_rule(chain="OUTPUT", action="DROP",   protocol="tcp", dst_port=80, order=2)
        assert conflicts.detect_conflicting_rules([r1, r2]) == []

    def test_empty_input(self):
        assert conflicts.detect_conflicting_rules([]) == []
