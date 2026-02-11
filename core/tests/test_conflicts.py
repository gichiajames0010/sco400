import ipaddress
import pytest
from core.models.firewall_rule import FirewallRule
from core.anomalies import conflicts

# Helper to create FirewallRule objects
def make_rule(
    table="filter",
    chain="INPUT",
    action="ACCEPT",
    protocol=None,
    src=None,
    dst=None,
    src_port=None,
    dst_port=None,
    in_iface=None,
    out_iface=None,
    order=1,
    raw="",
) -> FirewallRule:
    """
    Helper to create FirewallRule objects for testing.

    - IP addresses/subnets are converted to ipaddress.IPv4Network objects.
    - Ports can be:
        * int (single port)
        * tuple (start, end) range
        * None (unspecified/wildcard)
    """
    # Convert src/dst to ip_network objects if given
    src_net = ipaddress.ip_network(src) if src else None
    dst_net = ipaddress.ip_network(dst) if dst else None

    # Normalize ports
    def normalize_port(port):
        if port is None:
            return None
        if isinstance(port, int):
            return port
        if isinstance(port, tuple) and len(port) == 2:
            return port
        raise ValueError(f"Invalid port specification: {port}")

    return FirewallRule(
        table=table,
        chain=chain,
        action=action,
        protocol=protocol,
        src=src_net,
        dst=dst_net,
        src_port=normalize_port(src_port),
        dst_port=normalize_port(dst_port),
        in_iface=in_iface,
        out_iface=out_iface,
        raw=raw,
        order=order
    )
# -----------------------------
# Tests for rules_overlap
# -----------------------------
def test_rules_overlap_ip():
    r1 = make_rule(src="10.0.0.0/8")
    r2 = make_rule(src="10.1.1.0/24")
    r3 = make_rule(src="192.168.0.0/16")

    assert conflicts.rules_overlap(r1, r2)
    assert not conflicts.rules_overlap(r1, r3)

def test_rules_overlap_port():
    r1 = make_rule(dst_port=(1000, 2000))
    r2 = make_rule(dst_port=(1500, 2500))
    r3 = make_rule(dst_port=(3000, 4000))

    assert conflicts.rules_overlap(r1, r2)
    assert not conflicts.rules_overlap(r1, r3)

def test_rules_overlap_protocol():
    r1 = make_rule(protocol="tcp")
    r2 = make_rule(protocol="tcp")
    r3 = make_rule(protocol="udp")

    assert conflicts.rules_overlap(r1, r2)
    assert not conflicts.rules_overlap(r1, r3)

def test_rules_overlap_interfaces():
    r1 = make_rule(in_iface="eth0", out_iface=None)
    r2 = make_rule(in_iface="eth0")
    r3 = make_rule(in_iface="eth1")

    assert conflicts.rules_overlap(r1, r2)
    assert not conflicts.rules_overlap(r1, r3)

# -----------------------------
# Tests for rule_covers
# -----------------------------
def test_rule_covers_ip():
    r1 = make_rule(src="10.0.0.0/8")
    r2 = make_rule(src="10.1.1.0/24")
    r3 = make_rule(src="192.168.0.0/16")

    assert conflicts.rule_covers(r1, r2)
    assert not conflicts.rule_covers(r2, r1)
    assert not conflicts.rule_covers(r1, r3)

def test_rule_covers_ports():
    r1 = make_rule(dst_port=(1000, 2000))
    r2 = make_rule(dst_port=1500)
    r3 = make_rule(dst_port=(500, 1500))

    assert conflicts.rule_covers(r1, r2)
    assert not conflicts.rule_covers(r2, r1)
    assert not conflicts.rule_covers(r1, r3)

def test_rule_covers_protocol():
    r1 = make_rule(protocol="tcp")
    r2 = make_rule(protocol="tcp")
    r3 = make_rule(protocol="udp")

    assert conflicts.rule_covers(r1, r2)
    assert not conflicts.rule_covers(r1, r3)

# -----------------------------
# Tests for detect_conflicting_rules
# -----------------------------
def test_detect_conflicting_rules_basic():
    r1 = make_rule(action="ACCEPT", src="10.0.0.0/8")
    r2 = make_rule(action="DROP", src="10.1.1.0/24")  # covered by r1
    r3 = make_rule(action="ACCEPT", src="192.168.0.0/16")

    conflicts_list = conflicts.detect_conflicting_rules([r1, r2, r3])
    # Shadowed rules (one covers the other) are not counted as conflicts
    assert conflicts_list == []

def test_multi_field_conflict():
    r1 = make_rule(
        src="10.0.0.0/8",
        dst="172.16.0.0/12",
        dst_port=(1000, 2000),
        protocol="tcp",
        action="ACCEPT",
    )
    r2 = make_rule(
        src="10.1.0.0/16",
        dst="172.16.5.0/24",
        dst_port=1500,
        protocol="tcp",
        action="DROP",
    )
    r3 = make_rule(
        src="192.168.1.0/24",
        dst="172.16.0.0/12",
        dst_port=1500,
        protocol="tcp",
        action="ACCEPT",
    )

    conflicts_list = conflicts.detect_conflicting_rules([r1, r2, r3])
    # r1 and r2 overlap but r1 covers r2, so not counted
    assert conflicts_list == []
