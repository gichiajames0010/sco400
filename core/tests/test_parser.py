"""
Tests for IptablesParser.

Covers: basic rule parsing, multi-table/chain, port ranges,
malformed line handling, and all option flags (-p, -s, -d, etc.).
"""

import ipaddress
import pytest
from core.parsers.iptables_parser import IptablesParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse(text: str):
    """Parse iptables-save text and return rule list."""
    return IptablesParser().parse(text)


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------

class TestBasicParsing:
    def test_single_rule_parsed(self):
        rules = parse("*filter\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT")
        assert len(rules) == 1

    def test_table_assigned(self):
        rules = parse("*filter\n-A INPUT -j DROP\nCOMMIT")
        assert rules[0].table == "filter"

    def test_chain_assigned(self):
        rules = parse("*filter\n-A FORWARD -j DROP\nCOMMIT")
        assert rules[0].chain == "FORWARD"

    def test_action_upper(self):
        rules = parse("*filter\n-A INPUT -j accept\nCOMMIT")
        assert rules[0].action == "ACCEPT"

    def test_raw_preserved(self):
        raw = "-A INPUT -p tcp --dport 22 -j ACCEPT"
        rules = parse(f"*filter\n{raw}\nCOMMIT")
        assert rules[0].raw == raw

    def test_order_increments_per_chain(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -p tcp -j ACCEPT\n"
            "-A INPUT -p udp -j DROP\n"
            "COMMIT"
        )
        assert rules[0].order == 1
        assert rules[1].order == 2

    def test_empty_input_returns_empty_list(self):
        assert parse("") == []

    def test_comment_lines_skipped(self):
        rules = parse("*filter\n# this is a comment\n-A INPUT -j DROP\nCOMMIT")
        assert len(rules) == 1

    def test_blank_lines_skipped(self):
        rules = parse("*filter\n\n-A INPUT -j DROP\n\nCOMMIT")
        assert len(rules) == 1


# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------

class TestFlagParsing:
    def test_protocol_parsed(self):
        rules = parse("*filter\n-A INPUT -p tcp -j ACCEPT\nCOMMIT")
        assert rules[0].protocol == "tcp"

    def test_source_ip_parsed(self):
        rules = parse("*filter\n-A INPUT -s 192.168.1.0/24 -j ACCEPT\nCOMMIT")
        assert rules[0].src == ipaddress.ip_network("192.168.1.0/24")

    def test_dest_ip_parsed(self):
        rules = parse("*filter\n-A INPUT -d 10.0.0.1 -j DROP\nCOMMIT")
        assert rules[0].dst == ipaddress.ip_network("10.0.0.1")

    def test_single_dst_port_parsed(self):
        rules = parse("*filter\n-A INPUT -p tcp --dport 80 -j ACCEPT\nCOMMIT")
        assert rules[0].dst_port == 80

    def test_dst_port_range_parsed(self):
        rules = parse("*filter\n-A INPUT -p tcp --dport 80:90 -j ACCEPT\nCOMMIT")
        assert rules[0].dst_port == (80, 90)

    def test_single_src_port_parsed(self):
        rules = parse("*filter\n-A INPUT -p tcp --sport 1024 -j ACCEPT\nCOMMIT")
        assert rules[0].src_port == 1024

    def test_in_interface_parsed(self):
        rules = parse("*filter\n-A INPUT -i eth0 -j ACCEPT\nCOMMIT")
        assert rules[0].in_iface == "eth0"

    def test_out_interface_parsed(self):
        rules = parse("*filter\n-A OUTPUT -o eth1 -j ACCEPT\nCOMMIT")
        assert rules[0].out_iface == "eth1"

    def test_unspecified_fields_are_none(self):
        rules = parse("*filter\n-A INPUT -j DROP\nCOMMIT")
        r = rules[0]
        assert r.protocol is None
        assert r.src is None
        assert r.dst is None
        assert r.src_port is None
        assert r.dst_port is None
        assert r.in_iface is None
        assert r.out_iface is None


# ---------------------------------------------------------------------------
# Multi-table / multi-chain
# ---------------------------------------------------------------------------

class TestMultiTableChain:
    def test_multiple_tables(self):
        rules = parse(
            "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"
            "*nat\n-A PREROUTING -j ACCEPT\nCOMMIT"
        )
        tables = {r.table for r in rules}
        assert "filter" in tables
        assert "nat" in tables

    def test_order_resets_per_chain(self):
        rules = parse(
            "*filter\n"
            "-A INPUT -j ACCEPT\n"
            "-A INPUT -j DROP\n"
            "-A OUTPUT -j ACCEPT\n"
            "COMMIT"
        )
        input_rules = [r for r in rules if r.chain == "INPUT"]
        output_rules = [r for r in rules if r.chain == "OUTPUT"]
        assert input_rules[0].order == 1
        assert input_rules[1].order == 2
        assert output_rules[0].order == 1
