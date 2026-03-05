"""
Tests for NftablesParser.

Covers: table/chain context tracking, IP address extraction,
port extraction, interface extraction, action detection, and
rejection of lines without a terminal action.
"""

import ipaddress
import pytest
from core.parsers.nftables_parser import NftablesParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse(text: str):
    """Parse nftables text and return rule list."""
    return NftablesParser().parse(text)


BASIC_RULESET = """
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr 192.168.1.0/24 accept
        ip daddr 10.0.0.1 drop
    }
}
"""

# ---------------------------------------------------------------------------
# Basic structure parsing
# ---------------------------------------------------------------------------

class TestContextParsing:
    def test_rules_extracted(self):
        rules = parse(BASIC_RULESET)
        assert len(rules) == 2

    def test_table_assigned(self):
        rules = parse(BASIC_RULESET)
        assert all("filter" in r.table for r in rules)

    def test_chain_assigned(self):
        rules = parse(BASIC_RULESET)
        assert all(r.chain == "input" for r in rules)

    def test_empty_input_returns_empty(self):
        assert parse("") == []

    def test_comment_lines_skipped(self):
        text = """
table inet filter {
    chain input {
        # this is a comment
        tcp dport 80 accept
    }
}
"""
        rules = parse(text)
        assert len(rules) == 1

    def test_multiple_chains(self):
        text = """
table inet filter {
    chain input {
        tcp dport 80 accept
    }
    chain output {
        tcp dport 443 accept
    }
}
"""
        rules = parse(text)
        chains = {r.chain for r in rules}
        assert "input" in chains
        assert "output" in chains


# ---------------------------------------------------------------------------
# IP address parsing
# ---------------------------------------------------------------------------

class TestIPParsing:
    def test_source_ip_extracted(self):
        rules = parse(BASIC_RULESET)
        src_rules = [r for r in rules if r.src is not None]
        assert len(src_rules) >= 1
        assert src_rules[0].src == ipaddress.ip_network("192.168.1.0/24")

    def test_dest_ip_extracted(self):
        rules = parse(BASIC_RULESET)
        dst_rules = [r for r in rules if r.dst is not None]
        assert len(dst_rules) >= 1
        assert dst_rules[0].dst == ipaddress.ip_network("10.0.0.1")

    def test_invalid_ip_returns_none(self):
        # Lines with bad IPs should produce a rule with src=None
        text = """
table inet filter {
    chain input {
        ip saddr not_an_ip accept
    }
}
"""
        rules = parse(text)
        assert rules[0].src is None


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------

class TestPortParsing:
    def test_single_dst_port(self):
        text = """
table inet filter {
    chain input {
        tcp dport 80 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].dst_port == 80

    def test_dst_port_range(self):
        text = """
table inet filter {
    chain input {
        tcp dport 8080-8090 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].dst_port == (8080, 8090)

    def test_src_port_extracted(self):
        text = """
table inet filter {
    chain input {
        tcp sport 1024 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].src_port == 1024


# ---------------------------------------------------------------------------
# Action detection
# ---------------------------------------------------------------------------

class TestActionParsing:
    def test_accept_action(self):
        text = """
table inet filter {
    chain input {
        tcp dport 80 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].action == "ACCEPT"

    def test_drop_action(self):
        text = """
table inet filter {
    chain input {
        tcp dport 80 drop
    }
}
"""
        rules = parse(text)
        assert rules[0].action == "DROP"

    def test_line_without_action_skipped(self):
        """Lines with no terminal verdict (accept/drop/reject/return) are ignored."""
        text = """
table inet filter {
    chain input {
        tcp dport 80 log prefix "test"
    }
}
"""
        rules = parse(text)
        assert len(rules) == 0


# ---------------------------------------------------------------------------
# Interface parsing
# ---------------------------------------------------------------------------

class TestInterfaceParsing:
    def test_in_interface_extracted(self):
        text = """
table inet filter {
    chain input {
        iifname eth0 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].in_iface == "eth0"

    def test_out_interface_extracted(self):
        text = """
table inet filter {
    chain output {
        oifname eth1 accept
    }
}
"""
        rules = parse(text)
        assert rules[0].out_iface == "eth1"
