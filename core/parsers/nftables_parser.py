"""
Parser for nftables configuration.

This parser extracts firewall rules from `nft list ruleset` style output.
It maps nftables constructs to the generic FirewallRule model.

Handles UFW-generated nftables rulesets including:
  - counter packets <N> bytes <N> metadata (stripped before parsing)
  - jump/log/return/accept/drop/reject actions
  - ct state, meta l4proto, fib, limit rate, icmp/icmpv6 type constructs
  - Quoted interface names (e.g. "lo")
"""

import re
import ipaddress
from typing import List, Optional, Union, Dict
from core.models.firewall_rule import FirewallRule

# Regex to strip "counter packets <N> bytes <N>" from a rule line.
_COUNTER_RE = re.compile(r'\bcounter\s+packets\s+\d+\s+bytes\s+\d+\b')

# Regex to strip standalone "counter" keyword (without packets/bytes).
_COUNTER_BARE_RE = re.compile(r'\bcounter\b')

# Regex to strip "limit rate <N>/<unit> burst <N> packets" constructs.
_LIMIT_RE = re.compile(r'\blimit\s+rate\s+\S+\s+burst\s+\d+\s+packets\b')

# Regex to strip log prefix strings: log prefix "..."
_LOG_PREFIX_RE = re.compile(r'\blog\s+prefix\s+"[^"]*"')

# Regex to strip xt match "..." constructs (compat layer references).
_XT_MATCH_RE = re.compile(r'\bxt\s+match\s+"[^"]*"')


class NftablesParser:
    def parse(self, text: str) -> List[FirewallRule]:
        """Parse nftables text and extract rules."""
        rules: List[FirewallRule] = []

        # Context tracking
        current_table: Optional[str] = None
        current_chain: Optional[str] = None

        # Rule ordering per chain
        rule_order: Dict[str, Dict[str, int]] = {}

        # Regex for capturing context
        table_regex = re.compile(r'^table\s+(\w+)\s+(\w+)\s+\{')
        chain_regex = re.compile(r'^chain\s+([\w-]+)\s+\{')
        close_regex = re.compile(r'^\}\s*$')

        lines = text.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check for Table start
            table_match = table_regex.match(line)
            if table_match:
                family, name = table_match.groups()
                current_table = f"{family} {name}"
                rule_order[current_table] = {}
                continue

            # Check for Chain start
            chain_match = chain_regex.match(line)
            if chain_match:
                current_chain = chain_match.group(1)
                if current_table:
                    rule_order[current_table].setdefault(current_chain, 0)
                continue

            # Check for closing brace (end of chain or table)
            if close_regex.match(line):
                if current_chain:
                    current_chain = None
                elif current_table:
                    current_table = None
                continue

            # Parsing rules inside a chain
            if current_table and current_chain:
                # Ignore chain metadata lines (type, hook, policy, etc.)
                if line.startswith('type ') or line.startswith('policy '):
                    continue

                # Increment order
                rule_order[current_table][current_chain] += 1

                rule = self._parse_rule(
                    line,
                    current_table,
                    current_chain,
                    rule_order[current_table][current_chain]
                )
                if rule:
                    rules.append(rule)

        return rules

    def _clean_line(self, line: str) -> str:
        """Strip nftables metadata tokens that interfere with rule parsing.

        Removes:
          - counter packets <N> bytes <N>
          - bare counter keyword
          - limit rate ... burst ... packets
          - log prefix "..."
          - xt match "..."
          - surrounding quotes on values (e.g. "lo" -> lo)
        """
        cleaned = _COUNTER_RE.sub('', line)
        cleaned = _LIMIT_RE.sub('', cleaned)
        cleaned = _LOG_PREFIX_RE.sub('', cleaned)
        cleaned = _XT_MATCH_RE.sub('', cleaned)
        cleaned = _COUNTER_BARE_RE.sub('', cleaned)
        # Remove quotes around values like "lo"
        cleaned = cleaned.replace('"', '')
        # Collapse multiple spaces
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    def _parse_rule(self, line: str, table: str, chain: str, order: int) -> Optional[FirewallRule]:
        """Parse a single nftables rule line into a FirewallRule object.

        This method first cleans the line (stripping counters, log prefixes,
        etc.) and then tokenizes it to extract semantic fields such as
        protocol, source/destination IPs, ports, interfaces, and actions.

        Args:
            line: The raw rule string.
            table: The table name the rule belongs to.
            chain: The chain name the rule belongs to.
            order: The generic order/priority index of the rule.

        Returns:
            A FirewallRule object if the line represents a valid rule with
            an action, otherwise None.
        """
        cleaned = self._clean_line(line)
        tokens = cleaned.split()

        protocol: Optional[str] = None
        src: Optional[ipaddress.IPv4Network] = None
        dst: Optional[ipaddress.IPv4Network] = None
        src_port: Optional[Union[int, tuple]] = None
        dst_port: Optional[Union[int, tuple]] = None
        in_iface: Optional[str] = None
        out_iface: Optional[str] = None
        action: Optional[str] = None

        i = 0
        while i < len(tokens):
            token = tokens[i]

            # ------------------------------------------------------------ #
            # Skip nftables-specific keywords that carry multi-token args  #
            # ------------------------------------------------------------ #

            # ct state <value[,value]>
            if token == 'ct' and i + 2 < len(tokens) and tokens[i + 1] == 'state':
                i += 3  # skip "ct state <value>"
                continue

            # meta l4proto <proto>
            if token == 'meta' and i + 2 < len(tokens) and tokens[i + 1] == 'l4proto':
                proto_val = tokens[i + 2]
                if proto_val in ('tcp', 'udp', 'icmp', 'ipv6-icmp'):
                    protocol = proto_val
                i += 3
                continue

            # fib daddr type <value>
            if token == 'fib' and i + 3 < len(tokens):
                i += 4  # skip "fib daddr type local"
                continue

            # rt type <value>
            if token == 'rt' and i + 2 < len(tokens) and tokens[i + 1] == 'type':
                i += 3
                continue

            # icmp type <value> / icmpv6 type <value>
            if token in ('icmp', 'icmpv6') and i + 2 < len(tokens) and tokens[i + 1] == 'type':
                protocol = token
                i += 3  # skip "icmp type <value>"
                continue

            # ip6 hoplimit <value>
            if token == 'ip6' and i + 2 < len(tokens) and tokens[i + 1] == 'hoplimit':
                i += 3
                continue

            # log (standalone, prefix already stripped)
            if token == 'log':
                action = 'LOG'
                i += 1
                continue

            # ------------------------------------------------------------ #
            # Protocol                                                      #
            # ------------------------------------------------------------ #
            if token in ('tcp', 'udp', 'icmp', 'icmpv6'):
                protocol = token
                i += 1
                continue

            if token == 'ip' and i + 1 < len(tokens) and tokens[i + 1] == 'protocol':
                if i + 2 < len(tokens):
                    protocol = tokens[i + 2]
                i += 3
                continue

            # ------------------------------------------------------------ #
            # Source / Destination IP                                        #
            # ------------------------------------------------------------ #
            if token == 'ip' and i + 2 < len(tokens) and tokens[i + 1] == 'saddr':
                src = self._parse_ip(tokens[i + 2])
                i += 3
                continue
            if token == 'ip6' and i + 2 < len(tokens) and tokens[i + 1] == 'saddr':
                src = self._parse_ip(tokens[i + 2])
                i += 3
                continue
            if token == 'saddr':
                if i + 1 < len(tokens):
                    src = self._parse_ip(tokens[i + 1])
                i += 2
                continue

            if token == 'ip' and i + 2 < len(tokens) and tokens[i + 1] == 'daddr':
                dst = self._parse_ip(tokens[i + 2])
                i += 3
                continue
            if token == 'ip6' and i + 2 < len(tokens) and tokens[i + 1] == 'daddr':
                dst = self._parse_ip(tokens[i + 2])
                i += 3
                continue
            if token == 'daddr':
                if i + 1 < len(tokens):
                    dst = self._parse_ip(tokens[i + 1])
                i += 2
                continue

            # ------------------------------------------------------------ #
            # Ports                                                          #
            # ------------------------------------------------------------ #
            if token in ('sport', 'dport') and i + 1 < len(tokens):
                val = self._parse_port(tokens[i + 1])
                if token == 'sport':
                    src_port = val
                else:
                    dst_port = val
                i += 2
                continue

            # ------------------------------------------------------------ #
            # Interfaces                                                     #
            # ------------------------------------------------------------ #
            if token == 'iifname' and i + 1 < len(tokens):
                in_iface = tokens[i + 1]
                i += 2
                continue
            if token == 'oifname' and i + 1 < len(tokens):
                out_iface = tokens[i + 1]
                i += 2
                continue

            # ------------------------------------------------------------ #
            # Actions (terminal)                                             #
            # ------------------------------------------------------------ #
            if token in ('accept', 'drop', 'reject', 'return'):
                action = token.upper()
                i += 1
                continue

            # jump <chain-name>
            if token == 'jump' and i + 1 < len(tokens):
                action = f"JUMP {tokens[i + 1]}"
                i += 2
                continue

            # goto <chain-name>
            if token == 'goto' and i + 1 < len(tokens):
                action = f"GOTO {tokens[i + 1]}"
                i += 2
                continue

            # Skip unknown tokens
            i += 1

        # If no action was parsed, this is not a meaningful rule (e.g.
        # a bare metadata line that survived cleaning). Skip it.
        if not action:
            return None

        return FirewallRule(
            table=table,
            chain=chain,
            protocol=protocol,
            src=src,
            dst=dst,
            src_port=src_port,
            dst_port=dst_port,
            in_iface=in_iface,
            out_iface=out_iface,
            action=action,
            raw=line,
            order=order
        )

    @staticmethod
    def _parse_ip(ip_str: str) -> Optional[ipaddress.IPv4Network]:
        try:
            return ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _parse_port(port_str: str) -> Optional[Union[int, tuple]]:
        # Handle ranges like 80-90
        if '-' in port_str:
            try:
                start, end = map(int, port_str.split('-'))
                return (start, end)
            except ValueError:
                return None
        try:
            return int(port_str)
        except ValueError:
            return None
