"""
Parser for nftables configuration.

This parser extracts firewall rules from `nft list ruleset` style output.
It maps nftables constructs to the generic FirewallRule model.
"""

import re
import ipaddress
from typing import List, Optional, Union, Dict
from core.models.firewall_rule import FirewallRule


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
        # table <family> <name> {
        table_regex = re.compile(r'^table\s+(\w+)\s+(\w+)\s+\{')
        # chain <name> {
        chain_regex = re.compile(r'^chain\s+(\w+)\s+\{')
        # closing brace }
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
                # We assume purely nested structure: table { chain { rules } }
                # So a closing brace ends the current innermost context
                if current_chain:
                    current_chain = None
                elif current_table:
                    current_table = None
                continue

            # parsing rules inside a chain
            if current_table and current_chain:
                # Ignore chain metadata lines (type, hook, policy, etc.)
                if line.startswith('type ') or line.startswith('policy '):
                    continue
                
                # Assume it's a rule
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

    def _parse_rule(self, line: str, table: str, chain: str, order: int) -> Optional[FirewallRule]:
        """Parse a single rule line."""
        tokens = line.split()
        
        protocol: Optional[str] = None
        src: Optional[ipaddress.IPv4Network] = None
        dst: Optional[ipaddress.IPv4Network] = None
        src_port: Optional[Union[int, tuple]] = None
        dst_port: Optional[Union[int, tuple]] = None
        in_iface: Optional[str] = None
        out_iface: Optional[str] = None
        action: Optional[str] = None

        # Simple token consumption loop
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            # Protocol
            if token in ('tcp', 'udp', 'icmp'):
                protocol = token
                i += 1
            elif token == 'ip' and i + 1 < len(tokens) and tokens[i+1] == 'protocol':
                 protocol = tokens[i+2]
                 i += 3
            
            # Source IP
            elif token == 'ip' and i + 2 < len(tokens) and tokens[i+1] == 'saddr':
                src = self._parse_ip(tokens[i+2])
                i += 3
            elif token == 'saddr': # simplified if ip is omitted or handled elsewhere
                 src = self._parse_ip(tokens[i+1])
                 i += 2

            # Destination IP
            elif token == 'ip' and i + 2 < len(tokens) and tokens[i+1] == 'daddr':
                dst = self._parse_ip(tokens[i+2])
                i += 3
            elif token == 'daddr':
                 dst = self._parse_ip(tokens[i+1])
                 i += 2

            # Ports
            elif token in ('sport', 'dport') and i + 1 < len(tokens):
                val = self._parse_port(tokens[i+1])
                if token == 'sport':
                    src_port = val
                else:
                    dst_port = val
                i += 2
            
            # Interfaces
            elif token == 'iifname':
                in_iface = tokens[i+1]
                i += 2
            elif token == 'oifname':
                out_iface = tokens[i+1]
                i += 2
            
            # Actions (terminal)
            elif token in ('accept', 'drop', 'reject', 'return'):
                action = token.upper()
                i += 1
            
            # Skip unknown tokens
            else:
                i += 1

        if not action:
            # Maybe it's a counter rule or log rule without terminal action?
            # treating as valid rule but "NO_ACTION" or skipping?
            # For now, let's treat it as a valid rule if we parsed anything significant
            pass

        # If no explicit action, it might not be a filtering rule we care about,
        # but let's store it for context if it looks like a rule.
        # Ideally we want rules with actions.
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
