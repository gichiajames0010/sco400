"""
A robust iptables-save style parser for firewall rule analysis.

This parser extracts only the fields needed for analysis:
- Protocol (-p)
- Source/destination (-s/-d)
- Source/destination ports (--sport/--dport)
- Input/output interfaces (-i/-o)
- Target action (-j)

It preserves the original raw line in the FirewallRule object for debugging.
"""

from typing import List, Optional, Union
import ipaddress
from core.models.firewall_rule import FirewallRule


class IptablesParser:
    def parse(self, text: str) -> List[FirewallRule]:
        """Parse iptables-save text and extract rules."""
        rules: List[FirewallRule] = []
        current_table: Optional[str] = None
        rule_order: dict[str, dict[str, int]] = {}

        for line in text.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("*"):
                current_table = line[1:]
                rule_order[current_table] = {}
                continue

            if line.startswith("-A"):
                tokens = line.split()
                chain = tokens[1]

                # initialize per-chain counter
                rule_order[current_table].setdefault(chain, 0)
                rule_order[current_table][chain] += 1

                rule = self._parse_tokens(
                    tokens=tokens,
                    table=current_table,
                    chain=chain,
                    order=rule_order[current_table][chain],
                    raw=line
                )
                rules.append(rule)

        return rules

    def _parse_tokens(
        self,
        tokens: List[str],
        table: str,
        chain: str,
        order: int,
        raw: str
    ) -> FirewallRule:
        """Parse recognized tokens and return a FirewallRule."""
        protocol: Optional[str] = None
        src: Optional[ipaddress.IPv4Network] = None
        dst: Optional[ipaddress.IPv4Network] = None
        src_port: Optional[Union[int, tuple[int, int]]] = None
        dst_port: Optional[Union[int, tuple[int, int]]] = None
        in_iface: Optional[str] = None
        out_iface: Optional[str] = None
        action: Optional[str] = None

        i = 0
        while i < len(tokens):
            if tokens[i] == "-p":
                protocol = tokens[i + 1].lower()
                i += 2
            elif tokens[i] == "-s":
                src = self._parse_ip(tokens[i + 1])
                i += 2
            elif tokens[i] == "-d":
                dst = self._parse_ip(tokens[i + 1])
                i += 2
            elif tokens[i] == "--sport":
                src_port = self._parse_port(tokens[i + 1])
                i += 2
            elif tokens[i] == "--dport":
                dst_port = self._parse_port(tokens[i + 1])
                i += 2
            elif tokens[i] == "-i":
                in_iface = tokens[i + 1]
                i += 2
            elif tokens[i] == "-o":
                out_iface = tokens[i + 1]
                i += 2
            elif tokens[i] == "-j":
                action = tokens[i + 1].upper()
                i += 2
            else:
                i += 1

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
            raw=raw,
            order=order
        )

    @staticmethod
    def _parse_ip(ip_str: str) -> Optional[ipaddress.IPv4Network]:
        """Convert string to IPv4Network or return None if invalid."""
        try:
            return ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _parse_port(port_str: str) -> Optional[Union[int, tuple[int, int]]]:
        """Convert port or port range string to int or tuple."""
        if ":" in port_str:
            try:
                start, end = map(int, port_str.split(":"))
                return (start, end)
            except ValueError:
                return None
        try:
            return int(port_str)
        except ValueError:
            return None
