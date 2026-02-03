"""Firewall rule model used across the analyzer.

This module defines a compact, typed `FirewallRule` dataclass that stores the
attributes extracted from firewall configuration (for example, iptables
rules). Fields that are typed as `Optional` may be `None` to indicate that
the corresponding match criterion was not specified (treated as a
wildcard when evaluating overlaps/coverage).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FirewallRule:
    """A parsed firewall rule.

    Attributes:
        table: The table (e.g., 'filter') the rule belongs to.
        chain: The chain (e.g., 'INPUT', 'OUTPUT') the rule belongs to.
        protocol: Protocol string (e.g., 'tcp', 'udp') or None for any.
        src: Source address (CIDR or single IP) or None for any.
        dst: Destination address (CIDR or single IP) or None for any.
        src_port: Source port number or port range string, or None for any.
        dst_port: Destination port number or port range string, or None.
        in_iface: Incoming interface name or None for any.
        out_iface: Outgoing interface name or None for any.
        action: The target/action of the rule (e.g., 'ACCEPT', 'DROP').
        raw: The original rule text as parsed, useful for display/debugging.
        order: The position of the rule in the original rule list (0-based).
    """

    # Table and chain identify the rule's context and are required.
    table: str
    chain: str

    # Match fields. A value of `None` represents a wildcard (unspecified).
    protocol: Optional[str]
    src: Optional[str]
    dst: Optional[str]
    src_port: Optional[str]
    dst_port: Optional[str]
    in_iface: Optional[str]
    out_iface: Optional[str]

    # Action to take when the rule matches (required) and metadata used by
    # parsers/analyzers.
    action: str
    raw: str
    order: int
