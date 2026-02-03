"""A tiny iptables-save style parser used by tests and analyzers.

This parser is intentionally small and only extracts a subset of
iptables rule fields needed by the analyzers (protocol, src/dst
addresses and ports, interfaces and target action). It is not a full
iptables grammar implementation — instead it tokenizes each rule line
and picks out recognized options. Unknown tokens are ignored, preserving
the original raw rule text in the produced `FirewallRule` for diagnostics.
"""

from typing import List
from core.models.firewall_rule import FirewallRule


class IptablesParser:
    def parse(self, text: str) -> List[FirewallRule]:
        """Parse iptables configuration text and extract firewall rules.

        The parser expects text in the style produced by `iptables-save`,
        where tables are introduced by a line beginning with `*` and rules
        are lines beginning with `-A <CHAIN> ...`. Comment lines (starting
        with `#`) and blank lines are ignored. The parser maintains an
        ordering for rules per chain which is stored in the `order`
        attribute of the returned `FirewallRule` objects.
        """
        rules: List[FirewallRule] = []
        current_table = None
        # rule_order keeps per-(table,chain) counters so we can populate
        # the `order` field on FirewallRule instances.
        rule_order = {}

        for line in text.splitlines():
            line = line.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue

            # Table headers are of the form '*filter' and set the context
            if line.startswith("*"):
                current_table = line[1:]
                rule_order[current_table] = {}
                continue

            # Rule lines start with '-A' followed by the chain name
            if line.startswith("-A"):
                tokens = line.split()
                chain = tokens[1]

                # Initialize and increment the per-chain rule counter
                rule_order[current_table].setdefault(chain, 0)
                rule_order[current_table][chain] += 1

                # Delegate detailed token parsing to helper
                rule = self._parse_tokens(
                    tokens,
                    current_table,
                    chain,
                    rule_order[current_table][chain],
                    line
                )
                rules.append(rule)

        return rules

    def _parse_tokens(self, tokens: List[str], table: str, chain: str, order: int, raw: str) -> FirewallRule:
        """Extract recognized token values from a tokenized rule line.

        This helper walks the token list and picks the following known
        options: `-p`, `-s`, `-d`, `--sport`, `--dport`, `-i`, `-o`, `-j`.
        Any other tokens are ignored to keep the parser robust to
        unrecognized extensions.

        Returns a `FirewallRule` populated with found values and the
        original `raw` line for debugging.
        """
        # Initialize parsed fields (None means "any" / unspecified)
        protocol = src = dst = src_port = dst_port = None
        in_iface = out_iface = None
        action = None

        i = 0
        while i < len(tokens):
            # Use index-based parsing to allow skipping optional values
            if tokens[i] == "-p":
                protocol = tokens[i + 1]
                i += 2
            elif tokens[i] == "-s":
                src = tokens[i + 1]
                i += 2
            elif tokens[i] == "-d":
                dst = tokens[i + 1]
                i += 2
            elif tokens[i] == "--sport":
                src_port = tokens[i + 1]
                i += 2
            elif tokens[i] == "--dport":
                dst_port = tokens[i + 1]
                i += 2
            elif tokens[i] == "-i":
                in_iface = tokens[i + 1]
                i += 2
            elif tokens[i] == "-o":
                out_iface = tokens[i + 1]
                i += 2
            elif tokens[i] == "-j":
                # jump/target (action) indicates the decision taken if the
                # rule matches (e.g., ACCEPT, DROP)
                action = tokens[i + 1]
                i += 2
            else:
                # Unrecognized token: skip it to remain tolerant of other
                # iptables options we don't need for analysis.
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
