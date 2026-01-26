from typing import List
from core.models.firewall_rule import FirewallRule

class IptablesParser:
    def parse(self, text: str) -> List[FirewallRule]:
        """
        Parse iptables configuration text and extract firewall rules.
        
        Processes iptables rule definitions from text format, identifying tables,
        chains, and individual rules while maintaining rule ordering within each chain.
        
        Args:
            text (str): iptables configuration text containing rules in iptables-save format.
        
        Returns:
            List[FirewallRule]: A list of parsed firewall rule objects extracted from the input text.
        
        Raises:
            None explicitly, but may raise exceptions from _parse_tokens if invalid tokens are encountered.
        
        Notes:
            - Skips empty lines and comments (lines starting with '#')
            - Tables are identified by lines starting with '*'
            - Rules are identified by lines starting with '-A'
            - Rules are ordered sequentially within their respective chains
            - Requires current_table to be set before processing rules
        """
        rules = []
        current_table = None
        rule_order = {}

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

                rule_order[current_table].setdefault(chain, 0)
                rule_order[current_table][chain] += 1

                rule = self._parse_tokens(
                    tokens,
                    current_table,
                    chain,
                    rule_order[current_table][chain],
                    line
                )
                rules.append(rule)

        return rules

    def _parse_tokens(self, tokens, table, chain, order, raw):
        protocol = src = dst = src_port = dst_port = None
        in_iface = out_iface = None
        action = None

        i = 0
        while i < len(tokens):
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
                action = tokens[i + 1]
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
