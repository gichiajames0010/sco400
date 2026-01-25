from typing import List
from core.models.firewall_rule import FirewallRule

class IptablesParser:
    def parse(self, text: str) -> List[FirewallRule]:
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
