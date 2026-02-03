from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from core.parsers.iptables_parser import IptablesParser
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules
from core.anomalies.conflicts import detect_conflicting_rules
from core.optimizer.rule_optimizer import optimize_rules
from core.optimizer.metrics import compute_metrics


class AnalyzeRulesView(APIView):
    def post(self, request):
        rules_text = request.data.get("rules")

        if not rules_text:
            return Response(
                {"error": "No firewall rules provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        parser = IptablesParser()
        rules = parser.parse(rules_text)

        def serialize_rule(rule):
            return {
                "order": rule.order,
                "table": rule.table,
                "chain": rule.chain,
                "action": rule.action,
                "raw": rule.raw,
            }

        response = {
            "metrics": compute_metrics(rules),
            "redundant_rules": [
                serialize_rule(r) for r in detect_redundant_rules(rules)
            ],
            "shadowed_rules": [
                serialize_rule(r) for r in detect_shadowed_rules(rules)
            ],
            "conflicts": [
                {
                    "rule_1": serialize_rule(r1),
                    "rule_2": serialize_rule(r2)
                }
                for r1, r2 in detect_conflicting_rules(rules)
            ],
            "optimized_rules": [
                serialize_rule(r) for r in optimize_rules(rules)
            ]
        }


        return Response(response, status=status.HTTP_200_OK)
