from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from core.parsers.iptables_parser import IptablesParser
from core.parsers.nftables_parser import NftablesParser
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules
from core.anomalies.conflicts import detect_conflicting_rules
from core.optimizer.rule_optimizer import optimize_rules
from core.optimizer.rule_optimizer import optimize_rules
from core.optimizer.metrics import compute_metrics
from .models import AnalysisSession
from .serializers import AnalysisSessionSerializer
from rest_framework.generics import ListAPIView


class AnalyzeRulesView(APIView):
    def post(self, request):
        rules_text = request.data.get("rules")

        if not rules_text:
            return Response(
                {"error": "No firewall rules provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Auto-detect parser
        if "table" in rules_text and "{" in rules_text:
            parser = NftablesParser()
        else:
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
                    "rule1": serialize_rule(r1),
                    "rule2": serialize_rule(r2)
                }
                for r1, r2 in detect_conflicting_rules(rules)
            ],
            "optimized_rules": [
                serialize_rule(r) for r in optimize_rules(rules)
            ]
        }

        # Save session to DB
        metrics = response["metrics"]
        session = AnalysisSession.objects.create(
            raw_rules=rules_text,
            rule_type='nftables' if isinstance(parser, NftablesParser) else 'iptables',
            total_rules=metrics['total_rules'],
            redundant_count=metrics['redundant_rules'],
            shadowed_count=metrics['shadowed_rules'],
            conflict_count=metrics['conflicting_pairs'],
            optimized_count=metrics['optimized_rule_count']
        )
        
        # Add session ID to response
        response["session_id"] = session.id

        return Response(response, status=status.HTTP_200_OK)


class AnalysisHistoryView(ListAPIView):
    queryset = AnalysisSession.objects.all()
    serializer_class = AnalysisSessionSerializer

