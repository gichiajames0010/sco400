"""
API Views for the Firewall Rule Analyzer.

This module exposes two HTTP endpoints:

  POST /api/analyze/
      Accept raw firewall rules (iptables or nftables format), run anomaly
      detection and optimization, persist a summary to the database, and
      return the full analysis result.

  GET /api/history/
      Return a paginated list of past AnalysisSession records ordered from
      newest to oldest.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import ListAPIView

# Parsers — each parser converts raw text to a list of FirewallRule objects.
from core.parsers.iptables_parser import IptablesParser
from core.parsers.nftables_parser import NftablesParser

# Anomaly detectors — each returns a list / list-of-pairs.
from core.anomalies.redundancy import detect_redundant_rules
from core.anomalies.shadowing import detect_shadowed_rules
from core.anomalies.conflicts import detect_conflicting_rules

# Optimizer and metrics helpers.
from core.optimizer.rule_optimizer import optimize_rules
from core.optimizer.metrics import compute_metrics

# Database model and its DRF serializer.
from .models import AnalysisSession
from .serializers import AnalysisSessionSerializer


class AnalyzeRulesView(APIView):
    """Handle POST /api/analyze/ requests.

    The view auto-detects whether the submitted rules use iptables-save or
    nftables syntax, selects the correct parser, runs the full analysis
    pipeline, and returns a structured JSON response containing:

      - metrics         — high-level statistics about the ruleset
      - redundant_rules — rules that are fully covered by an earlier rule with
                          the same action and can therefore be removed
      - shadowed_rules  — rules that are unreachable because an earlier rule
                          with a *different* action has the same or broader scope
      - conflicts       — pairs of rules that overlap but have opposing actions
      - optimized_rules — the ruleset after removing redundant and shadowed rules
      - session_id      — UUID of the AnalysisSession row saved to the database
    """

    def post(self, request):
        """Analyze submitted firewall rules and return the result.

        Args:
            request: DRF Request object.  Expected body: {"rules": "<raw text>"}

        Returns:
            200 OK  — with the analysis JSON payload described above.
            400 Bad Request — if the 'rules' field is missing or empty.
        """
        rules_text = request.data.get("rules")

        # Reject requests that do not include any rules.
        if not rules_text:
            return Response(
                {"error": "No firewall rules provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ------------------------------------------------------------------ #
        # Parser auto-detection
        # nftables configs always contain 'table' keyword and curly braces.
        # A plain iptables-save file uses '-A' append syntax instead.
        # ------------------------------------------------------------------ #
        if "table" in rules_text and "{" in rules_text:
            parser = NftablesParser()
        else:
            parser = IptablesParser()

        # Parse the raw text into a list of FirewallRule dataclass instances.
        try:
            rules = parser.parse(rules_text)
        except Exception as exc:
            return Response(
                {
                    "error": "Failed to parse firewall rules.",
                    "details": str(exc),
                    "message": (
                        "The input could not be parsed. Please ensure it follows "
                        "valid iptables-save or nftables syntax."
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Helper — convert a FirewallRule to a JSON-serialisable dict.
        def serialize_rule(rule):
            return {
                "order": rule.order,
                "table": rule.table,
                "chain": rule.chain,
                "action": rule.action,
                "raw": rule.raw,
            }

        # ------------------------------------------------------------------ #
        # Build the analysis response dict
        # All anomaly detectors are called once; their return values are kept
        # in plain Python lists so we can also count them for the DB record.
        # ------------------------------------------------------------------ #
        redundant = detect_redundant_rules(rules)
        shadowed = detect_shadowed_rules(rules)
        conflicts = detect_conflicting_rules(rules)
        optimized = optimize_rules(rules)

        response = {
            "metrics": compute_metrics(rules),
            "redundant_rules": [serialize_rule(r) for r in redundant],
            "shadowed_rules": [serialize_rule(r) for r in shadowed],
            "conflicts": [
                {
                    "rule1": serialize_rule(r1),
                    "rule2": serialize_rule(r2)
                }
                for r1, r2 in conflicts
            ],
            "optimized_rules": [serialize_rule(r) for r in optimized],
        }

        # ------------------------------------------------------------------ #
        # Persist a session summary to SQLite so users can review past runs.
        # We store high-level counts rather than full rule details to keep the
        # database lightweight.
        # ------------------------------------------------------------------ #
        metrics = response["metrics"]
        session = AnalysisSession.objects.create(
            raw_rules=rules_text,
            rule_type='nftables' if isinstance(parser, NftablesParser) else 'iptables',
            total_rules=metrics['total_rules'],
            redundant_count=metrics['redundant_rules'],
            shadowed_count=metrics['shadowed_rules'],
            conflict_count=metrics['conflicting_pairs'],
            optimized_count=metrics['optimized_rule_count'],
        )

        # Include the new session UUID so the client can reference this run.
        response["session_id"] = str(session.id)

        # Add interactive feedback message
        if len(rules) == 0:
            response['message'] = (
                'No actionable rules were found in the input. '
                'The configuration may contain only policy declarations or empty chains.'
            )
        elif not redundant and not shadowed and not conflicts:
            response['message'] = (
                'Analysis complete — no anomalies detected. '
                'The provided rules are already optimal.'
            )
        else:
            parts = []
            if redundant:
                parts.append(f'{len(redundant)} redundant')
            if shadowed:
                parts.append(f'{len(shadowed)} shadowed')
            if conflicts:
                parts.append(f'{len(conflicts)} conflicting pair(s)')
            response['message'] = (
                f'Optimisation opportunities found: {", ".join(parts)}. '
                'Review the anomaly details below.'
            )

        return Response(response, status=status.HTTP_200_OK)


class AnalysisHistoryView(ListAPIView):
    """Handle GET /api/history/ requests.

    Returns a list of all AnalysisSession records ordered with the most
    recent first (defined by AnalysisSession.Meta.ordering).  Each record
    includes a summary of the metrics computed during that run.
    """

    queryset = AnalysisSession.objects.all()
    serializer_class = AnalysisSessionSerializer
