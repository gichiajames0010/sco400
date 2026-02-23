"""
DRF serializers for the Firewall Rule Analyzer API.

Serializers convert Django model instances to/from JSON for the REST API.
Currently only the AnalysisSession model needs serialization (for the
GET /api/history/ endpoint).  The raw_rules field is intentionally excluded
from the list endpoint to keep responses concise.
"""

from rest_framework import serializers
from .models import AnalysisSession


class AnalysisSessionSerializer(serializers.ModelSerializer):
    """Serialize AnalysisSession instances for the history endpoint.

    All fields are read-only because sessions are created exclusively by the
    AnalyzeRulesView and should never be modified via the API.

    The serialized payload includes:
      id              — UUID of the session.
      created_at      — ISO-8601 timestamp of when the analysis was run.
      rule_type       — 'iptables' or 'nftables'.
      total_rules     — Total rules in the submitted ruleset.
      redundant_count — Number of redundant rules found.
      shadowed_count  — Number of shadowed rules found.
      conflict_count  — Number of conflicting pairs found.
      optimized_count — Rules remaining after optimization.

    Note: raw_rules is deliberately excluded to keep the list response lightweight.
    """

    class Meta:
        model = AnalysisSession
        fields = [
            'id',
            'created_at',
            'rule_type',
            'total_rules',
            'redundant_count',
            'shadowed_count',
            'conflict_count',
            'optimized_count',
        ]
        # All fields are read-only — sessions are only written by the view.
        read_only_fields = fields
