from rest_framework import serializers
from .models import AnalysisSession

class AnalysisSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisSession
        fields = [
            'id', 'created_at', 'rule_type', 
            'total_rules', 'redundant_count', 
            'shadowed_count', 'conflict_count', 
            'optimized_count'
        ]
        read_only_fields = fields
