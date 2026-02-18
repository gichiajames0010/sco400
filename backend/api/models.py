from django.db import models
import uuid

class AnalysisSession(models.Model):
    """Stores the result of a firewall rule analysis session."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Input Data
    raw_rules = models.TextField(help_text="The original raw firewall rules input")
    rule_type = models.CharField(
        max_length=20, 
        choices=[('iptables', 'iptables'), ('nftables', 'nftables')],
        default='iptables'
    )

    # Metrics
    total_rules = models.IntegerField(default=0)
    redundant_count = models.IntegerField(default=0)
    shadowed_count = models.IntegerField(default=0)
    conflict_count = models.IntegerField(default=0)
    optimized_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Analysis {self.id} ({self.rule_type}) - {self.created_at}"
