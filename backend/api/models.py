"""
Database models for the Firewall Rule Analyzer API.

Currently a single model, AnalysisSession, is used to persist a summary
of each analysis run performed via the /api/analyze/ endpoint.  Django's
default SQLite backend is used in development; any standard Django-supported
database can be substituted by changing the DATABASES setting.
"""

from django.db import models
import uuid


class AnalysisSession(models.Model):
    """Stores a summary record for each firewall rule analysis run.

    One AnalysisSession row is created every time a user submits rules to the
    /api/analyze/ endpoint.  Rather than storing the full analysis result
    (which can be large), we store only the key metrics so that the history
    view remains fast and the database stays small.

    Fields:
        id          — Auto-generated UUID used as the primary key and returned
                      to the client so future requests can reference this run.
        created_at  — Timestamp recorded automatically when the row is created.
        raw_rules   — The original text submitted by the user, kept for
                      auditability and future replay of the analysis.
        rule_type   — Either 'iptables' or 'nftables', as detected by the view.
        total_rules — Total number of rules parsed from raw_rules.
        redundant_count  — Number of redundant rules found.
        shadowed_count   — Number of shadowed rules found.
        conflict_count   — Number of conflicting rule pairs detected.
        optimized_count  — Number of rules remaining after optimization.
    """

    # Use a UUID as primary key to avoid leaking sequential IDs to clients.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Timestamp — set once at creation, never updated.
    created_at = models.DateTimeField(auto_now_add=True)

    # ------------------------------------------------------------------ #
    # Input fields
    # ------------------------------------------------------------------ #

    # The full raw text submitted by the user.  Stored as a text field so
    # there is no upper-bound on size.
    raw_rules = models.TextField(
        help_text="The original raw firewall rules submitted for analysis."
    )

    # Whether the ruleset was parsed as iptables or nftables syntax.
    rule_type = models.CharField(
        max_length=20,
        choices=[('iptables', 'iptables'), ('nftables', 'nftables')],
        default='iptables',
        help_text="Format of the submitted rules: 'iptables' or 'nftables'.",
    )

    # ------------------------------------------------------------------ #
    # Metric summary fields (all default to 0 for safety)
    # ------------------------------------------------------------------ #

    total_rules = models.IntegerField(
        default=0,
        help_text="Total number of rules parsed from raw_rules.",
    )
    redundant_count = models.IntegerField(
        default=0,
        help_text="Number of redundant rules detected.",
    )
    shadowed_count = models.IntegerField(
        default=0,
        help_text="Number of shadowed rules detected.",
    )
    conflict_count = models.IntegerField(
        default=0,
        help_text="Number of conflicting rule pairs detected.",
    )
    optimized_count = models.IntegerField(
        default=0,
        help_text="Number of rules remaining after optimization.",
    )

    class Meta:
        # Newest sessions appear first in list views.
        ordering = ['-created_at']

    def __str__(self):
        return f"Analysis {self.id} ({self.rule_type}) at {self.created_at:%Y-%m-%d %H:%M}"
