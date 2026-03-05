"""
Integration tests for the Firewall Rule Analyzer REST API.

Tests the two endpoints:
  POST /api/analyze/  — submit rules, get analysis result + session_id
  GET  /api/history/  — list past analysis sessions

Uses Django's built-in test client (no live server needed).
"""

import json
from django.test import TestCase
from django.urls import reverse


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

IPTABLES_RULES = """\
*filter
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

NFTABLES_RULES = """\
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 22 accept
        tcp dport 80 accept
    }
}
"""


# ---------------------------------------------------------------------------
# Analyze endpoint
# ---------------------------------------------------------------------------

class TestAnalyzeEndpoint(TestCase):

    def test_valid_iptables_returns_200(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_valid_nftables_returns_200(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": NFTABLES_RULES}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_missing_rules_returns_400(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_empty_rules_returns_400(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": ""}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_response_contains_expected_keys(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        body = response.json()
        expected_keys = {
            "metrics", "redundant_rules", "shadowed_rules",
            "conflicts", "optimized_rules", "session_id",
        }
        self.assertEqual(expected_keys, set(body.keys()))

    def test_metrics_contains_expected_fields(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        metrics = response.json()["metrics"]
        for key in ["total_rules", "redundant_rules", "shadowed_rules",
                    "conflicting_pairs", "optimized_rule_count", "reduction_ratio"]:
            self.assertIn(key, metrics)

    def test_session_id_is_returned(self):
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        body = response.json()
        self.assertIn("session_id", body)
        self.assertTrue(len(body["session_id"]) > 0)

    def test_redundant_rule_detected(self):
        """The duplicate rule in IPTABLES_RULES must appear in redundant_rules."""
        response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        body = response.json()
        self.assertEqual(body["metrics"]["redundant_rules"], 1)

    def test_nftables_session_type(self):
        """An nftables submission should record rule_type='nftables' in the DB."""
        from api.models import AnalysisSession
        self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": NFTABLES_RULES}),
            content_type="application/json",
        )
        session = AnalysisSession.objects.last()
        self.assertEqual(session.rule_type, "nftables")


# ---------------------------------------------------------------------------
# History endpoint
# ---------------------------------------------------------------------------

class TestHistoryEndpoint(TestCase):

    def test_history_returns_200(self):
        response = self.client.get("/api/history/")
        self.assertEqual(response.status_code, 200)

    def test_history_initially_empty(self):
        response = self.client.get("/api/history/")
        self.assertEqual(response.json(), [])

    def test_session_appears_in_history_after_analyze(self):
        # Submit an analysis
        analyze_response = self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        session_id = analyze_response.json()["session_id"]

        # Fetch history
        history_response = self.client.get("/api/history/")
        ids = [str(s["id"]) for s in history_response.json()]
        self.assertIn(session_id, ids)

    def test_multiple_sessions_in_history(self):
        for _ in range(3):
            self.client.post(
                "/api/analyze/",
                data=json.dumps({"rules": IPTABLES_RULES}),
                content_type="application/json",
            )
        history = self.client.get("/api/history/").json()
        self.assertEqual(len(history), 3)

    def test_history_item_has_correct_fields(self):
        self.client.post(
            "/api/analyze/",
            data=json.dumps({"rules": IPTABLES_RULES}),
            content_type="application/json",
        )
        item = self.client.get("/api/history/").json()[0]
        for key in ["id", "created_at", "rule_type",
                    "total_rules", "redundant_count", "shadowed_count",
                    "conflict_count", "optimized_count"]:
            self.assertIn(key, item)

    def test_history_ordered_newest_first(self):
        """History is sorted by -created_at so newer sessions appear first."""
        for _ in range(2):
            self.client.post(
                "/api/analyze/",
                data=json.dumps({"rules": IPTABLES_RULES}),
                content_type="application/json",
            )
        history = self.client.get("/api/history/").json()
        # created_at of first item should be >= second item
        self.assertGreaterEqual(history[0]["created_at"], history[1]["created_at"])
