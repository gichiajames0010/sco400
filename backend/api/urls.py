"""
URL configuration for the Firewall Rule Analyzer API.

Routes are registered under the /api/ prefix defined in the project-level
urls.py.  Full endpoint paths are therefore:

  POST  /api/analyze/   — Submit rules for analysis.
  GET   /api/history/   — Retrieve a list of past analysis sessions.
"""

from django.urls import path
from .views import AnalyzeRulesView, AnalysisHistoryView

urlpatterns = [
    # POST — accept raw firewall rules and return a full analysis result.
    path("analyze/", AnalyzeRulesView.as_view(), name="analyze-rules"),

    # GET — return a list of all past AnalysisSession records.
    path("history/", AnalysisHistoryView.as_view(), name="analysis-history"),
]
