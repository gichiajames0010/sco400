from django.urls import path
from .views import AnalyzeRulesView, AnalysisHistoryView

urlpatterns = [
    path("analyze/", AnalyzeRulesView.as_view()),
    path("history/", AnalysisHistoryView.as_view()),
]
