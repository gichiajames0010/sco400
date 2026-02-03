from django.urls import path
from .views import AnalyzeRulesView

urlpatterns = [
    path("analyze/", AnalyzeRulesView.as_view()),
]
