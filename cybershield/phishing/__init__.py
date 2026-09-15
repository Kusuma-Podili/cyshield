"""Phishing & Email Security Analysis Module for CyberShield Enterprise."""

from cybershield.phishing.email_analyzer import EmailSecurityAnalyzer, levenshtein_distance
from cybershield.phishing.service import PhishingService, phishing_service
from cybershield.phishing.routes import router

__all__ = [
    "EmailSecurityAnalyzer",
    "levenshtein_distance",
    "PhishingService",
    "phishing_service",
    "router",
]
