"""Compatibility shim - re-exports for backward compatibility."""

from janitor.types import Finding, RiskLevel
from janitor.analyzers.python import PythonAnalyzer

__all__ = [
    "PythonAnalyzer",
    "Finding",
    "RiskLevel",
]
