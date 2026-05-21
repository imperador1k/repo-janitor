"""Base analyzer interface for all language analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
from janitor.types import Finding, RiskLevel


@dataclass
class AnalysisResult:
    """Generic result of analyzing a file."""
    file_path: Path
    findings: List[Finding] = field(default_factory=list)
    has_errors: bool = False
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    """Abstract base class for all language analyzers."""

    @abstractmethod
    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a single file and return results."""
        ...

    @abstractmethod
    def get_language(self) -> str:
        """Return the language this analyzer handles."""
        ...

    def get_supported_extensions(self) -> List[str]:
        """Return file extensions this analyzer supports."""
        return []

    def get_file_patterns(self) -> List[str]:
        """Return filename patterns this analyzer supports (e.g., 'Dockerfile')."""
        return []

    def can_analyze(self, file_path: Path) -> bool:
        """Check if this analyzer can handle the given file."""
        ext = file_path.suffix.lower()
        if ext in self.get_supported_extensions():
            return True
        if file_path.name in self.get_file_patterns():
            return True
        return False

    def analyze_files(self, file_paths: List[Path]) -> List[AnalysisResult]:
        """Analyze multiple files and return combined results."""
        results = []
        for file_path in file_paths:
            if self.can_analyze(file_path):
                results.append(self.analyze_file(file_path))
        return results

    def get_findings_summary(self, results: List[AnalysisResult]) -> Dict[str, int]:
        """Get a summary of findings by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for result in results:
            for finding in result.findings:
                severity = finding.risk_level.value
                if severity in summary:
                    summary[severity] += 1
                summary["total"] += 1
        return summary
