"""Shared types for all analyzers."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List
from pathlib import Path


class RiskLevel(Enum):
    """Risk levels for vulnerabilities."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Represents a static analysis finding."""
    file: str
    line: int
    column: int
    issue_type: str
    message: str
    risk_level: RiskLevel
    code_snippet: str = ""
    suggestion: str = ""


@dataclass
class PythonAnalysisResult:
    """Result of analyzing a Python file."""
    file_path: Path
    findings: List[Finding] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    has_errors: bool = False
    error_message: str = ""
    complexity: dict = field(default_factory=dict)
