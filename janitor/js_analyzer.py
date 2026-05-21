"""Static analyzer for JavaScript/TypeScript code."""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field
from janitor.analyzer import Finding, RiskLevel, PythonAnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class JSAnalysisResult:
    """Result of analyzing a JS/TS file."""
    file_path: Path
    findings: List[Finding] = field(default_factory=list)
    has_errors: bool = False
    error_message: str = ""


class JSAnalyzer:
    """Static analyzer for JavaScript/TypeScript code."""

    DANGEROUS_FUNCTIONS = [
        r'\beval\s*\(',
        r'\bFunction\s*\(',
        r'\bsetTimeout\s*\(\s*["\x27]',
        r'\bsetInterval\s*\(\s*["\x27]',
    ]

    SECURITY_PATTERNS = [
        (r'\binnerHTML\s*=', 'dom_xss', 'Using innerHTML can lead to XSS', RiskLevel.HIGH),
        (r'\bdocument\.write\s*\(', 'dom_xss', 'Using document.write can lead to XSS', RiskLevel.HIGH),
        (r'\bexecScript\s*\(', 'dom_xss', 'Using execScript is dangerous', RiskLevel.HIGH),
        (r'\blocalStorage\.setItem\s*\(.*password', 'storage_secret', 'Storing passwords in localStorage', RiskLevel.CRITICAL),
        (r'\bconsole\.(log|warn|error|info|debug)\s*\(', 'console_log', 'Console statement left in code', RiskLevel.LOW),
        (r'\bdebugger\s*;?', 'debugger_statement', 'Debugger statement left in code', RiskLevel.MEDIUM),
        (r'\balert\s*\(', 'alert_usage', 'Using alert() is not recommended', RiskLevel.LOW),
    ]

    TS_PATTERNS = [
        (r':\s*any\b', 'any_type', 'Using "any" type defeats TypeScript purpose', RiskLevel.MEDIUM),
        (r'//\s*@ts-ignore', 'ts_ignore', 'Using @ts-ignore suppresses type checking', RiskLevel.MEDIUM),
        (r'//\s*@ts-nocheck', 'ts_nocheck', 'Using @ts-nocheck disables type checking for file', RiskLevel.HIGH),
    ]

    def __init__(self):
        self._dangerous_patterns = [re.compile(p) for p in self.DANGEROUS_FUNCTIONS]

    def analyze_file(self, file_path: Path) -> JSAnalysisResult:
        """Analyze a JS/TS file and return results."""
        result = JSAnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        self._check_dangerous_functions(content, result)
        self._check_security_patterns(content, result)

        if file_path.suffix in ('.ts', '.tsx'):
            self._check_typescript_patterns(content, result)

        return result

    def _check_dangerous_functions(self, content, result):
        """Check for dangerous function calls."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._dangerous_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "dangerous_function",
                                    "Use of dangerous function detected",
                                    RiskLevel.HIGH,
                                    code_snippet=line.strip(),
                                    suggestion="Avoid eval/Function with dynamic content.")
                    break

    def _check_security_patterns(self, content, result):
        """Check for security-related patterns."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern, issue_type, message, risk_level in self.SECURITY_PATTERNS:
                if re.search(pattern, line):
                    if issue_type == 'dom_xss' and self._is_false_positive_innerhtml(line):
                        continue
                    self._add_finding(result, i, 0, issue_type,
                                    message, risk_level,
                                    code_snippet=line.strip())
                    break

    def _is_false_positive_innerhtml(self, line: str) -> bool:
        """Check if innerHTML usage is a false positive."""
        stripped = line.strip()
        if re.search(r'innerHTML\s*=\s*["\x27]\s*["\x27]', stripped):
            return True
        if re.search(r'innerHTML\s*=\s*["\x27][^"\x27]*["\x27]\s*[;]', stripped):
            return True
        return False

    def _check_typescript_patterns(self, content, result):
        """Check for TypeScript-specific issues."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern, issue_type, message, risk_level in self.TS_PATTERNS:
                if re.search(pattern, line):
                    self._add_finding(result, i, 0, issue_type,
                                    message, risk_level,
                                    code_snippet=line.strip())
                    break

    def _add_finding(self, result, line, column, issue_type, message, risk_level, code_snippet="", suggestion=""):
        """Add a finding to results."""
        finding = Finding(
            file=str(result.file_path),
            line=line,
            column=column,
            issue_type=issue_type,
            message=message,
            risk_level=risk_level,
            code_snippet=code_snippet,
            suggestion=suggestion
        )
        result.findings.append(finding)


def analyze_js_file(file_path: Path) -> JSAnalysisResult:
    """Helper function to analyze a JS/TS file."""
    analyzer = JSAnalyzer()
    return analyzer.analyze_file(file_path)
