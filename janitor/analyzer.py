"""Static analyzer for Python code using AST."""

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


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
    complexity: Dict[str, int] = field(default_factory=dict)


class PythonAnalyzer:
    """Static analyzer for Python code using AST."""

    DANGEROUS_FUNCTIONS: Set[str] = {"eval", "exec", "compile"}
    SECRET_PATTERNS = [
        r'(?i)(api[_-]?key|apikey)\s*=\s*"[^"]+"',
        r'(?i)(secret[_-]?key|secretkey)\s*=\s*"[^"]+"',
        r'(?i)(password|passwd|pwd)\s*=\s*"[^"]+"',
        r'(?i)(token|auth[_-]?token)\s*=\s*"[^"]+"',
    ]
    SQL_INJECTION_PATTERNS = [
        r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*%s',
        r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*\+',
        r'(?i)(execute|cursor\.execute)\s*\(\s*f["\']',
        r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*\.format\s*\(',
    ]
    XSS_PATTERNS = [
        r'(?i)HttpResponse\s*\(\s*f["\']',
        r'(?i)render_template\s*\(.*\+\s*',
        r'(?i)markupsafe|Markup\s*\(\s*f["\']',
    ]
    DEBUG_PATTERNS = [
        r'(?i)DEBUG\s*=\s*True',
        r'(?i)app\.debug\s*=\s*True',
        r'(?i)FLASK_DEBUG\s*=\s*["\']?1',
        r'(?i)DJANGO_DEBUG\s*=\s*["\']?True',
    ]
    URL_PATTERNS = [
        r'(?i)(https?://[^\s"\x27]+(?:api\.|secret|internal|admin))',
        r'(?i)(mongodb|redis|postgres)://[^\s"\x27]+:[^\s"\x27]+@',
    ]

    def __init__(self, max_complexity: int = 10):
        self._compiled_patterns = [re.compile(p) for p in self.SECRET_PATTERNS]
        self._sql_patterns = [re.compile(p) for p in self.SQL_INJECTION_PATTERNS]
        self._xss_patterns = [re.compile(p) for p in self.XSS_PATTERNS]
        self._debug_patterns = [re.compile(p) for p in self.DEBUG_PATTERNS]
        self._url_patterns = [re.compile(p) for p in self.URL_PATTERNS]
        self.max_complexity = max_complexity

    def analyze_file(self, file_path: Path) -> PythonAnalysisResult:
        """Analyze a Python file and return results."""
        result = PythonAnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as e:
            result.has_errors = True
            result.error_message = f"Syntax error at line {e.lineno}: {e.msg}"
            self._add_finding(result, e.lineno or 0, 0, "syntax_error",
                            f"Invalid syntax: {e.msg}", RiskLevel.MEDIUM)
            return result

        self._extract_imports(tree, result)
        self._extract_functions(tree, result)
        self._extract_classes(tree, result)
        self._check_dangerous_calls(tree, result)
        self._check_secrets(content, result)
        self._check_sql_injection(content, result)
        self._check_xss(content, result)
        self._check_debug_mode(content, result)
        self._check_hardcoded_urls(content, result)
        self._check_complexity(tree, result)
        self._check_missing_docstrings(tree, result)
        self._check_unused_imports(tree, content, result)

        return result

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

    def _extract_imports(self, tree, result):
        """Extract all imports from AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    result.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    result.imports.append(f"{module}.{alias.name}" if module else alias.name)

    def _extract_functions(self, tree, result):
        """Extract all function definitions."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result.functions.append(node.name)

    def _extract_classes(self, tree, result):
        """Extract all class definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                result.classes.append(node.name)

    def _check_dangerous_calls(self, tree, result):
        """Check for dangerous function calls."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self.DANGEROUS_FUNCTIONS:
                    self._add_finding(result, node.lineno, node.col_offset,
                                    "dangerous_function",
                                    f"Use of {func_name}() can be dangerous",
                                    RiskLevel.HIGH,
                                    suggestion="Avoid eval/exec/compile. Consider safer alternatives.")
                elif func_name.startswith("subprocess"):
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                            if keyword.value.value is True:
                                self._add_finding(result, node.lineno, node.col_offset,
                                                "subprocess_shell_true",
                                                "shell=True in subprocess can allow command injection",
                                                RiskLevel.HIGH,
                                                suggestion="Use shell=False and pass commands as a list.")
                elif func_name == "pickle.load" or func_name == "pickle.loads":
                    self._add_finding(result, node.lineno, node.col_offset,
                                    "unsafe_pickle",
                                    "pickle can execute arbitrary code on deserialization",
                                    RiskLevel.HIGH,
                                    suggestion="Use json or msgpack instead of pickle for untrusted data.")

    def _get_call_name(self, node):
        """Get full name of a function call."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            return node.attr
        return ""

    def _check_secrets(self, content, result):
        """Check for secret patterns in code."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._compiled_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "potential_secret",
                                    "Possible secret or credential hardcoded",
                                    RiskLevel.CRITICAL,
                                    code_snippet=line.strip(),
                                    suggestion="Use environment variables or a secrets manager.")
                    break

    def _check_sql_injection(self, content, result):
        """Check for potential SQL injection patterns."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._sql_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "sql_injection",
                                    "Potential SQL injection - using string formatting in query",
                                    RiskLevel.CRITICAL,
                                    code_snippet=line.strip(),
                                    suggestion="Use parameterized queries instead of string formatting.")
                    break

    def _check_xss(self, content, result):
        """Check for potential XSS patterns."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._xss_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "potential_xss",
                                    "Potential XSS vulnerability - unescaped user input",
                                    RiskLevel.HIGH,
                                    code_snippet=line.strip(),
                                    suggestion="Use proper escaping or templating with auto-escape enabled.")
                    break

    def _check_debug_mode(self, content, result):
        """Check for debug mode enabled in production code."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._debug_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "debug_enabled",
                                    "Debug mode is enabled - should be disabled in production",
                                    RiskLevel.MEDIUM,
                                    code_snippet=line.strip(),
                                    suggestion="Set DEBUG=False in production environments.")
                    break

    def _check_hardcoded_urls(self, content, result):
        """Check for hardcoded URLs with credentials."""
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern in self._url_patterns:
                if pattern.search(line):
                    self._add_finding(result, i, 0, "hardcoded_url",
                                    "Hardcoded URL with potential credentials",
                                    RiskLevel.HIGH,
                                    code_snippet=line.strip(),
                                    suggestion="Use environment variables for connection strings.")
                    break

    def _check_complexity(self, tree, result):
        """Calculate cyclomatic complexity for each function."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._calculate_complexity(node)
                result.complexity[node.name] = complexity
                if complexity > self.max_complexity:
                    self._add_finding(result, node.lineno, node.col_offset,
                                    "high_complexity",
                                    f"Function '{node.name}' has cyclomatic complexity of {complexity} (max: {self.max_complexity})",
                                    RiskLevel.MEDIUM,
                                    suggestion="Consider refactoring into smaller functions.")

    def _calculate_complexity(self, node) -> int:
        """Calculate cyclomatic complexity for a function node."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
                if child.ifs:
                    complexity += len(child.ifs)
        return complexity

    def _check_missing_docstrings(self, tree, result):
        """Check for functions and classes without docstrings."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not ast.get_docstring(node):
                    self._add_finding(result, node.lineno, node.col_offset,
                                    "missing_docstring",
                                    f"{'Function' if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else 'Class'} '{node.name}' has no docstring",
                                    RiskLevel.LOW,
                                    suggestion="Add a docstring to document the purpose and usage.")

    def _check_unused_imports(self, tree, content, result):
        """Check for imports that are not used in the code."""
        imported_names = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno

        lines = content.split("\n")
        for name, line_num in imported_names.items():
            if name == "_":
                continue
            used = False
            for i, line in enumerate(lines):
                if i == line_num - 1:
                    continue
                if re.search(r'\b' + re.escape(name) + r'\b', line):
                    used = True
                    break
            if not used:
                self._add_finding(result, line_num, 0,
                                "unused_import",
                                f"Import '{name}' is not used",
                                RiskLevel.LOW,
                                suggestion="Remove unused imports to keep code clean.")


def analyze_python_file(file_path: Path) -> PythonAnalysisResult:
    """Helper function to analyze a Python file."""
    analyzer = PythonAnalyzer()
    return analyzer.analyze_file(file_path)
