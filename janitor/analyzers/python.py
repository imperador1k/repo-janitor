"""Elite static analyzer for Python code with comprehensive security checks."""

import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Callable, Set
from dataclasses import dataclass, field

from janitor.analyzers.base import BaseAnalyzer, AnalysisResult
from janitor.types import Finding, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class SecurityCheck:
    """A 'security unit test' for Python code."""
    id: str
    name: str
    category: str
    severity: RiskLevel
    description: str
    pattern: re.Pattern
    context_checks: List[Callable[[str, str, List[str]], bool]] = field(default_factory=list)
    suggestion: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    remediation_example: str = ""
    attack_vector: str = ""
    mitre_technique: str = ""


class PythonAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Python code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "python"

    def get_supported_extensions(self) -> List[str]:
        return [".py", ".pyi", ".pyx"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Python file and return results."""
        result = AnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        self._current_path = file_path

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as e:
            result.has_errors = True
            result.error_message = f"Syntax error at line {e.lineno}: {e.msg}"
            finding = Finding(
                file=str(file_path), line=e.lineno or 0, column=0,
                issue_type="PY-SYNTAX-001",
                message=f"Invalid Python syntax: {e.msg}",
                risk_level=RiskLevel.MEDIUM,
                suggestion="Fix the syntax error before deploying",
            )
            result.findings.append(finding)
            return result

        result.metadata["imports"] = self._extract_imports(tree)
        result.metadata["functions"] = self._extract_functions(tree)
        result.metadata["classes"] = self._extract_classes(tree)

        lines = content.split("\n")
        detected_frameworks = self._detect_frameworks(content, file_path)
        result.metadata["frameworks"] = detected_frameworks

        for i, line in enumerate(lines, 1):
            for check in self.checks:
                if check.pattern.search(line):
                    if self._passes_context_checks(check, line, content, detected_frameworks):
                        self._add_finding(result, i, line, check)

        self._run_taint_analysis(content, lines, result, detected_frameworks)
        self._run_cross_line_analysis(content, lines, result, detected_frameworks)

        return result

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract imports from AST."""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)
        return imports

    def _extract_functions(self, tree: ast.AST) -> List[str]:
        """Extract function definitions."""
        return [node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _extract_classes(self, tree: ast.AST) -> List[str]:
        """Extract class definitions."""
        return [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by severity."""
        checks = []

        # ====================================================================
        # CRITICAL CHECKS
        # ====================================================================

        checks.extend([
            # PY-EVAL-001
            SecurityCheck(
                id="PY-EVAL-001",
                name="Code Injection via eval()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="eval() executes arbitrary Python code from string input",
                pattern=re.compile(r'\beval\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Use ast.literal_eval() for data, or proper parsers",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="import ast\ntry:\n    result = ast.literal_eval(user_input)\nexcept ValueError:\n    # handle invalid input",
                attack_vector="User input -> eval() -> RCE -> Full compromise",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-EXEC-001
            SecurityCheck(
                id="PY-EXEC-001",
                name="Code Injection via exec()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="exec() executes arbitrary Python code and can compromise the application",
                pattern=re.compile(r'\bexec\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Avoid exec entirely. Use restricted eval or proper program logic",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Never use exec() with user input\n# Use predefined functions instead:\ntransformers = {'uppercase': str.upper, 'lowercase': str.lower}\nresult = transformers[selected](data)",
                attack_vector="User input -> exec() -> RCE -> Full compromise",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-COMPILE-001
            SecurityCheck(
                id="PY-COMPILE-001",
                name="Code Injection via compile()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="compile() with user input enables arbitrary code execution via exec/eval",
                pattern=re.compile(r'\bcompile\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Avoid compile() with untrusted input. Use safer alternatives",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="# compile() should never receive user input\n# Use ast.literal_eval for safe evaluation",
                attack_vector="User input -> compile() -> exec() -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-CMD-001: os.system
            SecurityCheck(
                id="PY-CMD-001",
                name="Command Injection via os.system",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="os.system() passes strings to shell, enabling command injection",
                pattern=re.compile(r'\bos\.system\s*\('),
                context_checks=[self._is_fp_cmd],
                suggestion="Use subprocess.run with a list of arguments (shell=False)",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="import subprocess\nsubprocess.run(['ls', '-la', safe_dir], shell=False)",
                attack_vector="User input -> os.system() -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PY-CMD-002: subprocess shell=True
            SecurityCheck(
                id="PY-CMD-002",
                name="Command Injection via subprocess shell=True",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="subprocess with shell=True enables shell injection via string arguments",
                pattern=re.compile(r'subprocess\.\w+\s*\([^)]*\bshell\s*=\s*True'),
                context_checks=[],
                suggestion="Use shell=False with argument list instead of shell string",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="subprocess.run(['grep', '-r', pattern, target_dir], shell=False)",
                attack_vector="User input -> subprocess(shell=True) -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PY-CMD-003: os.popen
            SecurityCheck(
                id="PY-CMD-003",
                name="Command Injection via os.popen",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="os.popen() executes commands via shell, enabling injection",
                pattern=re.compile(r'\bos\.popen\s*\('),
                context_checks=[self._is_fp_cmd],
                suggestion="Use subprocess.run with argument list (shell=False)",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="import subprocess\nresult = subprocess.run(['ls'], capture_output=True, shell=False)",
                attack_vector="User input -> os.popen() -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PY-SQL-001: f-string in SQL
            SecurityCheck(
                id="PY-SQL-001",
                name="SQL Injection via f-string Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Using f-strings to build SQL queries allows direct SQL injection",
                pattern=re.compile(r'(?i)(execute|cursor\.execute|\.raw|\.filter|\.having)\s*\(\s*f["\x27]'),
                context_checks=[self._is_fp_sql],
                suggestion="Use parameterized queries with placeholders (%s or ?)",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                attack_vector="User input -> f-string in SQL -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-SQL-002: format/sprintf in SQL
            SecurityCheck(
                id="PY-SQL-002",
                name="SQL Injection via %s Format String",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String formatting (.format() or %s) in SQL queries enables injection",
                pattern=re.compile(r'(?i)(execute|cursor\.execute)\s*\(\s*["\x27][^"\x27]*%(?:\(?\w+\)?)?[sdf]'),
                context_checks=[self._is_fp_sql],
                suggestion="Use parameterized queries with DB-API placeholders (%s for psycopg2, ? for sqlite3)",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="cursor.execute('SELECT * FROM users WHERE id = %s', [user_id])",
                attack_vector="User input -> format string in SQL -> SQLi -> Database dump",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-SQL-003: Django raw() / RawSQL
            SecurityCheck(
                id="PY-SQL-003",
                name="SQL Injection via Django RawSQL",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Django RawSQL or raw() with string formatting allows SQL injection",
                pattern=re.compile(r'(?i)(raw\s*\(|RawSQL\s*\(|Extra\s*\(.*where|annotate.*RawSQL)'),
                context_checks=[self._is_fp_sql],
                suggestion="Use Django ORM query parameters instead of string formatting",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="Model.objects.raw('SELECT * FROM table WHERE id = %s', [params])",
                attack_vector="User input -> RawSQL -> SQLi -> Database access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-SQL-004: SQLAlchemy text() dangers
            SecurityCheck(
                id="PY-SQL-004",
                name="SQL Injection via SQLAlchemy text()",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="SQLAlchemy text() with string formatting enables SQL injection",
                pattern=re.compile(r'(?i)text\s*\(\s*f["\x27]|text\s*\(\s*["\x27][^"\x27]*%(?:\(?\w+\)?)?[sdf]'),
                context_checks=[self._is_fp_sql],
                suggestion="Use SQLAlchemy text() with bound parameters (:param_name)",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="session.execute(text('SELECT * FROM users WHERE id = :uid'), {'uid': user_id})",
                attack_vector="User input -> SQLAlchemy text() -> SQLi -> Database access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-SQL-005: psycopg2 string formatting
            SecurityCheck(
                id="PY-SQL-005",
                name="SQL Injection via psycopg2 String Formatting",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="psycopg2 queries built with string operators (% or +) enable SQL injection",
                pattern=re.compile(r'(?i)(psycopg2\.connect|\.execute)\s*\([^)]*["\x27].*[%\+]'),
                context_checks=[self._is_fp_sql],
                suggestion="Always use %s placeholders with psycopg2's automatic parameterization",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="cur.execute('INSERT INTO users (name) VALUES (%s)', (user_name,))",
                attack_vector="User input -> psycopg2 string concat -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-DESER-001: pickle
            SecurityCheck(
                id="PY-DESER-001",
                name="Unsafe Deserialization via pickle",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="pickle.loads() can execute arbitrary Python code during deserialization",
                pattern=re.compile(r'\bpickle\.loads?\s*\('),
                context_checks=[self._is_fp_deser],
                suggestion="Use json, msgpack, or yaml.safe_load() instead of pickle",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="import json\ndata = json.loads(untrusted_string)  # Safe alternative",
                attack_vector="Malicious pickle payload -> __reduce__ execution -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-DESER-002: yaml.load
            SecurityCheck(
                id="PY-DESER-002",
                name="Unsafe Deserialization via yaml.load",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="yaml.load() (without Loader=yaml.SafeLoader) can execute arbitrary code",
                pattern=re.compile(r'\byaml\.load\s*\(\s*(?!.*SafeLoader|.*BaseLoader)'),
                context_checks=[self._is_fp_yaml],
                suggestion="Use yaml.safe_load() instead of yaml.load()",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="import yaml\ndata = yaml.safe_load(untrusted_yaml)  # Safe",
                attack_vector="Malicious YAML with !!python/object -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-DESER-003: jsonpickle
            SecurityCheck(
                id="PY-DESER-003",
                name="Unsafe Deserialization via jsonpickle",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="jsonpickle.decode() can reconstruct arbitrary Python objects",
                pattern=re.compile(r'\bjsonpickle\.(decode|loads)\s*\('),
                context_checks=[],
                suggestion="Use plain json.loads() instead of jsonpickle for untrusted data",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="import json\ndata = json.loads(json_string)  # Safe; no object reconstruction",
                attack_vector="Malicious jsonpickle payload -> Object reconstruction -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-SSTI-001: Jinja2 SSTI
            SecurityCheck(
                id="PY-SSTI-001",
                name="Server-Side Template Injection (Jinja2)",
                category="ssti",
                severity=RiskLevel.CRITICAL,
                description="Passing user input to Jinja2 rendering from string can enable SSTI",
                pattern=re.compile(r'(?i)Jinja2|jinja2|from_string|Template\s*\('),
                context_checks=[self._is_fp_ssti],
                suggestion="Never render templates from user-controlled strings. Use template files with context variables",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="from jinja2 import Environment, FileSystemLoader\nenv = Environment(loader=FileSystemLoader('templates'))\ntemplate = env.get_template('safe_template.html')",
                attack_vector="User input -> Jinja2 from_string -> {{ config }} / RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-SSTI-002: Mako SSTI
            SecurityCheck(
                id="PY-SSTI-002",
                name="Server-Side Template Injection (Mako)",
                category="ssti",
                severity=RiskLevel.CRITICAL,
                description="Mako templates from user strings can enable SSTI and RCE",
                pattern=re.compile(r'(?i)mako\.template|Template\s*\(.*mako|TemplateLookup'),
                context_checks=[self._is_fp_ssti],
                suggestion="Use the Mako template lookup with file-based templates, not from_string",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="from mako.lookup import TemplateLookup\nlookup = TemplateLookup(directories=['templates'])\ntemplate = lookup.get_template('page.html')",
                attack_vector="User input -> Mako template -> <% import os %> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-XSS-001: Django mark_safe/|safe
            SecurityCheck(
                id="PY-XSS-001",
                name="XSS via Django mark_safe or |safe filter",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="mark_safe() or the |safe template filter disables HTML escaping",
                pattern=re.compile(r'(\bmark_safe\s*\()|(\|\s*safe\b[^{]|\.\s*safe\s*=\s*True)'),
                context_checks=[self._is_fp_xss],
                suggestion="Avoid marking user input as safe. Use format_html() instead",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="from django.utils.html import format_html\nreturn format_html('<b>{}</b>', user_input)  # Auto-escaped",
                attack_vector="User input -> mark_safe() -> XSS in response -> Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PY-XSS-002: format_html with user input
            SecurityCheck(
                id="PY-XSS-002",
                name="XSS via format_html Misuse",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Using format_html() with format specifiers or embedded HTML can bypass escaping",
                pattern=re.compile(r'format_html\s*\(\s*f["\x27]|format_html\s*\(\s*["\x27][^"\x27]*<[^>]*>["\x27]'),
                context_checks=[self._is_fp_xss],  # false positive when all args are escaped
                suggestion="Use format_html with positional arguments and avoid HTML in the format string",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="format_html('<a href={}>{}</a>', url, label)  # Both values escaped",
                attack_vector="User input -> format_html -> Unescaped HTML -> XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PY-XSS-003: Flask render_template_string
            SecurityCheck(
                id="PY-XSS-003",
                name="XSS via Flask render_template_string",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="render_template_string with user input enables both XSS and SSTI",
                pattern=re.compile(r'render_template_string\s*\('),
                context_checks=[self._is_fp_ssti],
                suggestion="Use render_template with file-based templates, not render_template_string",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="from flask import render_template\nreturn render_template('page.html', data=user_data)",
                attack_vector="User input -> render_template_string -> SSTI/XSS -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PY-PATH-001: Path traversal
            SecurityCheck(
                id="PY-PATH-001",
                name="Path Traversal via open()",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="open() with user-controlled path can access arbitrary files via ../",
                pattern=re.compile(r'\bopen\s*\([^)]*\b(user|path|filename|file|input|data|name)'),
                context_checks=[self._is_fp_file_op],
                suggestion="Use os.path.abspath() and verify path is within allowed directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="import os\nBASE_DIR = '/app/data/'\nfull_path = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not full_path.startswith(BASE_DIR):\n    raise ValueError('Invalid path')",
                attack_vector="User input -> open() with ../ -> Arbitrary file read",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # PY-PATH-002: Path via Path.read_text
            SecurityCheck(
                id="PY-PATH-002",
                name="Path Traversal via Path().read_text",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="Path.read_text/write_text with user input can traverse directories",
                pattern=re.compile(r'Path\s*\([^)]*\b(user|path|filename|file|input|data|name)\)\.(read|write)'),
                context_checks=[self._is_fp_file_op],
                suggestion="Resolve canonical path and check prefix before file operations",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="from pathlib import Path\nsafe_dir = Path('/app/data/')\ntarget = (safe_dir / user_filename).resolve()\nif not str(target).startswith(str(safe_dir)):\n    raise ValueError('Invalid path')",
                attack_vector="User input -> Path.read_text -> ../ traversal -> File read",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # PY-SSRF-001: SSRF via requests
            SecurityCheck(
                id="PY-SSRF-001",
                name="Server-Side Request Forgery (SSRF)",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="requests.get() with user-controlled URL can target internal services",
                pattern=re.compile(r'(requests|urllib|httpx|aiohttp)\.(get|post|put|delete|request|head|options|patch)\s*\('),
                context_checks=[self._is_fp_url],
                suggestion="Validate URL against an allowlist. Block private IP ranges",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="from urllib.parse import urlparse\nfrom allowlist import ALLOWED_DOMAINS\nparsed = urlparse(url)\nif parsed.hostname not in ALLOWED_DOMAINS:\n    raise ValueError('Domain not allowed')",
                attack_vector="User input -> requests.get() -> Internal network scan / Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # PY-AUTH-001: Hardcoded Django SECRET_KEY
            SecurityCheck(
                id="PY-AUTH-001",
                name="Hardcoded Django/Flask SECRET_KEY",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded SECRET_KEY allows session forgery and cryptographic attacks",
                pattern=re.compile(r'(?i)(SECRET_KEY|FLASK_SECRET)\s*=\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables and a secrets manager for SECRET_KEY",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="import os\nSECRET_KEY = os.environ['SECRET_KEY']\n# Never: SECRET_KEY = 'my-dev-key-12345'",
                attack_vector="Hardcoded SECRET_KEY -> Session forgery / signed cookie tampering",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # PY-AUTH-002: Hardcoded password
            SecurityCheck(
                id="PY-AUTH-002",
                name="Hardcoded Password / Credential",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded passwords, API keys, or tokens in source code",
                pattern=re.compile(r'(?i)(password|passwd|pwd|api[_-]?key|secret[_-]?key|token|auth[_-]?token)\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables, .env files, or a secrets manager",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="import os\nDB_PASSWORD = os.getenv('DB_PASSWORD')\nAPI_KEY = os.getenv('API_KEY')",
                attack_vector="Source leak (GitHub) -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # PY-CRYPTO-001: MD5/SHA1
            SecurityCheck(
                id="PY-CRYPTO-001",
                name="Weak Hashing Algorithm (MD5/SHA1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks",
                pattern=re.compile(r'(?i)hashlib\.(md5|sha1)\s*\('),
                context_checks=[self._is_fp_hash],
                suggestion="Use hashlib.sha256() or stronger; use bcrypt/argon2 for passwords",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import hashlib\nhash_obj = hashlib.sha256(data.encode()).hexdigest()  # Secure",
                attack_vector="Collision attack on MD5/SHA1 -> Signature forgery",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PY-CRYPTO-002: Hardcoded crypto key
            SecurityCheck(
                id="PY-CRYPTO-002",
                name="Hardcoded Encryption Key",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Hardcoded AES/RSA keys in source code can be extracted from leaks",
                pattern=re.compile(r'(?i)(aes|des|rsa|fernet|encrypt).*(key|secret)\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Store encryption keys in a KMS or environment variables",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import os\nfrom cryptography.fernet import Fernet\nkey = os.environ['ENCRYPTION_KEY']  # From KMS/env",
                attack_vector="Hardcoded encryption key -> Decrypt all protected data",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # PY-CRYPTO-003: ECB mode
            SecurityCheck(
                id="PY-CRYPTO-003",
                name="Insecure Block Cipher Mode (ECB)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="ECB mode encrypts identical plaintext blocks to identical ciphertext blocks",
                pattern=re.compile(r'(?i)(AES|DES)\s*\.\s*new\s*\([^)]*\bECB\b|MODE_ECB'),
                context_checks=[],
                suggestion="Use CBC with random IV, or GCM/CTR mode with authentication",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="from Crypto.Cipher import AES\nfrom Crypto.Random import get_random_bytes\niv = get_random_bytes(16)\ncipher = AES.new(key, AES.MODE_CBC, iv)",
                attack_vector="ECB mode -> Pattern leakage in encrypted data -> Data exposure",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PY-CRYPTO-004: random module
            SecurityCheck(
                id="PY-CRYPTO-004",
                name="Insecure Random for Security Context",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="random module is predictable and should not be used for security tokens",
                pattern=re.compile(r'\brandom\.(choice|choices|randint|randrange|random|sample|shuffle)\s*\('),
                context_checks=[self._is_fp_random],
                suggestion="Use secrets module (Python 3.6+) or os.urandom for security-sensitive values",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import secrets\ntoken = secrets.token_hex(32)  # Cryptographically secure",
                attack_vector="Predictable random token -> Session hijacking / CSRF bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PY-CRYPTO-005: Timing attack
            SecurityCheck(
                id="PY-CRYPTO-005",
                name="Timing Attack via String Comparison",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="String/length comparison of secrets leaks timing information to attackers",
                pattern=re.compile(r'(?i)(\bhsecret\b|\btoken\b|\bsignature\b|\bhmac\b|\bapi_key\b)\s*(==|!=|is\s+not|is)\s+'),
                context_checks=[self._is_fp_timing],
                suggestion="Use hmac.compare_digest() for constant-time comparison",
                cwe_id="CWE-208",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import hmac\nif hmac.compare_digest(received_token, expected_token):\n    # constant-time comparison",
                attack_vector="Timing side-channel -> Character-by-character secret recovery",
                mitre_technique="T1600.002 - Weaken Encryption: Reducing Key Space",
            ),
            # PY-NOSQL-001: MongoDB injection
            SecurityCheck(
                id="PY-NOSQL-001",
                name="NoSQL Injection (MongoDB)",
                category="nosql-injection",
                severity=RiskLevel.HIGH,
                description="Unsanitized user input in MongoDB queries with $regex, $ne, $where operators",
                pattern=re.compile(r'(?i)(pymongo|mongodb|motor)\..*(find|find_one|update|aggregate|delete)\s*\(\s*\{[^}]*\$\w+'),
                context_checks=[self._is_fp_nosql],
                suggestion="Sanitize query input and reject operator keys ($, $gt, $ne)",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="import re\ndef sanitize_query(data):\n    if isinstance(data, dict):\n        return {k: sanitize_query(v) for k, v in data.items() if not k.startswith('$')}\n    return data",
                attack_vector="User input with $ne/$regex -> MongoDB query bypass -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-LDAP-001: LDAP injection
            SecurityCheck(
                id="PY-LDAP-001",
                name="LDAP Injection",
                category="ldap-injection",
                severity=RiskLevel.HIGH,
                description="LDAP queries with unsanitized user input can bypass filters",
                pattern=re.compile(r'(?i)(ldap3|python-ldap).*(search|bind|simple_bind)\s*\('),
                context_checks=[self._is_fp_ldap],
                suggestion="Escape LDAP special characters (\\, *, (, ), etc.) in user input",
                cwe_id="CWE-90",
                owasp_category="A03:2021 - Injection",
                remediation_example="import ldap3\nfrom ldap3.utils.conv import escape_filter_chars\nsafe_filter = f'(uid={escape_filter_chars(user_input)})'",
                attack_vector="User input -> LDAP filter -> Bypass / Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-XXE-001: XML entities
            SecurityCheck(
                id="PY-XXE-001",
                name="XML External Entity (XXE) Injection",
                category="xxe",
                severity=RiskLevel.HIGH,
                description="XML parsing without disabling external entities can expose files or SSRF",
                pattern=re.compile(r'(?i)(xml\.etree|ElementTree|lxml|minidom|xml\.dom|sax|xml\.sax|etree|parse\s*\(.*\.xml)'),
                context_checks=[self._is_fp_xxe],
                suggestion="Disable external entity processing when parsing XML",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.parse(source, parser)",
                attack_vector="Malicious XML with external entity -> File read / SSRF",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # PY-CORS-001: Wildcard CORS
            SecurityCheck(
                id="PY-CORS-001",
                name="Overly Permissive CORS (Wildcard)",
                category="cors",
                severity=RiskLevel.HIGH,
                description="Flask/Django CORS with origins='*' exposes API to all domains",
                pattern=re.compile(r"(?i)(CORS|cors|flask-cors|django-cors-headers).*([\"\x27]\*[\"\x27]|origins\s*=\s*[\"\x27]\*[\"\x27])"),
                context_checks=[self._is_fp_dev],
                suggestion="Specify exact allowed origins in an allowlist",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="CORS(app, origins=['https://app.example.com'])",
                attack_vector="Wildcard CORS -> Any domain reads API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # PY-CSRF-001: @csrf_exempt
            SecurityCheck(
                id="PY-CSRF-001",
                name="CSRF Protection Disabled (Django @csrf_exempt)",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="@csrf_exempt or @csrf_exempt disables CSRF protection for the view",
                pattern=re.compile(r'@csrf_exempt|csrf_exempt|@method_decorator.*csrf_exempt'),
                context_checks=[],
                suggestion="Remove @csrf_exempt and use proper CSRF tokens for state-changing operations",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="# Remove @csrf_exempt decorator\n# Django handles CSRF by default\n# For API views, use @method_decorator(csrf_protect)",
                attack_vector="Missing CSRF -> Attacker forges authenticated request -> State change",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PY-REDIR-001: Open redirect
            SecurityCheck(
                id="PY-REDIR-001",
                name="Open Redirect via User-Controlled URL",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="redirect() or HttpResponseRedirect with user input enables phishing",
                pattern=re.compile(r'(?i)(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect)\s*\(\s*[^)]*\b(request|next|url|return_url|redirect_to)\b'),
                context_checks=[self._is_fp_redirect],
                suggestion="Validate redirect URLs against an allowlist of trusted domains",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="from urllib.parse import urlparse\nALLOWED_HOSTS = ['example.com']\nparsed = urlparse(redirect_url)\nif parsed.hostname in ALLOWED_HOSTS:\n    return redirect(redirect_url)\nreturn redirect('/fallback')",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # PY-TOCTOU-001: Race condition
            SecurityCheck(
                id="PY-TOCTOU-001",
                name="Time-of-Check Time-of-Use (TOCTOU) Race Condition",
                category="race-condition",
                severity=RiskLevel.HIGH,
                description="os.path.exists() followed by open() creates a race window for symlink attacks",
                pattern=re.compile(r'os\.path\.(exists|isfile|islink|isdir)\s*\([^)]*\)[\s\S]{0,200}os\.(remove|unlink|rename|open|chmod|chown)'),
                context_checks=[],
                suggestion="Use exceptions (try/except OSError) instead of check-then-act patterns",
                cwe_id="CWE-367",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="try:\n    with open(filepath, 'w') as f:\n        f.write(data)\n except OSError as e:\n    if e.errno == errno.ENOENT:\n        # handle missing file\n    # Check-fail pattern avoids race conditions",
                attack_vector="Symlink planted between check and use -> Arbitrary file write",
                mitre_technique="T1055 - Process Injection",
            ),
            # PY-AUTH-003: Paramiko missing host key
            SecurityCheck(
                id="PY-AUTH-003",
                name="SSH Host Key Verification Disabled (Paramiko)",
                category="authentication",
                severity=RiskLevel.HIGH,
                description="AutoAddPolicy or MissingHostKeyPolicy allows MITM attacks",
                pattern=re.compile(r'(?i)(AutoAddPolicy|WarningPolicy|MissingHostKeyPolicy|set_missing_host_key_policy)'),
                context_checks=[self._is_fp_paramiko],
                suggestion="Use paramiko.RejectPolicy (default) or explicitly verify host keys",
                cwe_id="CWE-300",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import paramiko\nclient = paramiko.SSHClient()\nclient.load_system_host_keys()\n# Never use AutoAddPolicy in production",
                attack_vector="No host key verification -> MITM -> Credential theft / RCE",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # PY-CONFIG-001: ALLOWED_HOSTS wildcard
            SecurityCheck(
                id="PY-CONFIG-001",
                name="Django ALLOWED_HOSTS Wildcard",
                category="configuration",
                severity=RiskLevel.HIGH,
                description="ALLOWED_HOSTS = ['*'] allows HTTP Host header attacks",
                pattern=re.compile(r'(?i)ALLOWED_HOSTS\s*=\s*\[[\s]*["\x27]\*["\x27]'),
                context_checks=[self._is_fp_dev],
                suggestion="Specify explicit allowed hostnames for your application",
                cwe_id="CWE-444",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="ALLOWED_HOSTS = ['example.com', 'www.example.com', 'api.example.com']",
                attack_vector="Wildcard ALLOWED_HOSTS -> Host header injection -> Cache poisoning",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-CONFIG-002: Debug mode enabled
            SecurityCheck(
                id="PY-CONFIG-002",
                name="Debug Mode Enabled (Django/Flask)",
                category="configuration",
                severity=RiskLevel.HIGH,
                description="DEBUG=True in production exposes stack traces, settings, and can enable code execution",
                pattern=re.compile(r'(?i)(DEBUG|debug)\s*=\s*(True|1)\s*$'),
                context_checks=[self._is_fp_dev],
                suggestion="Set DEBUG=False in production and use proper error logging",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="DEBUG = False  # Production\n# Use proper logging instead\nLOGGING = {'level': 'ERROR'}",
                attack_vector="Debug mode enabled -> Stack trace with secrets -> Information disclosure",
                mitre_technique="T1214 - Credentials in Registry",
            ),
            # PY-SMTP-001: SMTP header injection
            SecurityCheck(
                id="PY-SMTP-001",
                name="SMTP Header Injection",
                category="injection",
                severity=RiskLevel.HIGH,
                description="Email headers with user input (\\n injection) can inject malicious headers",
                pattern=re.compile(r'(?i)(EmailMessage|smtplib|send_mail|mail_admins)\s*\([^)]*\\[rn]|Subject.*\\[rn]|From.*\\[rn]'),
                context_checks=[self._is_fp_smtp],
                suggestion="Sanitize line breaks (\\r\\n) from any user input used in email headers",
                cwe_id="CWE-93",
                owasp_category="A03:2021 - Injection",
                remediation_example="def sanitize_header(value):\n    return value.replace('\\r', '').replace('\\n', '')\nemail = EmailMessage(subject=sanitize_header(user_subj), body=msg)",
                attack_vector="User input with \\r\\n -> SMTP header injection -> Spam / Phishing from your domain",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # PY-ASSERT-001: assert validation
            SecurityCheck(
                id="PY-ASSERT-001",
                name="Assert Used for Validation",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="assert statements are removed when Python runs with -O (optimize)",
                pattern=re.compile(r'\bassert\s+'),
                context_checks=[self._is_fp_assert],
                suggestion="Use proper if/raise validation instead of assert for security checks",
                cwe_id="CWE-617",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if user_input is None:\n    raise ValueError('User input is required')\n# Instead of: assert user_input is not None",
                attack_vector="Python -O disables assert -> Security check bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-FORMAT-001: Format string vuln
            SecurityCheck(
                id="PY-FORMAT-001",
                name="Format String Vulnerability via User Input",
                category="injection",
                severity=RiskLevel.MEDIUM,
                description="Using user input as the format string with % operator can expose memory",
                pattern=re.compile(r'["\x27][^"\x27]{0,20}["\x27]\s*%\s*\w'),
                context_checks=[self._is_fp_format],
                suggestion="Use str.format() or f-strings with positional arguments, not % formatting with user data",
                cwe_id="CWE-134",
                owasp_category="A03:2021 - Injection",
                remediation_example="name = user_name  # Variable, not the format string\nmsg = 'Hello, {}!'.format(name)  # Safe\n# 'Hello %s' % name  # Also safe for single substitution",
                attack_vector="User input in format string -> Memory read -> Information disclosure",
                mitre_technique="T1214 - Credentials in Registry",
            ),
            # PY-SUBPROCESS-001: Missing timeout
            SecurityCheck(
                id="PY-SUBPROCESS-001",
                name="Subprocess Without Timeout",
                category="subprocess",
                severity=RiskLevel.MEDIUM,
                description="subprocess.run() without timeout can hang indefinitely",
                pattern=re.compile(r'subprocess\.(run|Popen|check_output|call)\s*\('),
                context_checks=[self._is_fp_timeout],
                suggestion="Always set a timeout for subprocess operations",
                cwe_id="CWE-400",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="subprocess.run(['ls'], timeout=30)  # Always set a timeout",
                attack_vector="Process hangs indefinitely -> Resource exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # PY-SHELL-001: shlex misuse
            SecurityCheck(
                id="PY-SHELL-001",
                name="Potential shlex.quote Misuse",
                category="shell-injection",
                severity=RiskLevel.MEDIUM,
                description="shlex.quote() may not fully protect against injection in all contexts",
                pattern=re.compile(r'(?i)shlex\.quote\s*\('),
                context_checks=[self._is_fp_shlex],
                suggestion="Use subprocess with argument list instead of shell strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of: subprocess.run(f'grep {shlex.quote(pattern)} file', shell=True)\nsubprocess.run(['grep', pattern, 'file'], shell=False)  # Safer",
                attack_vector="Incomplete shell quoting -> Shell injection",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PY-FILE-001: Unsafe temp files
            SecurityCheck(
                id="PY-FILE-001",
                name="Insecure Temporary File",
                category="file",
                severity=RiskLevel.MEDIUM,
                description="mktemp() or NamedTemporaryFile without proper cleanup can leak sensitive data",
                pattern=re.compile(r'(?i)(tempfile\.mktemp|tempfile\.NamedTemporaryFile|mktemp)'),
                context_checks=[self._is_fp_temp],
                suggestion="Use tempfile.TemporaryFile() or tempfile.mkstemp() with proper cleanup",
                cwe_id="CWE-377",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="import tempfile\nwith tempfile.TemporaryFile() as f:\n    f.write(data)\n  # Auto-deleted on exit",
                attack_vector="Insecure temp file -> Symlink attack -> Data leak / file overwrite",
                mitre_technique="T1055 - Process Injection",
            ),
            # PY-FILE-002: os.chmod 777
            SecurityCheck(
                id="PY-FILE-002",
                name="Overly Permissive File Permissions (0o777)",
                category="file",
                severity=RiskLevel.MEDIUM,
                description="os.chmod(0o777) makes files world-readable/writable/executable",
                pattern=re.compile(r'os\.chmod\s*\([^)]*0o?777\)'),
                context_checks=[],
                suggestion="Use minimum required permissions (e.g., 0o600 for secrets, 0o755 for executables)",
                cwe_id="CWE-732",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="os.chmod('secret.key', 0o600)  # Owner read/write only",
                attack_vector="World-readable file -> Sensitive data exposure",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # PY-DEPR-001: Deprecated APIs
            SecurityCheck(
                id="PY-DEPR-001",
                name="Deprecated API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated Python APIs that may have known vulnerabilities",
                pattern=re.compile(r'(?i)(inspect\.getargspec|optparse|urllib\.urlopen|thread\.start_new|asyncore|asynchat|pipes\.Template)'),
                context_checks=[],
                suggestion="Replace deprecated APIs with modern alternatives",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="# Instead of: urllib.urlopen(url)\nimport requests\nresponse = requests.get(url)",
                attack_vector="Deprecated API may bypass security fixes",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PY-LOG-001: Log injection
            SecurityCheck(
                id="PY-LOG-001",
                name="Log Injection via User Input",
                category="logging",
                severity=RiskLevel.MEDIUM,
                description="Logging user input without sanitization enables log injection attacks",
                pattern=re.compile(r'logging\.\w+\s*\(\s*f["\x27]|logger\.\w+\s*\(\s*f["\x27]'),
                context_checks=[self._is_fp_log],
                suggestion="Sanitize line breaks from user input before logging or use structured logging",
                cwe_id="CWE-117",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="safe_input = user_input.replace('\\n', '_').replace('\\r', '_')\nlogger.info(f'User action: {safe_input}')",
                attack_vector="User input with \\r\\n -> Log file injection -> Splunk log injection / CRLF",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # PY-FLASK-001: Flask SECRET_KEY weak
            SecurityCheck(
                id="PY-FLASK-001",
                name="Weak/Default Flask SECRET_KEY",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="Weak or default Flask SECRET_KEY allows session forgery",
                pattern=re.compile(r'(?i)app\.(secret_key|config)\s*[:=].*["\x27](change|secret|key|default|password)["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Generate a strong random SECRET_KEY using os.urandom() or secrets module",
                cwe_id="CWE-798",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import secrets\napp.secret_key = secrets.token_hex(32)",
                attack_vector="Weak SECRET_KEY -> Flask session forgery -> Auth bypass",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # PY-CONFIG-003: Werkzeug debugger
            SecurityCheck(
                id="PY-CONFIG-003",
                name="Werkzeug Debugger Enabled in Production",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="Werkzeug debugger with PIN can lead to RCE if PIN is leaked",
                pattern=re.compile(r'(?i)app\.run\s*\([^)]*debug\s*=\s*True'),
                context_checks=[self._is_fp_dev],
                suggestion="Never run Flask with debug=True in production",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="if __name__ == '__main__':\n    app.run(debug=False)  # Or use env var: app.run(debug=os.getenv('DEBUG', 'False') == 'True')",
                attack_vector="Werkzeug debugger -> RCE via debugger console",
                mitre_technique="T1505 - Server Software Component",
            ),
            # PY-SECRET-001: AWS/GCP keys
            SecurityCheck(
                id="PY-SECRET-001",
                name="Hardcoded Cloud Provider Credentials",
                category="secrets",
                severity=RiskLevel.MEDIUM,
                description="Hardcoded AWS/GCP/Azure access keys in source code",
                pattern=re.compile(r'(?i)(AKIA[0-9A-Z]{16}|aws[_-]?(secret|access)[_-]?key|gcp[_-]?key|azure[_-]?(key|connection)|AIza[0-9A-Za-z\-_]{35})'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables, IAM roles, or workload identity federation",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="import os\nAWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY_ID']  # From env/secret manager",
                attack_vector="Hardcoded cloud key -> Cloud account compromise -> Data breach",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # PY-LOG-002: print in production
            SecurityCheck(
                id="PY-LOG-002",
                name="print() Statement in Production Code",
                category="logging",
                severity=RiskLevel.LOW,
                description="print() statements can leak sensitive data to stdout",
                pattern=re.compile(r'\bprint\s*\('),
                context_checks=[self._is_fp_print],
                suggestion="Use logging module instead of print()",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="import logging\nlogger = logging.getLogger(__name__)\nlogger.info('Operation completed')",
                attack_vector="Sensitive data printed to stdout -> Log exposure",
                mitre_technique="N/A",
            ),
            # PY-DOC-001: Missing docstrings
            SecurityCheck(
                id="PY-DOC-001",
                name="Missing Docstring",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Functions and classes should have docstrings for understanding",
                pattern=re.compile(r'(?i)^\s*(def\s+\w+|class\s+\w+)'),
                context_checks=[self._is_fp_docstring],
                suggestion="Add docstrings explaining purpose, parameters, and return values",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example='def process_user(user_id: int) -> dict:\n    """Fetch and process user data.\n    Args:\n        user_id: The user identifier\n    Returns:\n        Processed user dictionary\n    """',
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PY-MAGIC-001: Magic numbers
            SecurityCheck(
                id="PY-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(?:if|elif|while|return|case|==|!=|>=|<=|>|<|==)\s*[^;]*\b[3-9]\d{2}\b'),
                context_checks=[self._is_fp_magic],
                suggestion="Define magic numbers as named constants with descriptive names",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="MAX_RETRIES = 5\nTIMEOUT_SECONDS = 3600\nif retry_count > MAX_RETRIES: raise TimeoutError()",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PY-COMM-001: TODO comments
            SecurityCheck(
                id="PY-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security work",
                pattern=re.compile(r'(?i)#\s*TODO|TODO:|#\s*FIXME|FIXME:'),
                context_checks=[],
                suggestion="Address TODO/FIXME items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="# Address all TODOs before shipping to production",
                attack_vector="Unresolved TODO may indicate missing security control",
                mitre_technique="N/A",
            ),
            # PY-COMM-002: FIXME/HACK comments
            SecurityCheck(
                id="PY-COMM-002",
                name="HACK Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="HACK/XXX comments indicate potentially unsafe workarounds",
                pattern=re.compile(r'(?i)#\s*HACK|#\s*XXX|#\s*BUG|#\s*TEMP|HACK:|XXX:'),
                context_checks=[],
                suggestion="Address HACK/XXX items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove HACK workarounds and implement proper solutions",
                attack_vector="HACK workaround may introduce security bypass",
                mitre_technique="N/A",
            ),
            # PY-QUAL-001: Bare except
            SecurityCheck(
                id="PY-QUAL-001",
                name="Bare Except Clause",
                category="error-handling",
                severity=RiskLevel.LOW,
                description="bare except: catches all exceptions including SystemExit, KeyboardInterrupt",
                pattern=re.compile(r'\bexcept\s*:'),
                context_checks=[],
                suggestion="Catch specific exceptions (except ValueError:, except OSError:)",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="try:\n    result = risky_operation()\nexcept ValueError as e:\n    # Handle specific error\n    logger.error(f'Validation failed: {e}')",
                attack_vector="Bare except masks critical errors -> Silent failure",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # PY-QUAL-002: Too broad except (Exception)
            SecurityCheck(
                id="PY-QUAL-002",
                name="Overly Broad Exception Catch",
                category="error-handling",
                severity=RiskLevel.LOW,
                description="except Exception: catches too many error types, can hide bugs",
                pattern=re.compile(r'\bexcept\s+(Exception|BaseException)\s*:'),
                context_checks=[],
                suggestion="Catch only specific exception types that you expect",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="try:\n    result = db.query(sql)\nexcept DatabaseError as e:\n    logger.error(f'DB error: {e}')\n    raise",
                attack_vector="Silence of specific exceptions -> Hidden attack attempts",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # PY-QUAL-003: Unused imports
            SecurityCheck(
                id="PY-QUAL-003",
                name="Unused Import",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Importing modules that are never used clutters code",
                pattern=re.compile(r'^import\s+\w+|^from\s+\w+\s+import'),
                context_checks=[self._is_fp_unused_import],
                suggestion="Remove unused imports to improve code clarity",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="# Keep only imports that are actually used",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PY-QUAL-004: Duplicate string literals
            SecurityCheck(
                id="PY-QUAL-004",
                name="Duplicate String Literal",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Repeated string literals should be named constants",
                pattern=re.compile(r'["\x27][A-Za-z0-9_/]{10,}["\x27]'),
                context_checks=[self._is_fp_dup_string],
                suggestion="Extract repeated strings as module-level constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="API_ENDPOINT = '/api/v2/users'\n# Instead of '/api/v2/users' appearing 5 times",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PY-QUAL-005: Hardcoded localhost
            SecurityCheck(
                id="PY-QUAL-005",
                name="Hardcoded localhost/127.0.0.1",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost addresses may indicate test/debug code",
                pattern=re.compile(r'["\x27](https?://)?(localhost|127\.0\.0\.1)["\x27]'),
                context_checks=[self._is_fp_dev],
                suggestion="Use environment variables or configuration for host addresses",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="import os\nDB_HOST = os.getenv('DB_HOST', 'localhost')  # Configurable default",
                attack_vector="Hardcoded test addresses -> Information disclosure",
                mitre_technique="N/A",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect which frameworks are used in the codebase."""
        frameworks = []

        if re.search(r'(?i)from django|import django|django\.conf', content):
            frameworks.append('django')

        if re.search(r'(?i)from flask|import flask|flask\.', content):
            frameworks.append('flask')

        if re.search(r'(?i)from fastapi|from starlette|import fastapi', content):
            frameworks.append('fastapi')

        if re.search(r'(?i)sqlalchemy|from sqlalchemy|declarative_base', content):
            frameworks.append('sqlalchemy')

        if re.search(r'(?i)from jinja2|jinja2\.Environment|jinja2\.Template', content):
            frameworks.append('jinja2')

        if re.search(r'(?i)mako\.template|mako\.lookup', content):
            frameworks.append('mako')

        if re.search(r'(?i)pymongo|from pymongo|motor\.', content):
            frameworks.append('mongodb')

        if re.search(r'(?i)celery|from celery', content):
            frameworks.append('celery')

        if re.search(r'(?i)from requests|import requests|httpx|aiohttp', content):
            frameworks.append('http-client')

        self._framework_cache[file_path.name] = frameworks
        return frameworks

    def _passes_context_checks(self, check: SecurityCheck, line: str, content: str, frameworks: List[str]) -> bool:
        """Run all context checks. Returns True if all pass (not a false positive)."""
        for context_check in check.context_checks:
            if context_check(line, content, frameworks):
                return False
        return True

    def _add_finding(self, result: AnalysisResult, line_num: int, line: str, check: SecurityCheck) -> None:
        """Add a finding with full metadata."""
        finding = Finding(
            file=str(result.file_path),
            line=line_num,
            column=0,
            issue_type=check.id,
            message=f"[{check.name}] {check.description}",
            risk_level=check.severity,
            code_snippet=line.strip(),
            suggestion=check.suggestion,
        )
        result.findings.append(finding)
        result.metadata[f"check_{check.id}"] = {
            "cwe_id": check.cwe_id,
            "owasp_category": check.owasp_category,
            "category": check.category,
            "remediation_example": check.remediation_example,
            "attack_vector": check.attack_vector,
            "mitre_technique": check.mitre_technique,
        }

    # ====================================================================
    # TAINT ANALYSIS
    # ====================================================================

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run taint tracking analysis for source-to-sink flow."""
        sources = {
            'request.GET': 'Django QueryDict',
            'request.POST': 'Django POST Data',
            'request.data': 'DRF Request Body',
            'request.query_params': 'DRF Query Params',
            'request.form': 'Flask Form Data',
            'request.args': 'Flask Query Args',
            'request.json': 'Flask JSON Body',
            'request.values': 'Flask All Params',
            'request.cookies': 'Cookie Data',
            'request.headers': 'HTTP Headers',
            'request.files': 'Uploaded File',
            'input(': 'Standard Input',
            'os.environ': 'Environment Variable',
        }

        sinks = {
            'os.system': 'Shell Execution',
            'subprocess': 'Subprocess Execution',
            'popen': 'Popen Execution',
            'eval(': 'Code Eval',
            'exec(': 'Code Exec',
            'execute(': 'SQL Execution',
            'raw(': 'SQL Raw Query',
            'open(': 'File Open',
            'pickle.load': 'Pickle Deserialize',
            'yaml.load': 'YAML Deserialize',
        }

        tainted_vars: Dict[str, str] = {}

        for i, line in enumerate(lines, 1):
            for source, source_type in sources.items():
                if source in line:
                    match = re.search(r'(\w+)\s*=\s*.*' + re.escape(source), line)
                    if match:
                        tainted_vars[match.group(1)] = source_type

            for sink, sink_type in sinks.items():
                if sink in line:
                    for var_name, source_type in tainted_vars.items():
                        if var_name in line:
                            self._add_taint_finding(result, i, line, source_type, sink_type)

    def _add_taint_finding(self, result: AnalysisResult, line_num: int, line: str, source_type: str, sink_type: str) -> None:
        """Add a taint analysis finding."""
        finding = Finding(
            file=str(result.file_path),
            line=line_num,
            column=0,
            issue_type="PY-TAINT-001",
            message=f"[Taint Flow] Data from {source_type} reaches {sink_type} without sanitization",
            risk_level=RiskLevel.HIGH,
            code_snippet=line.strip(),
            suggestion="Sanitize data between source and sink. Use parameterized queries, validation, or escapes",
        )
        result.findings.append(finding)

    # ====================================================================
    # CROSS-LINE ANALYSIS
    # ====================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run cross-line detection for complex patterns."""
        self._check_multiline_sql(content, lines, result)
        self._check_missing_try_catch(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL built across multiple lines with string concatenation."""
        sql_start = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+')
        concat_op = re.compile(r'["\x27]\s*\+\s*\w+|\w+\s*\+\s*["\x27]')

        for i, line in enumerate(lines):
            if sql_start.search(line):
                for j in range(i, min(i + 4, len(lines))):
                    if concat_op.search(lines[j]) and ('execute' in lines[j] or 'raw' in lines[j]):
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="PY-SQL-006",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with string concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries instead of string concatenation",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_missing_try_catch(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for missing try/catch around sensitive operations."""
        sensitive_ops = ['open(', 'pickle.load', 'yaml.load', 'eval(', 'exec(', 'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output']

        for i, line in enumerate(lines, 1):
            for op in sensitive_ops:
                if op in line and 'try' not in line:
                    has_try = False
                    for j in range(max(0, i - 4), i):
                        if 'try' in lines[j]:
                            has_try = True
                            break
                    if not has_try:
                        self._add_finding(result, i, line, SecurityCheck(
                            id="PY-ERR-001",
                            name="Sensitive Operation Without try/except",
                            category="error-handling",
                            severity=RiskLevel.MEDIUM,
                            description=f"Sensitive operation ({op}) without error handling may crash",
                            pattern=re.compile(r''),
                            suggestion="Wrap sensitive operations in try/except blocks",
                            cwe_id="CWE-391",
                            owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                            remediation_example="try:\n    result = sensitive_operation()\nexcept Exception as e:\n    logger.error(f'Failed: {e}')\n    raise",
                            attack_vector="No error handling -> Crash / DoS",
                            mitre_technique="T1499 - Endpoint Denial of Service",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_fp_eval(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if eval/exec/compile is false positive."""
        if re.search(r'(eval|exec|compile)\s*\(\s*["\x27]\d+["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_cmd(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if command execution is safe."""
        if re.search(r'(system|popen)\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_sql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SQL query is parameterized."""
        if re.search(r'(execute|raw)\s*\(\s*["\x27][^"\x27]*["\x27]\s*,', line):
            return True
        if re.search(r'%s|%(\(?\w+\)?)?s|:\w+', line) and ',' in line:
            return True
        return False

    def _is_fp_deser(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if deserialization is safe."""
        if re.search(r'pickle\.loads?\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        return False

    def _is_fp_yaml(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if YAML load is safe."""
        if 'SafeLoader' in line or 'safe_load' in line:
            return True
        return False

    def _is_fp_ssti(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if template rendering is safe."""
        if re.search(r'Template\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'loader=FileSystemLoader' in line or 'get_template' in line:
            return True
        return False

    def _is_fp_xss(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if XSS risk is false positive."""
        if 'sanitize' in line.lower() or 'strip_tags' in line or 'escape' in line.lower():
            return True
        return False

    def _is_fp_file_op(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if file operation is safe."""
        if '+' not in line and re.search(r'open\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'os.path.abspath' in line or 'resolve' in line.lower():
            return True
        return False

    def _is_fp_url(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if URL is safe."""
        if re.search(r'(get|post|put)\s*\(\s*["\x27]https?://', line):
            return True
        if 'allowed_domains' in line or 'ALLOWED_HOSTS' in line:
            return True
        return False

    def _is_fp_secret(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if secret is example/placeholder."""
        if 'example' in line.lower() or 'placeholder' in line.lower() or 'sample' in line.lower():
            return True
        if 'os.environ' in line or 'getenv' in line or 'environ[' in line:
            return True
        return False

    def _is_fp_hash(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if hash is used for non-security purpose."""
        if 'sha256' in line or 'sha512' in line or 'sha3' in line:
            return True
        if 'checksum' in line.lower() or 'non-security' in line.lower():
            return True
        return False

    def _is_fp_random(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if random is acceptable."""
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower() or 'color' in line.lower():
            return True
        return False

    def _is_fp_timing(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if comparison is constant-time."""
        if 'compare_digest' in content or 'timing_safe' in content.lower():
            return True
        return False

    def _is_fp_nosql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if NoSQL query is safe."""
        if 'sanitize' in line or 'escape' in line:
            return True
        return False

    def _is_fp_ldap(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if LDAP query is safe."""
        if 'escape_filter_chars' in content or 'escaped' in content.lower():
            return True
        return False

    def _is_fp_xxe(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if XML is safe."""
        if 'resolve_entities=False' in content or 'no_network=True' in content:
            return True
        return False

    def _is_fp_dev(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if dev config."""
        if 'development' in line.lower() or 'env' in line.lower():
            return True
        return False

    def _is_fp_redirect(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if redirect is safe."""
        if 'allowed_hosts' in line.lower() or 'whitelist' in line.lower():
            return True
        return False

    def _is_fp_paramiko(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if paramiko is secure."""
        if 'RejectPolicy' in line or 'WarningPolicy' not in line:
            return True
        return False

    def _is_fp_smtp(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SMTP injection is false positive."""
        if 'sanitize' in line.lower() or 'replace' in line.lower():
            return True
        return False

    def _is_fp_assert(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if assert is acceptable."""
        if 'unittest' in content or 'pytest' in content:
            return True
        if re.search(r'assert\s+(True|False|None|is\s+not\s+None)', line):
            return True
        return False

    def _is_fp_format(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if format string is safe."""
        if re.search(r'["\x27][^"\x27]*%[sfdr][\s,)]', line):
            return True
        return False

    def _is_fp_timeout(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if subprocess has timeout."""
        if 'timeout=' in line or 'timeout' in line:
            return True
        return False

    def _is_fp_shlex(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if shlex usage is acceptable."""
        return True

    def _is_fp_temp(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if temp file is safe."""
        if 'TemporaryFile' in line or 'mkstemp' in line:
            return True
        if 'delete=False' in line:
            return False
        return False

    def _is_fp_log(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if log injection is false positive."""
        if 'replace' in line.lower() or 'sanitize' in line.lower():
            return True
        return False

    def _is_fp_print(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if print is acceptable."""
        if 'test' in line.lower() or 'spec' in line.lower():
            return True
        if 'logger' in line:
            return True
        return False

    def _is_fp_docstring(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if docstring exists (before or after the def/class line)."""
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            # Check next line (common: def foo(): -> """docstring""")
            if idx + 1 < len(lines):
                next_line = lines[idx + 1].strip()
                if '"""' in next_line or "'''" in next_line:
                    return True
            # Check previous lines
            for j in range(max(0, idx - 1), max(0, idx - 3), -1):
                if '"""' in lines[j] or "'''" in lines[j]:
                    return True
        except ValueError:
            pass
        return False

    def _is_fp_magic(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if magic number is acceptable."""
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if '=' in line and re.search(r'\w+\s*=\s*\d+', line):
            return True
        return False

    def _is_fp_unused_import(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if import is used."""
        import_match = re.search(r'(?:from\s+(\S+)\s+import\s+\w+|import\s+(\w+))', line)
        if import_match:
            name = import_match.group(1) or import_match.group(2)
            class_name = name.split('.')[-1]
            if class_name in content:
                return True
        return False

    def _is_fp_dup_string(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if duplicated string is acceptable."""
        return False



