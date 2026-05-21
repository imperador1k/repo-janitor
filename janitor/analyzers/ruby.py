"""Elite static analyzer for Ruby code with comprehensive security checks."""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Callable, Set, Tuple
from dataclasses import dataclass, field

from janitor.analyzers.base import BaseAnalyzer, AnalysisResult
from janitor.types import Finding, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class SecurityCheck:
    """A security unit test for Ruby code."""
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


class RubyAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Ruby code — 50+ elite security checks."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._taint_sources: Set[str] = set()
        self._taint_sinks: Set[str] = set()

    def get_language(self) -> str:
        return "ruby"

    def get_supported_extensions(self) -> List[str]:
        return [".rb", ".rbw", ".rake"]

    def get_file_patterns(self) -> List[str]:
        return ["Gemfile", "Rakefile", "*.gemspec"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Ruby file and return results."""
        result = AnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        lines = content.split("\n")
        detected_frameworks = self._detect_frameworks(content, file_path)
        result.metadata["frameworks"] = detected_frameworks

        self._taint_sources = self._extract_taint_sources(lines)
        self._taint_sinks = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("=begin"):
                continue
            for check in self.checks:
                if check.pattern.search(line):
                    if self._passes_context_checks(check, line, content, detected_frameworks):
                        self._add_finding(result, i, line, check)

        self._run_taint_analysis(content, lines, result, detected_frameworks)
        self._run_cross_line_analysis(content, lines, result, detected_frameworks)

        return result

    def _passes_context_checks(self, check: SecurityCheck, line: str, content: str, frameworks: List[str]) -> bool:
        if not check.context_checks:
            return True
        for ctx_check in check.context_checks:
            if not ctx_check(line, content, frameworks):
                return False
        return True

    def _add_finding(self, result: AnalysisResult, line: int, code: str, check: SecurityCheck) -> None:
        result.findings.append(Finding(
            file=str(result.file_path),
            line=line,
            column=code.index(check.pattern.search(code).group()) + 1 if check.pattern.search(code) else 0,
            issue_type=check.id,
            message=check.description,
            risk_level=check.severity,
            code_snippet=code.strip()[:200],
            suggestion=check.suggestion,
        ))

    # ======================================================================
    # FRAMEWORK DETECTION
    # ======================================================================

    FRAMEWORKS: Dict[str, List[str]] = {
        "rails": ["Rails::Application", "config/application.rb", "ActiveRecord::Base", "ActionController::Base"],
        "sinatra": ["Sinatra::Base", "Sinatra::Application", "get /", "post /", "Sinatra.set"],
        "rack": ["Rack::", "config.ru", "use Rack::"],
        "activerecord": ["ActiveRecord::", "has_many", "belongs_to", "validates"],
        "sequel": ["Sequel::", "Sequel.connect", "Sequel::Model"],
        "devise": ["devise_for", "Devise::", "before_action :authenticate_user"],
        "sidekiq": ["Sidekiq::", "include Sidekiq::Worker", "sidekiq_options"],
        "rspec": ["RSpec.", "describe ", "context ", "it ", "expect("],
        "minitest": ["MiniTest::", "class.*Test <", "assert_"],
        "erb": [".erb", "<%=", "<% end %>"],
        "haml": ["%haml", "Haml::"],
        "slim": ["slim", "Slim::Template"],
        "grape": ["Grape::API", "Grape::"],
        "puma": ["puma", "Puma::"],
        "unicorn": ["unicorn", "Unicorn::"],
    }

    def _detect_frameworks(self, content: str, file_path: str) -> List[str]:
        cache_key = str(file_path)
        if cache_key in self._framework_cache:
            return self._framework_cache[cache_key]

        detected = []
        for framework, patterns in self.FRAMEWORKS.items():
            for pattern in patterns:
                if pattern in content:
                    detected.append(framework)
                    break
        self._framework_cache[cache_key] = detected
        return detected

    # ======================================================================
    # FALSE POSITIVE CONTEXT CHECKS
    # ======================================================================

    def _has_strong_params(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if params are properly permitted via strong parameters."""
        if ".permit(" in content or "params.require" in content:
            return False
        return True

    def _is_safe_command(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if command execution uses constant args."""
        if re.search(r'"(ping|echo|ls|whoami|date|id|uname)"', line):
            return False
        if 'params' not in line and 'request' not in line and 'user' not in line:
            return False
        return True

    def _is_parameterized_query(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SQL uses parameterized syntax."""
        if "?" in line or ":name" in line or "$1" in line:
            return False
        if ".where(" in line and not re.search(r'["\'].*["\']\s*\+\s*', line):
            return False
        return True

    def _is_safe_file_path(self, line: str, content: str, frameworks: List[str]) -> bool:
        if "canonicalize" in content or "canonical" in content:
            return False
        if 'Rails.root.join' in line and 'params' not in line:
            return False
        if '.basename' in line or '.cleanpath' in content:
            return False
        return True

    def _is_safe_render(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if render uses safe template reference."""
        if re.search(r'render\s+(?:json|xml|plain|html):', line):
            return False
        if re.search(r'render\s+["\']', line):
            return False
        return True

    def _is_safe_serialize(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if serialize uses safe format."""
        if ":json" in line or ":json" in content:
            return False
        return True

    def _has_authentication(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if controller has authentication."""
        if "before_action :authenticate" in content:
            return False
        if "before_action :authorize" in content:
            return False
        if "devise_group" in content or "authenticate_user" in content:
            return False
        return True

    def _is_csrf_protected(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if protect_from_forgery is enabled."""
        if "protect_from_forgery" in content and "except" not in line:
            return False
        return True

    def _is_dangerous_crypto(self, line: str, content: str, frameworks: List[str]) -> bool:
        if "test" in content.lower():
            return False
        return True

    def _is_safe_redirect(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if redirect uses allowlist."""
        if "redirect_to" in content and "allowlist" in content:
            return False
        if re.search(r'redirect_to\s+(root_path|root_url|@\w+)', line):
            return False
        return True

    # ======================================================================
    # BUILD CHECKS
    # ======================================================================

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by category and severity."""
        checks = []

        # ====================================================================
        # CATEGORY: RAILS-SPECIFIC (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-RAILS-001",
                name="Mass Assignment Without Strong Parameters",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="Direct mass assignment via update_attributes or create without strong params",
                pattern=re.compile(r'(?i)(update_attributes|update!|create!)\s*\(?\s*params'),
                context_checks=[self._has_strong_params],
                suggestion="Use strong parameters with require/permit to whitelist allowed attributes",
                cwe_id="CWE-915",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='def user_params\n  params.require(:user).permit(:name, :email)\nend',
                attack_vector="Mass assignment → Attacker sets admin=true → Privilege escalation",
                mitre_technique="T1548 - Abuse Elevation Control Mechanism",
            ),
            SecurityCheck(
                id="RB-RAILS-002",
                name="Unsafe Redirect via User Input",
                category="rails",
                severity=RiskLevel.HIGH,
                description="redirect_to with user-controlled params allows open redirect attacks",
                pattern=re.compile(r'(?i)redirect_to\s+(params\[|request\.|:back\b)'),
                context_checks=[self._is_safe_redirect],
                suggestion="Use allowlist for redirect destinations. Avoid user-controlled URLs",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='allowed = {"profile" => profile_path}\nredirect_to allowed[params[:dest]] || root_path',
                attack_vector="User param → Open redirect → Phishing → Credential theft",
                mitre_technique="T1566 - Phishing",
            ),
            SecurityCheck(
                id="RB-RAILS-003",
                name="Unsafe send_file / send_data with User Input",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="send_file with user-controlled path allows arbitrary file reads",
                pattern=re.compile(r'(?i)(send_file|send_data)\s*\('),
                context_checks=[self._is_safe_file_path],
                suggestion="Validate file paths and ensure they stay within allowed directories",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='path = Rails.root.join("uploads", File.basename(params[:file]))\nsend_file(path) if path.to_s.start_with?(Rails.root.join("uploads").to_s)',
                attack_vector="User path → send_file → /etc/passwd read → Information disclosure",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="RB-RAILS-004",
                name="Unsafe YAML Serialization",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="Rails serialize with YAML allows arbitrary code execution on deserialization",
                pattern=re.compile(r'(?i)serialize\s*:?\w+\s*,\s*(:yaml|YAML|Hash)'),
                context_checks=[self._is_safe_serialize],
                suggestion="Use JSON serialization instead of YAML for ActiveRecord serialization",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="serialize :preferences, JSON\n# or use native JSON columns in PostgreSQL",
                attack_vector="Serialized YAML → Malicious payload → Code execution → RCE",
                mitre_technique="T1055 - Process Injection",
            ),
            SecurityCheck(
                id="RB-RAILS-005",
                name="Authentication Bypass via skip_before_action",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="Skipping authentication on specific actions can expose sensitive endpoints",
                pattern=re.compile(r'(?i)skip_before_action\s*:authenticate'),
                context_checks=[self._has_authentication],
                suggestion="Ensure skipped actions are properly reviewed and secured",
                cwe_id="CWE-306",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="# If skipping authentication, add custom authorization:\nskip_before_action :authenticate_user!, only: [:show, :index]\nbefore_action :check_public_access, only: [:show, :index]",
                attack_vector="Skip auth → Unauthenticated access → Data breach",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RB-RAILS-006",
                name="CSRF Protection Disabled",
                category="rails",
                severity=RiskLevel.HIGH,
                description="Disabling CSRF protection leaves application vulnerable to cross-site requests",
                pattern=re.compile(r'(?i)protect_from_forgery.*except|skip_before_action.*verify_authenticity'),
                context_checks=[self._is_csrf_protected],
                suggestion="Only disable CSRF on public API endpoints with token-based authentication",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='protect_from_forgery with: :exception, unless: -> { request.headers["X-API-Key"].present? }',
                attack_vector="No CSRF → Cross-site request forgery → State-changing action",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RB-RAILS-007",
                name="eval of User Input in Controller",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="Evaluating user-controlled strings in Rails context can execute arbitrary code",
                pattern=re.compile(r'(?i)(eval|instance_eval|class_eval)\s*\(?\s*params'),
                context_checks=[],
                suggestion="Never pass user input to eval. Use safe alternatives like public_send",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of eval(params[:action]):\nsafe_actions = %w[index show edit update]\naction = safe_actions.include?(params[:action]) ? params[:action] : 'index'\npublic_send(action)",
                attack_vector="User input → eval → Arbitrary code execution → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-RAILS-008",
                name="Render with User-Controlled Inline Template",
                category="rails",
                severity=RiskLevel.CRITICAL,
                description="render inline: with user input can execute arbitrary template code",
                pattern=re.compile(r'(?i)render\s+(inline|text|body)\s*:\s*(params|request|@\w+\s*\+\s|")'),
                context_checks=[self._is_safe_render],
                suggestion="Never render user input as inline templates. Use views and escape output",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of render inline: params[:template]:\nrender :show, locals: { message: params[:message] }",
                attack_vector="User input → Inline render → Template injection → XSS",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: SQL INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-SQL-001",
                name="SQL Injection via String Interpolation in ActiveRecord",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String interpolation in ActiveRecord queries allows SQL injection",
                pattern=re.compile(r'(?i)(where|having|order)\s*\(?\s*["\'][^"\']*#\{'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use parameterized queries with ? placeholders or hash conditions",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='User.where("email = ? AND active = ?", params[:email], true)\n# or hash style:\nUser.where(email: params[:email], active: true)',
                attack_vector="User input → String interpolation → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RB-SQL-002",
                name="SQL Injection via String Concatenation in ActiveRecord",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in ActiveRecord queries allows SQL injection",
                pattern=re.compile(r'(?i)(where|having|order|joins)\s*\(?\s*["\'][^"\']*\s*\+'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use parameterized queries with ? placeholders or hash conditions",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='User.where("name LIKE ?", "%#{params[:q]}%")',
                attack_vector="User input → String concat → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RB-SQL-003",
                name="SQL Injection via find_by_sql",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="find_by_sql with string interpolation allows SQL injection",
                pattern=re.compile(r'(?i)find_by_sql\s*\(\s*["\'][^"\']*#\{'),
                context_checks=[],
                suggestion="Use parameterized queries with ? placeholders in find_by_sql",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='User.find_by_sql(["SELECT * FROM users WHERE email = ?", params[:email]])',
                attack_vector="User input → find_by_sql → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RB-SQL-004",
                name="SQL Injection via execute with Raw SQL",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="execute with raw SQL concatenation allows injection",
                pattern=re.compile(r'(?i)execute\s*\(\s*["\'][^"\']*#\{|execute\s*\(\s*["\'][^"\']*\s*\+'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use sanitized_sql or parameterized queries with execute",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='ActiveRecord::Base.connection.execute(\n  ["UPDATE users SET name = ? WHERE id = ?", params[:name], params[:id]]\n)',
                attack_vector="User input → execute → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: COMMAND INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-CMD-001",
                name="Command Injection via system()",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="system() with user input allows arbitrary command execution",
                pattern=re.compile(r'(?i)system\s*[\("]\s*.*#\{|system\s*[\("]\s*.*\+'),
                context_checks=[self._is_safe_command],
                suggestion="Use system with separate arguments or use Open3.capture3 for safety",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example='system("ls", "-la", user_input)  # separate args = safe\n# or:\nOpen3.capture3("ls", "-la", user_input)',
                attack_vector="User input → system() → Shell execution → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-CMD-002",
                name="Command Injection via Backticks",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Backtick command execution with user input allows arbitrary commands",
                pattern=re.compile(r'`[^`]*#\{[^}]*params|`[^`]*#\{[^}]*request|`[^`]*\+\s*\w+'),
                context_checks=[],
                suggestion="Avoid backtick execution. Use Open3.capture3 with separate arguments",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of `ls #{params[:dir]}`:\nOpen3.capture3(\"ls\", \"-la\", params[:dir])",
                attack_vector="User input → Backtick execution → Shell execution → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-CMD-003",
                name="Command Injection via IO.popen or Open3.popen3",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="IO.popen with user-controlled command string allows injection",
                pattern=re.compile(r'(?i)(IO\.popen|Open3\.(popen3|capture3|capture2|pipeline))\s*[\("]'),
                context_checks=[self._is_safe_command],
                suggestion="Use array form of command arguments to prevent shell injection",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example='Open3.capture3("ls", "-la", *user_args)\n# Array form prevents shell interpretation',
                attack_vector="User input → IO.popen → Shell execution → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: CODE INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-CODE-001",
                name="Code Injection via eval()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="eval() with user input allows arbitrary Ruby code execution",
                pattern=re.compile(r'(?i)\beval\s*[\("]'),
                context_checks=[],
                suggestion="Never use eval with user input. Use send, public_send, or pattern matching",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of eval(params[:method]):\nif allowed_methods.include?(params[:method])\n  send(params[:method])\nend",
                attack_vector="User input → eval → Arbitrary code execution → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-CODE-002",
                name="Code Injection via instance_eval / class_eval",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="instance_eval/class_eval with user input allows arbitrary method execution",
                pattern=re.compile(r'(?i)(instance_eval|class_eval|module_eval)\s*[\("]'),
                context_checks=[],
                suggestion="Avoid eval variants with user input. Use define_method with care",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of obj.instance_eval(params[:code]):\n# Use safe dispatch:\nobj.public_send(params[:safe_method]) if ALLOWED.include?(params[:safe_method])",
                attack_vector="User input → instance_eval → Context manipulation → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-CODE-003",
                name="Code Injection via send / public_send with User Input",
                category="code-injection",
                severity=RiskLevel.HIGH,
                description="send with user-controlled method name can call arbitrary methods",
                pattern=re.compile(r'(?i)(send|public_send|try)\s*\(?\s*(params\[|request\.)'),
                context_checks=[],
                suggestion="Whitelist allowed method names before calling send",
                cwe_id="CWE-470",
                owasp_category="A03:2021 - Injection",
                remediation_example='allowed = %w[index show edit update]\nif allowed.include?(params[:action])\n  send(params[:action])\nend',
                attack_vector="User method → send → Arbitrary method call → Logic bypass",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: DESERIALIZATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-DESER-001",
                name="Dangerous YAML Deserialization",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="YAML.load from untrusted sources can execute arbitrary code",
                pattern=re.compile(r'(?i)(YAML\.load|YAML::load|Psych\.load)\s*[\("]'),
                context_checks=[],
                suggestion="Use YAML.safe_load instead of YAML.load for untrusted data",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="YAML.safe_load(user_input, permitted_classes: [Symbol, Time])",
                attack_vector="Malicious YAML → Deserialization → Code execution → RCE",
                mitre_technique="T1055 - Process Injection",
            ),
            SecurityCheck(
                id="RB-DESER-002",
                name="Dangerous Marshal Deserialization",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="Marshal.load from untrusted sources allows arbitrary code execution",
                pattern=re.compile(r'(?i)Marshal\.(load|restore)\s*[\("]'),
                context_checks=[],
                suggestion="Avoid Marshal.load with untrusted data. Use JSON for serialization",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="# Instead of Marshal.load(user_data):\nJSON.parse(user_data, symbolize_names: true)",
                attack_vector="Malicious Marshal → Deserialization → Code execution → RCE",
                mitre_technique="T1055 - Process Injection",
            ),
            SecurityCheck(
                id="RB-DESER-003",
                name="CSV.parse with Untrusted Data",
                category="deserialization",
                severity=RiskLevel.MEDIUM,
                description="CSV.parse with untrusted data can execute formula injection attacks",
                pattern=re.compile(r'(?i)CSV\.(parse|read|foreach|table)\s*[\("]'),
                context_checks=[],
                suggestion="Sanitize CSV output: prepend values starting with =, +, -, @ with a tab",
                cwe_id="CWE-1236",
                owasp_category="A03:2021 - Injection",
                remediation_example='sanitized = value.start_with?("=", "+", "-", "@") ? "\\t#{value}" : value',
                attack_vector="Malicious CSV → Formula injection → Excel macro execution",
                mitre_technique="T1566 - Phishing",
            ),
        ])

        # ====================================================================
        # CATEGORY: PATH TRAVERSAL
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-PATH-001",
                name="Path Traversal via File.open",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File.open with user input allows path traversal attacks",
                pattern=re.compile(r'(?i)(File\.(open|read|write|exist|delete|rename)|FileUtils\.)\s*\(?\s*(params\[|request\.|#\{)'),
                context_checks=[self._is_safe_file_path],
                suggestion="Use File.basename or cleanpath to sanitize user-provided paths",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='safe_name = File.basename(params[:file])\npath = Rails.root.join("uploads", safe_name)',
                attack_vector="User path → File.open → ../../etc/passwd → Information disclosure",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="RB-PATH-002",
                name="Path Traversal via Dir.glob / Dir.entries",
                category="path-traversal",
                severity=RiskLevel.HIGH,
                description="Directory operations with user input can list arbitrary directories",
                pattern=re.compile(r'(?i)(Dir\.(glob|entries|\[\]|chdir|mkdir|delete)|Pathname\.new)\s*\(?\s*(params|request|#\{)'),
                context_checks=[self._is_safe_file_path],
                suggestion="Validate directory paths and use sanitized basenames",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='safe_dir = File.basename(params[:dir])\nDir.glob(Rails.root.join("data", safe_dir, "*.csv"))',
                attack_vector="User dir → Dir.glob → Directory listing → Information disclosure",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: SSRF
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-SSRF-001",
                name="SSRF via open-uri / Kernel#open",
                category="ssrf",
                severity=RiskLevel.HIGH,
                description="Kernel#open with user-controlled URL allows SSRF attacks",
                pattern=re.compile(r'(?i)\bopen\s*\(?\s*(params\[|request\.|#\{)'),
                context_checks=[],
                suggestion="Use an allowlist of permitted URLs or use URI.parse with validation",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="parsed = URI.parse(params[:url])\nunless ALLOWED_HOSTS.include?(parsed.host)\n  raise \"URL not allowed\"\nend\nNet::HTTP.get(parsed)",
                attack_vector="User URL → open → Internal network scan → Service compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RB-SSRF-002",
                name="SSRF via Net::HTTP with User Input",
                category="ssrf",
                severity=RiskLevel.HIGH,
                description="Net::HTTP requests to user-controlled URLs allow SSRF",
                pattern=re.compile(r'(?i)Net::HTTP\.(get|post|start)\s*\(?\s*(params\[|request\.|#\{)'),
                context_checks=[],
                suggestion="Validate URLs against an allowlist before making requests",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example='uri = URI.parse(params[:url])\nraise "Invalid host" unless ALLOWED.include?(uri.host)\nresponse = Net::HTTP.get_response(uri)',
                attack_vector="User URL → Net::HTTP → Internal service access → Lateral movement",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: XSS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-XSS-001",
                name="XSS via html_safe / raw with User Input",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Using html_safe or raw on user input allows XSS attacks",
                pattern=re.compile(r'(?i)(\.html_safe|raw\s*[\("])'),
                context_checks=[],
                suggestion="Avoid html_safe on user input. Use sanitize helper to allow safe HTML tags",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="sanitize(user_input, tags: %w[b i u em strong a], attributes: %w[href])",
                attack_vector="User input → html_safe → JavaScript injection → XSS",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-XSS-002",
                name="XSS via ERB without Escaping (raw tag)",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="ERB templates using raw or html_safe on user content allow XSS",
                pattern=re.compile(r'(?i)(<%=.*\.html_safe|<%=.*raw\s*\()'),
                context_checks=[],
                suggestion="ERB auto-escapes <%= %>. Use raw only for trusted content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="<%= user_input %>  \" ERB auto-escapes this\n<%= raw(trusted_html) %>  \" Only for trusted content",
                attack_vector="User input → ERB raw → JavaScript injection → XSS",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RB-XSS-003",
                name="XSS via link_to with user-controlled URL",
                category="xss",
                severity=RiskLevel.HIGH,
                description="link_to with user-controlled URL can execute javascript: URLs",
                pattern=re.compile(r'(?i)link_to\s+["\'][^"\']*["\'],\s*(params\[|request\.)'),
                context_checks=[],
                suggestion="Validate URLs in link_to and allow only http/https protocols",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example='link_to "Profile", user_profile_url(@user)  \" use named routes\n# Not: link_to "Profile", params[:url]',
                attack_vector="User URL → link_to → javascript: URL → XSS",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: SECRETS / AUTH
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-AUTH-001",
                name="Hardcoded API Key or Secret",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded secrets in source code are exposed in version control",
                pattern=re.compile(r'(?i)(api_key|apikey|secret_token|secret_key_base|password|credential)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}'),
                context_checks=[],
                suggestion="Use Rails credentials or environment variables for secrets",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example='Rails.application.credentials.api_key\n# or:\nENV["API_KEY"]',
                attack_vector="Hardcoded secret → VCS exposure → Credential leakage → Account compromise",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RB-AUTH-002",
                name="JWT Secret Key Hardcoded",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="JWT secret hardcoded in source allows token forgery",
                pattern=re.compile(r'(?i)(jwt_secret|jwt.*key|hmac_secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}'),
                context_checks=[],
                suggestion="Load JWT secrets from environment variables or credentials",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')",
                attack_vector="Hardcoded JWT secret → Token forgery → Authentication bypass",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RB-AUTH-003",
                name="Secrets in Rails Credentials Exposed",
                category="secrets",
                severity=RiskLevel.HIGH,
                description="Rails master key or credentials committed to version control",
                pattern=re.compile(r'(?i)(master\.key|credentials\.yml\.enc|config/master\.key)'),
                context_checks=[],
                suggestion="Never commit master.key. Add to .gitignore and use environment variables",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="echo 'config/master.key' >> .gitignore\n# Use RAILS_MASTER_KEY environment variable",
                attack_vector="Master key → Credentials decryption → All secrets exposed",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RB-AUTH-004",
                name="Use of authenticate_or_request_with_http_basic",
                category="secrets",
                severity=RiskLevel.MEDIUM,
                description="HTTP Basic Authentication transmits credentials in plaintext",
                pattern=re.compile(r'(?i)authenticate_or_request_with_http_basic'),
                context_checks=[],
                suggestion="Use token-based authentication or HTTPS with Basic Auth",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="authenticate_or_request_with_http_basic do |username, password|\n  # Ensure HTTPS is enforced\n  ActiveSupport::SecurityUtils.secure_compare(username, expected_user)\nend",
                attack_vector="Basic Auth → Plaintext transmission → Credential interception",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
        ])

        # ====================================================================
        # CATEGORY: CRYPTOGRAPHY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-CRYPTO-001",
                name="Use of MD5 for Security Purposes",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 is cryptographically broken and unsuitable for security",
                pattern=re.compile(r'(?i)(Digest::MD5|MD5\.(hexdigest|digest|base64digest))\s*\('),
                context_checks=[self._is_dangerous_crypto],
                suggestion="Use SHA-256 or bcrypt (via has_secure_password) for hashing",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example='Digest::SHA256.hexdigest(data)\n# For passwords:\nhas_secure_password\n# or:\nBCrypt::Password.create(password)',
                attack_vector="Weak hash → Collision → Integrity bypass → Data manipulation",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RB-CRYPTO-002",
                name="Use of SHA1 for Security Purposes",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="SHA1 is cryptographically weakened and deprecated for security",
                pattern=re.compile(r'(?i)(Digest::SHA1|SHA1\.(hexdigest|digest|base64digest))\s*\('),
                context_checks=[self._is_dangerous_crypto],
                suggestion="Use SHA-256 or SHA-3 instead of SHA1",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example='Digest::SHA256.hexdigest(data)\n# Or use HMAC:\nOpenSSL::HMAC.hexdigest("SHA256", key, data)',
                attack_vector="Weak hash → Collision → Integrity bypass → Data manipulation",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RB-CRYPTO-003",
                name="Low bcrypt Cost Factor",
                category="cryptography",
                severity=RiskLevel.MEDIUM,
                description="Bcrypt with cost factor below 12 is vulnerable to brute force",
                pattern=re.compile(r'(?i)BCrypt::Password\.create\s*\([^)]*cost\s*[:=>]\s*[0-9]{1}$'),
                context_checks=[],
                suggestion="Use cost factor of 12 or higher for bcrypt password hashing",
                cwe_id="CWE-916",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="BCrypt::Password.create(password, cost: 12)",
                attack_vector="Low bcrypt cost → Fast brute-force → Password cracking",
                mitre_technique="T1110 - Brute Force",
            ),
        ])

        # ====================================================================
        # CATEGORY: FILE UPLOAD
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-UPLOAD-001",
                name="Unrestricted File Upload",
                category="file-upload",
                severity=RiskLevel.CRITICAL,
                description="File upload without validation allows arbitrary file types",
                pattern=re.compile(r'(?i)(file_field|attach_file|upload|File\.new)\s*[\("]'),
                context_checks=[],
                suggestion="Validate file type, size, and content. Use dedicated upload libraries",
                cwe_id="CWE-434",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='validate :allowed_file_type\ndef allowed_file_type\n  allowed = %w[image/png image/jpeg application/pdf]\n  errors.add(:file, "not allowed") unless allowed.include?(file.content_type)\nend',
                attack_vector="Unrestricted upload → .exe/.php upload → RCE on server",
                mitre_technique="T1505 - Server Software Component",
            ),
            SecurityCheck(
                id="RB-UPLOAD-002",
                name="Symlink Attack in File Uploads",
                category="file-upload",
                severity=RiskLevel.HIGH,
                description="Allowing symlinks in uploads can overwrite arbitrary files",
                pattern=re.compile(r'(?i)File\.symlink|FileUtils\.ln_s|File\.lchmod'),
                context_checks=[],
                suggestion="Disable symlinks in upload directories. Use secure filenames",
                cwe_id="CWE-61",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='uploaded.original_filename = "#{SecureRandom.hex(16)}#{File.extname(uploaded.original_filename)}"\nsave_path = Rails.root.join("uploads", safe_filename)',
                attack_vector="Upload symlink → Overwrite system file → Privilege escalation",
                mitre_technique="T1574 - Hijack Execution Flow",
            ),
        ])

        # ====================================================================
        # CATEGORY: NETWORK / TLS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-NET-001",
                name="HTTP Without TLS",
                category="network",
                severity=RiskLevel.HIGH,
                description="Using http:// instead of https:// exposes data in transit",
                pattern=re.compile(r'(?i)https?://[^"\'\s]*\.(com|org|net|io|app|dev)\s'),
                context_checks=[],
                suggestion="Always use https:// for all external communications",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example='# Use https:// instead of http://\nuri = URI.parse("https://api.example.com/data")',
                attack_vector="HTTP → Man-in-the-middle → Data interception → Credential theft",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RB-NET-002",
                name="SSL/TLS Verification Disabled",
                category="network",
                severity=RiskLevel.CRITICAL,
                description="Disabling SSL verification allows MITM attacks",
                pattern=re.compile(r'(?i)OpenSSL::SSL::VERIFY_NONE|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|verify:?\s*:?false'),
                context_checks=[],
                suggestion="Never disable SSL verification. Always use VERIFY_PEER",
                cwe_id="CWE-295",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="http.verify_mode = OpenSSL::SSL::VERIFY_PEER",
                attack_vector="SSL bypass → MITM → Credential interception → Account compromise",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
        ])

        # ====================================================================
        # CATEGORY: CODE QUALITY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RB-QLTY-001",
                name="Use of unless with Complex Condition",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="unless with multiple conditions reduces readability",
                pattern=re.compile(r'(?i)unless\s+\w+\s+(&&|\|\||and|or)'),
                context_checks=[],
                suggestion="Use if ! instead of unless with complex conditions",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="if !user.nil? && user.active?\n  # ...\nend",
                attack_vector="—",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-002",
                name="Method Too Long (high complexity)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Methods over 30 lines indicate high complexity",
                pattern=re.compile(r'(?i)^\s*def\s+\w+'),
                context_checks=[],
                suggestion="Extract helper methods to reduce method size",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="# Good practice: methods under 10 lines\n# Extract: private\n\ndef helper_method\n  # ...\nend",
                attack_vector="Complex code → Logic errors → Security vulnerabilities",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-003",
                name="TODO or FIXME in Production Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO or FIXME comments indicate incomplete code",
                pattern=re.compile(r'(?i)#\s*(TODO|FIXME|XXX|HACK|FIXIT)'),
                context_checks=[],
                suggestion="Address all TODOs and FIXMEs before production release",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="# TODO: add authentication → done\n# FIXME: handle edge case → fixed",
                attack_vector="Incomplete code → Missing security check → Vulnerability",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-004",
                name="Use of eval-like patterns in Production",
                category="code-quality",
                severity=RiskLevel.HIGH,
                description="Creating methods dynamically from user data is dangerous",
                pattern=re.compile(r'(?i)(define_method|define_singleton_method)\s*\(?\s*:'),
                context_checks=[],
                suggestion="Avoid define_method with dynamically generated names",
                cwe_id="CWE-470",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Instead of define_method:\nMETHODS = { show: :show_method, edit: :edit_method }.freeze\nsend(METHODS[action])",
                attack_vector="Dynamic method → Collision → Logic bypass → Auth bypass",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RB-QLTY-005",
                name="Rescue Exception — too broad",
                category="code-quality",
                severity=RiskLevel.MEDIUM,
                description="Rescuing Exception catches all errors including SystemExit and NoMemoryError",
                pattern=re.compile(r'(?i)rescue\s+Exception'),
                context_checks=[],
                suggestion="Rescue specific exception classes instead of Exception",
                cwe_id="CWE-396",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="rescue ActiveRecord::RecordNotFound => e\n  # handle specific error\nrescue StandardError => e\n  # handle general errors",
                attack_vector="Broad rescue → Swallows critical errors → Application instability",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-006",
                name="Nil Without Safe Navigation",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Calling method on potentially nil object without safe navigation (&.)",
                pattern=re.compile(r'(?i)@\w+\s*\.\s*\w+\s*(?:\.|\(|\n)'),
                context_checks=[],
                suggestion="Use safe navigation operator (&.) to avoid NoMethodError on nil",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="user&.profile&.display_name  # safe navigation\nuser.profile.display_name   # potential NoMethodError",
                attack_vector="NoMethodError → 500 error → Information disclosure via error pages",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-007",
                name="puts/print/p in Production Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Using puts/print/p for debugging in production code",
                pattern=re.compile(r'(?i)^\s*(puts|print|p|pp|ap)\s'),
                context_checks=[],
                suggestion="Use Rails.logger or Logging library for production logging",
                cwe_id="CWE-532",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example='Rails.logger.info("User action: #{current_user.id}")',
                attack_vector="Console output → Log pollution → Missing security events",
                mitre_technique="T1565 - Data Manipulation",
            ),
            SecurityCheck(
                id="RB-QLTY-008",
                name="Unused Local Variable",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Unused variables indicate dead code or logic errors",
                pattern=re.compile(r'(?i)^\s+\w+\s*=\s*\w+\s*$'),
                context_checks=[],
                suggestion="Remove unused variables or prefix with _ to indicate intentional disuse",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="# If unused, prefix with _:\n_result = some_method()\n# Or remove entirely",
                attack_vector="Dead code → Confusion → Logic errors",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-009",
                name="Use of send for Dynamic Dispatch",
                category="code-quality",
                severity=RiskLevel.MEDIUM,
                description="Using send with dynamic method names can bypass method visibility",
                pattern=re.compile(r'(?i)\bsend\b\s+(?!"(index|show|edit|update|destroy|create|new|delete"))'),
                context_checks=[],
                suggestion="Use public_send instead of send to respect method visibility",
                cwe_id="CWE-470",
                owasp_category="A03:2021 - Injection",
                remediation_example="# Use public_send instead of send:\nobj.public_send(:safe_method)\nsend bypasses private/protected",
                attack_vector="send → Private method call → Internal logic bypass",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RB-QLTY-010",
                name="Hardcoded URLs or Endpoints",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded URLs should be configurable via environment",
                pattern=re.compile(r'(?i)https?://[^"\'\s]+\.(com|org|net|io)\b'),
                context_checks=[],
                suggestion="Use environment variables or Rails.application.config for URLs",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="API_URL = ENV.fetch('API_URL', 'https://default.api.com')",
                attack_vector="Hardcoded URL → Environment mismatch → Data leakage to wrong endpoint",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RB-QLTY-011",
                name="Use of !! for Boolean Coercion",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Using !! for boolean conversion is less readable than explicit check",
                pattern=re.compile(r'!!\s*\('),
                context_checks=[],
                suggestion="Use more explicit boolean checks or .present? / .any? for collections",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example='# Instead of !!user:\nuser.present?\n\n# Instead of !!items:\nitems.any?',
                attack_vector="—",
                mitre_technique="—",
            ),
        ])

        return checks

    # ======================================================================
    # TAINT ANALYSIS
    # ======================================================================

    TAINT_SOURCE_PATTERNS = {
        "params": [
            r'(?i)\bparams\b',
            r'(?i)\brequest\b',
            r'(?i)\bcookies\b',
            r'(?i)\bsession\b',
            r'(?i)env\[',
        ],
        "user_input": [
            r'(?i)gets\s*\(',
            r'(?i)ARGF',
            r'(?i)STDIN',
            r'(?i)readline',
            r'(?i)readlines',
        ],
        "file_input": [
            r'(?i)File\.read',
            r'(?i)IO\.read',
            r'(?i)File\.open',
            r'(?i)IO\.open',
        ],
        "external_api": [
            r'(?i)Net::HTTP',
            r'(?i)HTTParty',
            r'(?i)RestClient',
            r'(?i)HTTP\.\w+',
        ],
    }

    TAINT_SINK_PATTERNS = {
        "sql_execution": [
            r'(?i)\.where\(',
            r'(?i)\.find_by_sql\(',
            r'(?i)\.execute\(',
            r'(?i)\.connection\.execute',
            r'(?i)\.create\(',
            r'(?i)\.update\(',
        ],
        "command_execution": [
            r'(?i)system\s*\(',
            r'(?i)exec\s*\(',
            r'(?i)`[^`]*`',
            r'(?i)IO\.popen',
            r'(?i)Open3',
        ],
        "file_operations": [
            r'(?i)File\.(open|write|rename|delete|chmod)',
            r'(?i)FileUtils',
            r'(?i)IO\.write',
        ],
        "http_request": [
            r'(?i)Net::HTTP',
            r'(?i)HTTParty',
            r'(?i)RestClient',
        ],
        "render_output": [
            r'(?i)render\s+',
            r'(?i)redirect_to',
            r'(?i)send_file',
        ],
    }

    def _extract_taint_sources(self, lines: List[str]) -> Set[str]:
        """Extract taint source variable names from lines."""
        sources = set()
        for category, patterns in self.TAINT_SOURCE_PATTERNS.items():
            for i, line in enumerate(lines):
                for pattern in patterns:
                    if re.search(pattern, line):
                        var_match = re.search(r'(\w+)\s*=\s*(params|request|cookies|session|env)', line)
                        if var_match:
                            sources.add(var_match.group(1))
                        elif category == "params" and "@" in line:
                            ivar_match = re.search(r'(@\w+)\s*=\s*(params|request|cookies)', line)
                            if ivar_match:
                                sources.add(ivar_match.group(1))
        return sources

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult,
                           frameworks: List[str]) -> None:
        """Track tainted variables from sources to sinks."""
        if not self._taint_sources:
            return

        tainted_vars: Set[str] = self._taint_sources.copy()

        for _ in range(3):
            new_tainted: Set[str] = set()
            for i, line in enumerate(lines):
                for tv in tainted_vars:
                    assign = re.search(r'(\w+|@\w+)\s*=\s*' + re.escape(tv), line)
                    if assign:
                        new_tainted.add(assign.group(1))
            if not new_tainted:
                break
            tainted_vars |= new_tainted

        tainted_sinks: Dict[str, List[Tuple[int, str]]] = {}
        for sink_cat, patterns in self.TAINT_SINK_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line):
                        for var in tainted_vars:
                            if re.search(r'\b' + re.escape(var) + r'\b', line):
                                if sink_cat not in tainted_sinks:
                                    tainted_sinks[sink_cat] = []
                                tainted_sinks[sink_cat].append((i, line.strip()))
                                break

        for sink_cat, positions in tainted_sinks.items():
            for line_num, code in positions:
                severity = RiskLevel.CRITICAL if sink_cat in ("sql_execution", "command_execution") else RiskLevel.HIGH
                cwe_map = {
                    "sql_execution": "CWE-89", "command_execution": "CWE-78",
                    "file_operations": "CWE-22", "http_request": "CWE-918",
                    "render_output": "CWE-79",
                }
                issue_id = f"RB-TAINT-{sink_cat[:4].upper()}-001"
                result.findings.append(Finding(
                    file=str(result.file_path),
                    line=line_num,
                    column=1,
                    issue_type=issue_id,
                    message=f"Tainted data from user input flows to {sink_cat} — possible injection",
                    risk_level=severity,
                    code_snippet=code[:200],
                    suggestion=f"Validate and sanitize all user input before reaching {sink_cat}",
                ))

    # ======================================================================
    # CROSS-LINE ANALYSIS
    # ======================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult,
                                frameworks: List[str]) -> None:
        """Detect patterns that span multiple lines."""
        self._check_multiline_sql(content, lines, result)
        self._check_long_methods(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Detect multi-line SQL concatenation spanning several lines."""
        sql_keywords = r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s'
        for i, line in enumerate(lines):
            if re.search(sql_keywords, line) and re.search(r'\+\s*$|,\s*$', line):
                concat_lines = [i + 1]
                j = i + 1
                while j < len(lines) and re.search(r'["\'][^"\']*["\']\s*\+?\s*$|,\s*$', lines[j]):
                    concat_lines.append(j + 1)
                    j += 1
                    if j - i > 5:
                        break
                if len(concat_lines) > 2:
                    result.findings.append(Finding(
                        file=str(result.file_path),
                        line=concat_lines[0],
                        column=1,
                        issue_type="RB-SQL-MULTI",
                        message="Multi-line SQL concatenation detected across lines",
                        risk_level=RiskLevel.HIGH,
                        code_snippet=lines[concat_lines[0] - 1].strip()[:200],
                        suggestion="Refactor multi-line SQL into a parameterized query with ? placeholders",
                    ))

    def _check_long_methods(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Detect methods longer than 30 lines."""
        method_start = None
        method_name = None
        brace_depth = 0
        in_method = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            method_match = re.match(r'^\s*def\s+(\w+)', stripped)
            if method_match:
                method_start = i
                method_name = method_match.group(1)
                in_method = True
                brace_depth = stripped.count("end") - stripped.count("def")

            if in_method:
                brace_depth += stripped.count("do") + stripped.count("{") - stripped.count("end") - stripped.count("}")
                if brace_depth <= 0 or (brace_depth == 0 and i > method_start):
                    length = i - method_start
                    if length > 30:
                        result.findings.append(Finding(
                            file=str(result.file_path),
                            line=method_start + 1,
                            column=1,
                            issue_type="RB-QLTY-LONG",
                            message=f"Method '{method_name}' is {length} lines long — consider refactoring",
                            risk_level=RiskLevel.LOW,
                            code_snippet=lines[method_start].strip()[:200],
                            suggestion="Extract helper methods to reduce method size below 30 lines",
                        ))
                    in_method = False

    # ======================================================================
    # UTILITY
    # ======================================================================

    def can_analyze(self, file_path: Path) -> bool:
        return (file_path.suffix.lower() in [".rb", ".rbw", ".rake"] or
                file_path.name in ["Gemfile", "Rakefile"])
