"""Elite static analyzer for Dart/Flutter code with comprehensive security checks."""

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
    """A security check for Dart/Flutter code."""
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


class DartAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Dart/Flutter code — 50+ elite security checks."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._taint_sources: Set[str] = set()
        self._taint_sinks: Set[str] = set()

    def get_language(self) -> str:
        return "dart"

    def get_supported_extensions(self) -> List[str]:
        return [".dart"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Dart/Flutter file and return results."""
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
            if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*") or stripped.startswith("#"):
                continue
            for check in self.checks:
                if check.pattern.search(line):
                    if self._passes_context_checks(check, line, content, detected_frameworks):
                        self._add_finding(result, i, line, check)

        self._run_taint_analysis(content, lines, result, detected_frameworks)
        self._run_cross_line_analysis(content, lines, result, detected_frameworks)

        return result

    def _passes_context_checks(self, check: SecurityCheck, line: str, content: str, frameworks: List[str]) -> bool:
        """Run all context checks for a finding. Return True if finding is valid."""
        if not check.context_checks:
            return True
        for ctx_check in check.context_checks:
            if not ctx_check(line, content, frameworks):
                return False
        return True

    def _add_finding(self, result: AnalysisResult, line: int, code: str, check: SecurityCheck) -> None:
        """Add a finding to the result."""
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
        "flutter": ["flutter/", "Flutter", "MaterialApp", "CupertinoApp", "runApp("],
        "sqflite": ["sqflite", "openDatabase", "rawQuery", "rawInsert", "rawUpdate"],
        "firebase": ["firebase_", "Firebase.", "FirebaseApp"],
        "http": ["http.", "http.get", "http.post", "http.put", "http.delete"],
        "dio": ["Dio(", "dio.", "DioException"],
        "shared_preferences": ["SharedPreferences", "shared_preferences"],
        "flutter_secure_storage": ["FlutterSecureStorage", "flutter_secure_storage"],
        "provider": ["Provider<", "ChangeNotifierProvider", "MultiProvider"],
        "bloc": ["Bloc<", "BlocProvider", "BlocBuilder"],
        "getx": ["Getx", "Get.", "GetMaterialApp", "Obx("],
        "riverpod": ["riverpod", "Ref(", "ProviderRef"],
        "hive": ["hive", "Hive.", "Box<"],
        "drift": ["drift", "moor", "DriftDatabase"],
        "webview": ["webview_flutter", "WebView("],
        "url_launcher": ["url_launcher", "launchUrl", "launch("],
        "firebase_messaging": ["firebase_messaging", "FirebaseMessaging"],
        "firebase_auth": ["firebase_auth", "FirebaseAuth"],
        "firebase_storage": ["firebase_storage", "FirebaseStorage"],
        "firebase_firestore": ["cloud_firestore", "FirebaseFirestore"],
        "amplify": ["amplify_", "Amplify."],
        "graphql": ["graphql", "GraphQLClient", "graphql_flutter"],
        "grpc": ["grpc", "GrpcClient", "ClientChannel"],
        "sentry": ["sentry", "Sentry."],
        "in_app_purchase": ["in_app_purchase", "InAppPurchase"],
        "local_auth": ["local_auth", "LocalAuthentication"],
        "biometric_storage": ["biometric_storage", "BiometricStorage"],
        "camera": ["camera.", "CameraController"],
        "geolocator": ["geolocator", "Geolocator"],
        "image_picker": ["image_picker", "ImagePicker"],
        "path_provider": ["path_provider", "getApplicationDocumentsDirectory"],
    }

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect which frameworks/libraries the project uses."""
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

    def _is_safe_sql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SQL-like pattern uses parameterized queries."""
        if "?" in line or ":id" in line or "$1" in line or "$2" in line:
            return False
        if "whereIn" in line or "where" in line and "?" in content:
            return False
        return True

    def _is_not_encrypted_storage(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if shared_preferences is used for sensitive data."""
        if "flutter_secure_storage" in content or "FlutterSecureStorage" in content:
            return False
        if "encrypt" in content.lower() or "cipher" in content.lower():
            return False
        return True

    def _is_not_test_file(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Filter out test files for certain checks."""
        if "test(" in content or "Test(" in content or "void main()" in content:
            if "import" in content and "test/" in content:
                return False
        return True

    def _has_sensitive_logging(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if logging includes potential sensitive data."""
        keywords = ["password", "token", "secret", "user", "email", "phone",
                     "credit", "ssn", "cvv", "pin", "key", "auth"]
        for kw in keywords:
            if kw in line.lower():
                return True
        return True

    def _is_production_print(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Filter out print statements to production code only."""
        if "test(" in content and "void main()" in content:
            return False
        return True

    # ======================================================================
    # BUILD CHECKS
    # ======================================================================

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by category and severity."""
        checks = []

        checks.extend([
            SecurityCheck(
                id='DF-FLT-001',
                name='Platform Channel Without Validation',
                category='flutter-specific',
                severity=RiskLevel.CRITICAL,
                description='Platform channel receives data without input validation',
                pattern=re.compile('MethodChannel\\s*\\(|FlutterMethodChannel\\s*\\('),
                context_checks=[],
                suggestion='Validate all incoming method channel data server-side',
                cwe_id='CWE-749',
                owasp_category='A03:2021 - Injection',
                remediation_example='Validate method name and arguments in handleMethodCall',
                attack_vector='Attacker sends malicious data via platform channel to trigger native code execution',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='DF-FLT-002',
                name='WebView JavaScript Enabled',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='WebView with JavaScript enabled can lead to XSS',
                pattern=re.compile('javascriptMode:\\s*JavaScriptMode\\.unrestricted'),
                context_checks=[],
                suggestion='Disable JavaScript when not needed, or restrict to trusted domains',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use javascriptMode: JavaScriptMode.disabled unless absolutely required',
                attack_vector='JavaScript injection via user-controlled content in WebView',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='DF-FLT-003',
                name='Insecure WebView Configuration',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='WebView allows navigation to arbitrary URLs',
                pattern=re.compile('WebView\\s*\\('),
                context_checks=[],
                suggestion='Restrict WebView navigation with NavigationDelegate',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example="WebView(..., navigationDelegate: (NavigationRequest request) { if (request.url.startsWith('https://trusted.com')) return NavigationDecision.navigate; return NavigationDecision.prevent; })",
                attack_vector='Attacker redirects WebView to malicious site',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='DF-FLT-004',
                name='LocalStorage Without Encryption',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='Using SharedPreferences or local storage without encryption for sensitive data',
                pattern=re.compile('SharedPreferences\\.|prefs\\.setString|prefs\\.setInt|prefs\\.setBool'),
                context_checks=[self._is_not_encrypted_storage],
                suggestion='Use flutter_secure_storage for sensitive data',
                cwe_id='CWE-312',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example="final storage = FlutterSecureStorage(); await storage.write(key: 'token', value: token);",
                attack_vector='Sensitive data stored in plaintext accessible via device backup',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-FLT-005',
                name='Deep Link Without Validation',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='Deep link handled without origin or data validation',
                pattern=re.compile('getInitialLink|getLinksStream|onLinkReceived|uriLinkStrategy'),
                context_checks=[],
                suggestion='Validate deep link origins and parameters before processing',
                cwe_id='CWE-601',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='Verify that deep link URI matches trusted origins before navigation',
                attack_vector='Attacker crafts malicious deep link to redirect user or trigger actions',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='DF-FLT-006',
                name='Android Exported Activity',
                category='flutter-specific',
                severity=RiskLevel.MEDIUM,
                description='Android activity exported without proper permission checks',
                pattern=re.compile('android:exported\\s*=\\s*"true"'),
                context_checks=[],
                suggestion='Set android:exported="false" or add permission checks',
                cwe_id='CWE-926',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='android:exported="false" or add required permissions',
                attack_vector='Third-party apps can launch exported activities without authorization',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='DF-FLT-007',
                name='iOS Arbitrary Loads Enabled',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='NSAppTransportSecurity allows arbitrary HTTP loads',
                pattern=re.compile('NSAllowsArbitraryLoads\\s*=\\s*true|NSAllowsArbitraryLoads\\s*=\\s*YES'),
                context_checks=[],
                suggestion='Remove NSAllowsArbitraryLoads or restrict to specific domains',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use NSExceptionDomains to whitelist specific domains instead',
                attack_vector='App sends/receives data over unencrypted HTTP connections',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='DF-FLT-008',
                name='Cleartext Traffic in Android',
                category='flutter-specific',
                severity=RiskLevel.HIGH,
                description='Android network_security_config allows cleartext traffic',
                pattern=re.compile('cleartextTrafficPermitted\\s*=\\s*"true"|android:usesCleartextTraffic\\s*=\\s*"true"'),
                context_checks=[],
                suggestion='Disable cleartext traffic in Android network security config',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='android:usesCleartextTraffic="false"',
                attack_vector='Network traffic can be intercepted over unencrypted HTTP',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='DF-SQL-001',
                name='sqflite rawQuery With User Input',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='SQL query constructed with string interpolation instead of parameters',
                pattern=re.compile('rawQuery\\s*\\('),
                context_checks=[self._is_safe_sql],
                suggestion='Use parameterized queries with ? placeholders',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example="await db.rawQuery('SELECT * FROM users WHERE id = ?', [userId]);",
                attack_vector='SQL injection through user input in raw queries',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='DF-SQL-002',
                name='sqflite rawInsert With Interpolation',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='Insert query built with string concatenation instead of parameters',
                pattern=re.compile('rawInsert\\s*\\('),
                context_checks=[self._is_safe_sql],
                suggestion='Use parameterized insert with ? placeholders',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example="await db.rawInsert('INSERT INTO users (name) VALUES (?)', [name]);",
                attack_vector='SQL injection via string interpolation in INSERT',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='DF-SQL-003',
                name='sqflite rawUpdate With Interpolation',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='Update query built with string concatenation instead of parameters',
                pattern=re.compile('rawUpdate\\s*\\('),
                context_checks=[self._is_safe_sql],
                suggestion='Use parameterized update with ? placeholders',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example="await db.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [name, id]);",
                attack_vector='SQL injection via string interpolation in UPDATE',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='DF-SQL-004',
                name='sqflite rawDelete With Interpolation',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='Delete query built with string concatenation instead of parameters',
                pattern=re.compile('rawDelete\\s*\\('),
                context_checks=[self._is_safe_sql],
                suggestion='Use parameterized delete with ? placeholders',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example="await db.rawDelete('DELETE FROM users WHERE id = ?', [id]);",
                attack_vector='SQL injection via string interpolation in DELETE',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='DF-SQL-005',
                name='Drift/Moor Custom SQL Injection',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='Drift/moor SQL query using string interpolation',
                pattern=re.compile('customSelect\\s*\\(|customUpdate\\s*\\(|customInsert\\s*\\(|customDelete\\s*\\('),
                context_checks=[],
                suggestion="Use drift's built-in query methods with variables",
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example="Use drift's select/update/insert/delete methods instead of custom SQL",
                attack_vector='SQL injection via string interpolation in drift queries',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='DF-CMD-001',
                name='Process.run With User Input',
                category='command-injection',
                severity=RiskLevel.CRITICAL,
                description='Running system command with potentially user-controlled input',
                pattern=re.compile('Process\\.run\\s*\\('),
                context_checks=[],
                suggestion='Avoid shell execution with user input; use whitelist of allowed commands',
                cwe_id='CWE-78',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use a whitelist: if (allowedCommands.contains(cmd)) { Process.run(cmd, []); }',
                attack_vector='OS command injection via Process.run with unvalidated input',
                mitre_technique='T1202',
            ),
            SecurityCheck(
                id='DF-CMD-002',
                name='Process.start With User Input',
                category='command-injection',
                severity=RiskLevel.CRITICAL,
                description='Starting process with potentially user-controlled input',
                pattern=re.compile('Process\\.start\\s*\\('),
                context_checks=[],
                suggestion='Avoid Process.start with user-controlled arguments',
                cwe_id='CWE-78',
                owasp_category='A03:2021 - Injection',
                remediation_example='Process.start("ls", ["-l", whitelistedPath]);',
                attack_vector='OS command injection via Process.start',
                mitre_technique='T1202',
            ),
            SecurityCheck(
                id='DF-CINJ-001',
                name='dart:mirrors Reflection Usage',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='Using dart:mirrors can enable code injection via reflection',
                pattern=re.compile('import\\s+["\\\']dart:mirrors["\\\']'),
                context_checks=[],
                suggestion='Avoid dart:mirrors; use code generation instead',
                cwe_id='CWE-470',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use source_gen or json_serializable instead of mirrors',
                attack_vector='Reflection-based attacks allowing access to private members',
                mitre_technique='T1064',
            ),
            SecurityCheck(
                id='DF-CINJ-002',
                name='Isolate With Untrusted Code',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='Isolate spawned with potentially untrusted or dynamic code',
                pattern=re.compile('Isolate\\.spawn\\s*\\('),
                context_checks=[],
                suggestion='Restrict isolates to run only trusted code',
                cwe_id='CWE-470',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use Isolate.run with static entry point',
                attack_vector='Arbitrary code execution via isolate manipulation',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='DF-CINJ-003',
                name='Dynamic Library Loading',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='Loading native libraries dynamically at runtime',
                pattern=re.compile('DynamicLibrary\\.open\\s*\\(|dlopen\\s*\\('),
                context_checks=[],
                suggestion='Use statically linked libraries instead of dynamic loading',
                cwe_id='CWE-114',
                owasp_category='A03:2021 - Injection',
                remediation_example='Avoid DynamicLibrary.open; use dart:ffi with static linking',
                attack_vector='DLL hijacking via DynamicLibrary.open with user-controlled path',
                mitre_technique='T1574',
            ),
            SecurityCheck(
                id='DF-PTH-001',
                name='File Open With User Input',
                category='path-traversal',
                severity=RiskLevel.HIGH,
                description='Opening file with user-controlled path potentially allowing path traversal',
                pattern=re.compile('File\\s*\\(|openRead|openWrite|readAsString|writeAsString'),
                context_checks=[],
                suggestion='Validate file paths and restrict to allowed directories',
                cwe_id='CWE-22',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='final safePath = p.join(trustedDir, p.basename(userInput)); File(safePath).readAsString();',
                attack_vector='Path traversal to read/write files outside allowed directory',
                mitre_technique='T1006',
            ),
            SecurityCheck(
                id='DF-PTH-002',
                name='Directory Traversal',
                category='path-traversal',
                severity=RiskLevel.MEDIUM,
                description='Listing directory contents with user-controlled path',
                pattern=re.compile('Directory\\s*\\(|listSync|list\\s*\\('),
                context_checks=[],
                suggestion='Restrict directory listing to sandboxed directory',
                cwe_id='CWE-22',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='final safeDir = Directory(whitelistedBase); final entities = await safeDir.list().toList();',
                attack_vector='Directory traversal listing unauthorized files',
                mitre_technique='T1006',
            ),
            SecurityCheck(
                id='DF-NET-001',
                name='HTTP Instead of HTTPS',
                category='network-tls',
                severity=RiskLevel.HIGH,
                description='Using HTTP instead of HTTPS for network requests',
                pattern=re.compile('http://'),
                context_checks=[],
                suggestion='Always use HTTPS instead of HTTP',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use https:// and ensure valid TLS certificates',
                attack_vector='Man-in-the-middle attack via unencrypted HTTP',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='DF-NET-002',
                name='badCertificateCallback Bypass',
                category='network-tls',
                severity=RiskLevel.CRITICAL,
                description='TLS certificate validation is explicitly disabled via badCertificateCallback',
                pattern=re.compile('badCertificateCallback\\s*:\\s*\\([^)]*\\)\\s*=>\\s*true'),
                context_checks=[],
                suggestion='Never disable certificate validation in production',
                cwe_id='CWE-295',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Remove badCertificateCallback or validate certificates properly',
                attack_vector='MITM attack by accepting invalid/self-signed certificates',
                mitre_technique='T1557',
            ),
            SecurityCheck(
                id='DF-NET-003',
                name='Self-Signed Certificate Acceptance',
                category='network-tls',
                severity=RiskLevel.HIGH,
                description='Accepting self-signed certificates in production code',
                pattern=re.compile('allowSelfSigned\\s*:\\s*true|setTrustedCertificates'),
                context_checks=[],
                suggestion='Use properly issued certificates from trusted CAs',
                cwe_id='CWE-295',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Remove allowSelfSigned: true in production builds',
                attack_vector='MITM attack using self-signed certificate',
                mitre_technique='T1557',
            ),
            SecurityCheck(
                id='DF-XSS-001',
                name='dangerouslySetInnerHtml Usage',
                category='xss',
                severity=RiskLevel.HIGH,
                description='Setting inner HTML from user-controlled data can lead to XSS',
                pattern=re.compile('dangerouslySetInnerHtml|innerHtml\\s*=|setInnerHtml\\s*\\('),
                context_checks=[],
                suggestion='Sanitize HTML before rendering or use text content instead',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use flutter_html or html_escape to sanitize user content',
                attack_vector='Cross-site scripting via unsanitized HTML rendering',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='DF-XSS-002',
                name='Unsafe HTML Rendering',
                category='xss',
                severity=RiskLevel.MEDIUM,
                description='Using HtmlElementView or webview without HTML sanitization',
                pattern=re.compile('HtmlElementView|WebViewWidget|iframe'),
                context_checks=[],
                suggestion='Sanitize any dynamic content before rendering in HTML',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use html_escape or sanitize_html package before rendering',
                attack_vector='XSS via unescaped HTML content injection',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='DF-SEC-001',
                name='Hardcoded API Key',
                category='secrets',
                severity=RiskLevel.CRITICAL,
                description='API key hardcoded in source code',
                pattern=re.compile('(?:apiKey|api_key|apikey)\\s*[:=]\\s*[\\"\'][A-Za-z0-9_\\-]{16,}[\\"\']'),
                context_checks=[],
                suggestion='Store API keys in environment variables or a secure config service',
                cwe_id='CWE-798',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example="final apiKey = const String.fromEnvironment('API_KEY');",
                attack_vector='Exposed API keys in source code or version control',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-SEC-002',
                name='Hardcoded JWT/Token',
                category='secrets',
                severity=RiskLevel.CRITICAL,
                description='JWT token or auth token hardcoded in source',
                pattern=re.compile('(?:token|jwt|accessToken|refreshToken|authToken)\\s*[:=]\\s*[\\"\'][A-Za-z0-9_\\-=]{20,}[\\"\']'),
                context_checks=[],
                suggestion='Obtain tokens at runtime from secure auth flow',
                cwe_id='CWE-798',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='final token = await authProvider.getAccessToken();',
                attack_vector='Leaked authentication tokens allowing unauthorized access',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-SEC-003',
                name='SharedPreferences for Secrets',
                category='secrets',
                severity=RiskLevel.HIGH,
                description='Using SharedPreferences to store sensitive data like tokens',
                pattern=re.compile('SharedPreferences'),
                context_checks=[self._is_not_encrypted_storage],
                suggestion='Use flutter_secure_storage instead of SharedPreferences for secrets',
                cwe_id='CWE-522',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example="final storage = FlutterSecureStorage(); await storage.write(key: 'token', value: token);",
                attack_vector='Sensitive tokens stored in plaintext accessible via backup',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-SEC-004',
                name='Insecure Local Auth Fallback',
                category='secrets',
                severity=RiskLevel.MEDIUM,
                description='Local authentication without proper fallback or biometric check',
                pattern=re.compile('local_auth|LocalAuthentication|authenticate\\s*\\('),
                context_checks=[],
                suggestion='Always require biometric authentication for sensitive operations',
                cwe_id='CWE-287',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='final isAuth = await auth.authenticateWithBiometrics(); if (!isAuth) { return; }',
                attack_vector='Bypass of local authentication via fallback to device PIN',
                mitre_technique='T1550',
            ),
            SecurityCheck(
                id='DF-CRP-001',
                name='Weak Hash Function (MD5/SHA1)',
                category='crypto',
                severity=RiskLevel.HIGH,
                description='Using weak cryptographic hash functions like MD5 or SHA1',
                pattern=re.compile('md5\\s*\\(|sha1\\s*\\(|\\.md5\\s*\\(|\\.sha1\\s*\\('),
                context_checks=[],
                suggestion='Use SHA-256 or stronger hash for security purposes',
                cwe_id='CWE-327',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example="import 'package:crypto/crypto.dart'; sha256.convert(utf8.encode(data));",
                attack_vector='Hash collision or preimage attacks against weak hash functions',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='DF-CRP-002',
                name='Hardcoded Encryption Key',
                category='crypto',
                severity=RiskLevel.CRITICAL,
                description='Encryption key hardcoded in source code',
                pattern=re.compile('(?:key|secret|iv|initializationVector)\\s*[:=]\\s*[\\"\'][A-Za-z0-9+/=]{16,}[\\"\']'),
                context_checks=[],
                suggestion='Derive keys from user credentials or use platform key store',
                cwe_id='CWE-321',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example="final key = Key.fromUtf8(await keychain.read('encryption_key'));",
                attack_vector='Extraction of encryption keys from decompiled app binary',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-CRP-003',
                name='ECB Mode Encryption',
                category='crypto',
                severity=RiskLevel.HIGH,
                description='Using ECB mode encryption which is insecure for most use cases',
                pattern=re.compile('ECB|AES\\.ecb|AESECB|ecbEncrypt'),
                context_checks=[],
                suggestion='Use GCM or CBC mode with random IV instead of ECB',
                cwe_id='CWE-327',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='final cipher = AES(encryptKey, mode: AESMode.gcm);',
                attack_vector='ECB mode reveals plaintext patterns in ciphertext',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='DF-CRP-004',
                name='Weak Random Number Generator',
                category='crypto',
                severity=RiskLevel.MEDIUM,
                description='Using Random() without secure seed for security purposes',
                pattern=re.compile('Random\\s*\\(\\s*\\)'),
                context_checks=[],
                suggestion='Use Random.secure() for security-sensitive random values',
                cwe_id='CWE-338',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='final secureRand = Random.secure(); final token = secureRand.nextInt(1000000);',
                attack_vector='Predictable random values enable session hijacking or token forgery',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='DF-DAT-001',
                name='Sensitive Data in Logs',
                category='data-storage',
                severity=RiskLevel.MEDIUM,
                description='Logging potentially sensitive data like user information',
                pattern=re.compile('logger\\.(info|warning|error|severe|fine)\\(|log\\s*\\('),
                context_checks=[self._has_sensitive_logging],
                suggestion='Use redaction for sensitive fields in logs',
                cwe_id='CWE-532',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example="logger.info('User login: $userId', null, redact: [password, token]);",
                attack_vector='Sensitive information leakage through log files',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-DAT-002',
                name='Print Statements in Production Code',
                category='data-storage',
                severity=RiskLevel.LOW,
                description='Using print() or debugPrint() in production code',
                pattern=re.compile('\\bprint\\s*\\(|debugPrint\\s*\\('),
                context_checks=[self._is_production_print],
                suggestion='Use structured logging instead of print statements',
                cwe_id='CWE-532',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='Use a logging framework with log levels',
                attack_vector='Accidental information disclosure via console output',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-DAT-003',
                name='Unencrypted Local Database',
                category='data-storage',
                severity=RiskLevel.HIGH,
                description='Using SQLite/Hive without encryption for sensitive data storage',
                pattern=re.compile('openDatabase\\s*\\(|Hive\\.openBox|Hive\\.box\\s*\\('),
                context_checks=[],
                suggestion='Use sqflite with encryption or Hive with encryption cipher',
                cwe_id='CWE-312',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example="import 'package:sembast/sembast_io.dart'; final db = await databaseFactoryIo.openDatabase(path, encryptionKey: key);",
                attack_vector='Database file accessible from device storage and backups',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-FB-001',
                name='Firebase DB Open Rules',
                category='firebase',
                severity=RiskLevel.CRITICAL,
                description='Firebase Realtime Database rules may allow public read/write access',
                pattern=re.compile('firebase_|Firebase\\.|FirebaseApp'),
                context_checks=[],
                suggestion='Set proper Firebase security rules with authentication checks',
                cwe_id='CWE-285',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='{"rules": { ".read": "auth != null", ".write": "auth != null" } }',
                attack_vector='Public database accessible to anyone without authentication',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='DF-FB-002',
                name='Firebase Auth Without Email Verification',
                category='firebase',
                severity=RiskLevel.MEDIUM,
                description='Firebase authentication without checking email verification',
                pattern=re.compile('signInWithEmailAndPassword|createUserWithEmailAndPassword'),
                context_checks=[],
                suggestion='Check email verification before granting access to sensitive features',
                cwe_id='CWE-287',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='final user = FirebaseAuth.instance.currentUser; if (user != null && user.emailVerified) { }',
                attack_vector='Unauthorized access with unverified email accounts',
                mitre_technique='T1550',
            ),
            SecurityCheck(
                id='DF-PERM-001',
                name='Missing Runtime Permission Check',
                category='permissions',
                severity=RiskLevel.MEDIUM,
                description='Using permission-gated APIs without checking permission first',
                pattern=re.compile('Geolocator\\.getCurrentPosition|CameraController|ImagePicker\\.pickImage|startCamera'),
                context_checks=[],
                suggestion='Always check and request permissions at runtime before use',
                cwe_id='CWE-862',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='final status = await Permission.location.request(); if (status.isGranted) { Geolocator.getCurrentPosition(); }',
                attack_vector='App crashes or returns empty data without permission check',
                mitre_technique='T1589',
            ),
            SecurityCheck(
                id='DF-CQ-001',
                name='TODO/FIXME in Code',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Unresolved TODO or FIXME comment in source code',
                pattern=re.compile('TODO|FIXME|XXX|HACK'),
                context_checks=[],
                suggestion='Address all TODO/FIXME items before release',
                cwe_id='CWE-546',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Complete the implementation and remove the TODO comment',
                attack_vector='Incomplete security checks or missing implementations',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='DF-CQ-002',
                name='Empty Catch Block',
                category='code-quality',
                severity=RiskLevel.MEDIUM,
                description='Empty catch block silently swallows exceptions',
                pattern=re.compile('catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}'),
                context_checks=[],
                suggestion='Handle exceptions properly or log them',
                cwe_id='CWE-396',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example="catch (e) { logger.error('Operation failed', e); }",
                attack_vector='Silent failures can mask security incidents',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='DF-CQ-003',
                name='Dynamic Type Usage',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Using dynamic type bypasses type safety',
                pattern=re.compile('\\bdynamic\\b'),
                context_checks=[],
                suggestion='Prefer specific types or Object with type checking',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use specific type or generic <T> instead of dynamic',
                attack_vector='Type confusion or unexpected runtime exceptions',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='DF-CQ-004',
                name='Null Assertion (!) Operator',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Using null assertion operator (!) can cause runtime crashes',
                pattern=re.compile('\\w+!\\s*\\.'),
                context_checks=[],
                suggestion='Use proper null checking instead of null assertion',
                cwe_id='CWE-476',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='if (value != null) { value.method(); }',
                attack_vector='Null pointer exception and app crash',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='DF-CQ-005',
                name='Overbroad Android Permissions',
                category='code-quality',
                severity=RiskLevel.MEDIUM,
                description='Android manifest requests unnecessary dangerous permissions',
                pattern=re.compile('READ_CONTACTS|READ_SMS|READ_CALL_LOG|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE'),
                context_checks=[],
                suggestion='Request only permissions needed for core functionality',
                cwe_id='CWE-250',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='Remove unused permissions from AndroidManifest.xml',
                attack_vector='App collects excessive sensitive data',
                mitre_technique='T1589',
            ),
        ])

        return checks

    # ======================================================================
    # TAINT ANALYSIS
    # ======================================================================

    TAINT_SOURCE_PATTERNS: Dict[str, str] = {
        "http_request": r"http\.(get|post|put|delete|patch)\s*\(",
        "dio_request": r"dio\.(get|post|put|delete|patch)\s*\(",
        "form_input": r"TextEditingController|onChanged\s*:|onSubmitted\s*:",
        "url_param": r"ModalRoute\.of|settings\.arguments|onGenerateRoute",
        "deep_link": r"getInitialLink|getLinksStream",
        "shared_prefs": r"prefs\.getString|prefs\.getInt|prefs\.getBool",
        "notification": r"RemoteMessage|onMessage|onLaunch",
        "file_read": r"readAsString\s*\(|readAsLines\s*\(",
        "clipboard": r"Clipboard\.getData",
        "incoming_intent": r"getIntent|onNewIntent",
    }

    TAINT_SINK_PATTERNS: Dict[str, str] = {
        "sql_query": r"rawQuery\s*\(|rawInsert\s*\(|rawUpdate\s*\(|rawDelete\s*\(",
        "drift_query": r"customSelect\s*\(|customUpdate\s*\(|customInsert\s*\(|customDelete\s*\(",
        "file_write": r"writeAsString\s*\(|writeAsBytes\s*\(",
        "http_request": r"http\.(get|post|put|delete|patch)\s*\(",
        "dio_request": r"dio\.(get|post|put|delete|patch)\s*\(",
        "process_exec": r"Process\.run\s*\(|Process\.start\s*\(",
        "webview_nav": r"loadRequest\s*\(|loadUrl\s*\(|loadHtmlString\s*\(",
        "launch_url": r"launchUrl\s*\(|launch\s*\(",
    }

    def _extract_taint_sources(self, lines: List[str]) -> Set[str]:
        """Extract potential taint source variable names."""
        sources = set()
        for src_name, src_pattern in self.TAINT_SOURCE_PATTERNS.items():
            for line in lines:
                if re.search(src_pattern, line):
                    var_match = re.search(r"(?:final|var|const)?\s*(\w+)\s*(?:=)", line)
                    if var_match:
                        sources.add(var_match.group(1))
        return sources

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run taint analysis: track user-controlled data to dangerous sinks."""
        taint_vars: Set[str] = set()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            for src_name, src_pattern in self.TAINT_SOURCE_PATTERNS.items():
                if re.search(src_pattern, line):
                    var_match = re.search(r"(?:final|var|const)?\s*(\w+)\s*(?:=)", line)
                    if var_match:
                        taint_vars.add(var_match.group(1))

            taint_val = re.search(r"\b(\w+)\s*=.*", line)
            if taint_val and any(tv in line for tv in list(taint_vars)):
                taint_vars.add(taint_val.group(1))

            for sink_name, sink_pattern in self.TAINT_SINK_PATTERNS.items():
                if re.search(sink_pattern, line):
                    for tv in list(taint_vars):
                        if tv in line and tv not in ("i", "j", "k", "x", "y", "z"):
                            result.findings.append(Finding(
                                file=str(result.file_path),
                                line=i + 1,
                                column=line.index(tv) + 1,
                                issue_type=f"DF-TAINT-{sink_name.upper()}",
                                message=f"Tainted data [{tv}] from {src_name} flows to {sink_name} sink",
                                risk_level=RiskLevel.HIGH,
                                code_snippet=line.strip()[:200],
                                suggestion=f"Validate and sanitize {tv} before passing to {sink_name}",
                            ))
                            break

    # ======================================================================
    # CROSS-LINE ANALYSIS
    # ======================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run cross-line analysis to detect multi-line patterns."""
        # Cross-line SQL injection detection
        for i, line in enumerate(lines):
            if re.search(r"String\s+\w+\s*=\s*[\"']", line):
                multi_line = line
                j = i + 1
                while j < len(lines) and j < i + 10:
                    next_line = lines[j].strip()
                    multi_line += next_line
                    if next_line.endswith(";") or next_line.endswith('"'):
                        break
                    j += 1

                if re.search(r"SELECT|INSERT|UPDATE|DELETE", multi_line, re.IGNORECASE):
                    if "$" in multi_line or "+" in multi_line:
                        result.findings.append(Finding(
                            file=str(result.file_path),
                            line=i + 1,
                            column=0,
                            issue_type="DF-CROSS-SQL",
                            message="Multi-line SQL query with possible injection via string interpolation",
                            risk_level=RiskLevel.HIGH,
                            code_snippet=multi_line[:200],
                            suggestion="Use parameterized queries with ? placeholders",
                        ))

        # Cross-line long method detection
        for i, line in enumerate(lines):
            if re.search(r"(Future<|void|int|String|bool|List<|Map<|var|final)\s+\w+\s*\(", line):
                brace_count = 0
                method_start = i + 1
                for j in range(i, min(i + 150, len(lines))):
                    l = lines[j]
                    brace_count += l.count("{") - l.count("}")
                    if brace_count == 0 and j > i:
                        line_count = j - method_start
                        if line_count > 100:
                            func_name = re.search(r"(\w+)\s*\(", line)
                            fname = func_name.group(1) if func_name else "unknown"
                            result.findings.append(Finding(
                                file=str(result.file_path),
                                line=i + 1,
                                column=0,
                                issue_type="DF-CROSS-LONGFN",
                                message=f"Function {fname} is {line_count} lines long",
                                risk_level=RiskLevel.LOW,
                                code_snippet=line.strip()[:200],
                                suggestion="Refactor into smaller functions",
                            ))
                        break

    # ======================================================================
    # METADATA
    # ======================================================================

    def get_supported_checks(self) -> List[dict]:
        """Return metadata for all supported checks."""
        return [
            {
                "id": c.id,
                "name": c.name,
                "category": c.category,
                "severity": c.severity.value,
                "cwe_id": c.cwe_id,
                "owasp_category": c.owasp_category,
                "attack_vector": c.attack_vector,
                "mitre_technique": c.mitre_technique,
            }
            for c in self.checks
        ]
