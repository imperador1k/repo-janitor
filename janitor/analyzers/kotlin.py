"""Elite static analyzer for Kotlin code with comprehensive security checks."""

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
    """A 'security unit test' for Kotlin code."""
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


class KotlinAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Kotlin code - designed for enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._taint_sources: Set[str] = set()
        self._taint_sinks: Set[str] = set()

    def get_language(self) -> str:
        return "kotlin"

    def get_supported_extensions(self) -> List[str]:
        return [".kt", ".kts", ".ktm"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Kotlin file and return results."""
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

        # Phase 1: Pattern-based checks
        for i, line in enumerate(lines, 1):
            for check in self.checks:
                if check.pattern.search(line):
                    if self._passes_context_checks(check, line, content, detected_frameworks):
                        self._add_finding(result, i, line, check)

        # Phase 2: Taint analysis (source → sink tracking)
        self._run_taint_analysis(content, lines, result)

        # Phase 3: Cross-line pattern detection
        self._run_cross_line_analysis(content, lines, result)

        return result

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by category and severity."""
        checks = []

        # ====================================================================
        # CATEGORY: SQL INJECTION (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-SQL-001",
                name="SQL Injection via String Interpolation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String interpolation in SQL queries allows injection attacks",
                pattern=re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\$'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use parameterized queries with ? placeholders instead of string interpolation",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="val query = \"SELECT * FROM users WHERE id = ?\"\npreparedStatement.setString(1, userId)",
                attack_vector="User input → String interpolation → SQL query → Database execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-SQL-002",
                name="SQL Injection via String Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in SQL queries allows injection attacks",
                pattern=re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*"\s*\+\s*'),
                context_checks=[],
                suggestion="Use parameterized queries with ? placeholders instead of string concatenation",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="val query = \"SELECT * FROM users WHERE id = ?\"\npreparedStatement.setString(1, userId)",
                attack_vector="User input → String concatenation → SQL query → Database execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-SQL-003",
                name="SQL Injection via Room @Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in Room @Query annotations allows injection",
                pattern=re.compile(r'(?i)@Query\s*\(\s*"[^"]*\+\s*'),
                context_checks=[],
                suggestion="Use Room query parameters with :parameterName syntax",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="@Query(\"SELECT * FROM users WHERE id = :userId\")\nfun getUser(userId: String): User",
                attack_vector="User input → Room @Query concatenation → SQLite execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-SQL-004",
                name="SQL Injection via rawQuery",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="rawQuery with string concatenation allows injection",
                pattern=re.compile(r'(?i)rawQuery\s*\(\s*"[^"]*\+\s*'),
                context_checks=[],
                suggestion="Use rawQuery with selectionArgs parameter",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="db.rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId))",
                attack_vector="User input → rawQuery concatenation → SQLite execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-SQL-005",
                name="Second-Order SQL Injection",
                category="sql-injection",
                severity=RiskLevel.HIGH,
                description="Data stored from user input may be used in SQL queries later without sanitization",
                pattern=re.compile(r'(?i)(INSERT|UPDATE)\s+.*\$\{.*\}|"\s*\+\s*.*request|"\s*\+\s*.*intent'),
                context_checks=[self._is_safe_storage],
                suggestion="Sanitize data before storing. Validate data when retrieving from database",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Sanitize before insert: val safeName = name.replace(\"'\", \"''\")\n// Validate on retrieval: val user = validateUser(db.query(...))",
                attack_vector="Malicious input → Stored in DB → Retrieved → Used in query → Execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-SQL-006",
                name="Blind SQL Injection via Boolean Logic",
                category="sql-injection",
                severity=RiskLevel.HIGH,
                description="SQL queries with user-controlled boolean conditions can allow blind injection",
                pattern=re.compile(r'(?i)WHERE\s+.*=\s*\$\{|WHERE\s+.*"\s*\+\s*'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use parameterized queries. Never use user input in WHERE clauses directly",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="val query = \"SELECT * FROM users WHERE active = ? AND id = ?\"\npreparedStatement.setBoolean(1, isActive)\npreparedStatement.setString(2, userId)",
                attack_vector="User input → WHERE clause → Boolean-based blind extraction",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: COMMAND INJECTION (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-CMD-001",
                name="Command Injection via Runtime.exec",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Runtime.exec() with user input allows command injection",
                pattern=re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
                context_checks=[self._is_safe_command],
                suggestion="Use ProcessBuilder with explicit argument arrays instead of shell strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="val process = ProcessBuilder(\"ls\", \"-la\", userDir)\n    .redirectErrorStream(true)\n    .start()",
                attack_vector="User input → Runtime.exec() → Shell execution → Arbitrary command",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="KT-CMD-002",
                name="Command Injection via ProcessBuilder",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="ProcessBuilder with user-controlled arguments can allow command injection",
                pattern=re.compile(r'ProcessBuilder\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Validate and sanitize all ProcessBuilder arguments",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="val safeArgs = userInput.replace(Regex(\"[;&|`]\"), \"\")\nval pb = ProcessBuilder(\"ls\", safeArgs)",
                attack_vector="User input → ProcessBuilder argument → Command execution",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="KT-CMD-003",
                name="Command Injection via Environment Variables",
                category="command-injection",
                severity=RiskLevel.HIGH,
                description="Environment variables with user input can lead to command injection",
                pattern=re.compile(r'(?i)ProcessBuilder\s*\(\s*\)\.environment\s*\['),
                context_checks=[],
                suggestion="Never set environment variables from user input for executed processes",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Validate env vars:\nval safeValue = userInput.takeIf { it.matches(Regex(\"[a-zA-Z0-9_]+\")) }",
                attack_vector="User input → Environment variable → Process execution → Command injection",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: PATH TRAVERSAL (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-PATH-001",
                name="Path Traversal via File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user input can allow path traversal attacks",
                pattern=re.compile(r'(?i)(File|FileInputStream|FileOutputStream|BufferedReader)\s*\('),
                context_checks=[self._is_safe_file_path],
                suggestion="Validate file paths and use canonical paths to prevent traversal",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="val safeFile = File(baseDir, userInput).canonicalFile\nrequire(safeFile.startsWith(baseDir)) { \"Invalid path\" }",
                attack_vector="User input → File path → ../../etc/passwd → File read",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-PATH-002",
                name="Path Traversal via Null Byte Injection",
                category="path-traversal",
                severity=RiskLevel.HIGH,
                description="Null byte injection in file paths can bypass extension validation",
                pattern=re.compile(r'(?i)(File|FileInputStream)\s*\([^)]*\.txt'),
                context_checks=[self._is_safe_file_path],
                suggestion="Remove null bytes from file paths before processing",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="val cleanPath = userInput.replace(\"\\u0000\", \"\")\nval safeFile = File(baseDir, cleanPath).canonicalFile",
                attack_vector="User input → file.txt%00../../etc/passwd → Null byte truncation → File read",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: XSS (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-XSS-001",
                name="XSS via WebView loadData",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Loading untrusted HTML in WebView can execute JavaScript",
                pattern=re.compile(r'(?i)(webView|WebView)\.(loadData|loadDataWithBaseURL|loadUrl)\s*\('),
                context_checks=[self._is_safe_webview],
                suggestion="Disable JavaScript in WebView or sanitize HTML content before loading",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="webView.settings.javaScriptEnabled = false\nwebView.settings.domStorageEnabled = false\n// OR sanitize HTML before loading",
                attack_vector="User input → WebView HTML → JavaScript execution → Data theft",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="KT-XSS-002",
                name="XSS via addJavascriptInterface",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="WebView addJavascriptInterface exposes native methods to JavaScript",
                pattern=re.compile(r'(?i)addJavascriptInterface\s*\('),
                context_checks=[self._is_safe_js_interface],
                suggestion="Use @JavascriptInterface only on safe methods. Avoid exposing sensitive APIs",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Only expose safe methods:\nclass WebAppInterface {\n    @JavascriptInterface\n    fun showToast(message: String) { ... }\n}",
                attack_vector="WebView → addJavascriptInterface → JavaScript calls native methods → Data access",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="KT-XSS-003",
                name="DOM-based XSS via loadUrl with javascript:",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Loading javascript: URLs in WebView can execute arbitrary code",
                pattern=re.compile(r'(?i)loadUrl\s*\(\s*["\x27]javascript:'),
                context_checks=[],
                suggestion="Never load javascript: URLs with user-controlled content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Instead of loadUrl(\"javascript:...\" + userInput):\nwebView.evaluateJavascript(\"safeFunction()\", null)",
                attack_vector="User input → javascript: URL → Code execution → Data theft",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: CRYPTOGRAPHY (Advanced)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-CRYPTO-001",
                name="Insecure Cryptographic Algorithm",
                category="cryptography",
                severity=RiskLevel.CRITICAL,
                description="MD5 and SHA-1 are cryptographically broken and should not be used for security",
                pattern=re.compile(r'(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"'),
                context_checks=[self._is_non_security_hash],
                suggestion="Use SHA-256 or stronger algorithms for security-sensitive operations",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val digest = MessageDigest.getInstance(\"SHA-256\")\nval hash = digest.digest(data)",
                attack_vector="Weak hash → Collision attack → Data tampering → Authentication bypass",
                mitre_technique="T1573 - Encrypted Channel",
            ),
            SecurityCheck(
                id="KT-CRYPTO-002",
                name="Hardcoded Encryption Key",
                category="cryptography",
                severity=RiskLevel.CRITICAL,
                description="Encryption keys should not be hardcoded in source code",
                pattern=re.compile(r'(?i)(SecretKeySpec|SecretKey|Cipher\.init)\s*\([^)]*"[^"]{16,}"'),
                context_checks=[self._is_test_file],
                suggestion="Use Android KeyStore or a secure key management solution",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val keyStore = KeyStore.getInstance(\"AndroidKeyStore\")\nkeyStore.load(null)\nval key = keyStore.getKey(\"alias\", null)",
                attack_vector="Hardcoded key → Reverse engineering → Key extraction → Data decryption",
                mitre_technique="T1573 - Encrypted Channel",
            ),
            SecurityCheck(
                id="KT-CRYPTO-003",
                name="ECB Mode Encryption",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="ECB mode encryption is insecure - identical plaintext blocks produce identical ciphertext",
                pattern=re.compile(r'(?i)Cipher\.getInstance\s*\(\s*"[^"]*ECB'),
                context_checks=[],
                suggestion="Use CBC, GCM, or CTR mode instead of ECB",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")\nval gcmSpec = GCMParameterSpec(128, iv)\ncipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)",
                attack_vector="ECB mode → Pattern analysis → Plaintext recovery → Data exposure",
                mitre_technique="T1573 - Encrypted Channel",
            ),
            SecurityCheck(
                id="KT-CRYPTO-004",
                name="Static IV/Nonce Usage",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Using a static IV or nonce compromises encryption security",
                pattern=re.compile(r'(?i)(IvParameterSpec|GCMParameterSpec)\s*\([^)]*byteArrayOf'),
                context_checks=[self._is_random_iv],
                suggestion="Generate a random IV/nonce for each encryption operation",
                cwe_id="CWE-329",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val iv = ByteArray(16)\nSecureRandom().nextBytes(iv)\nval gcmSpec = GCMParameterSpec(128, iv)",
                attack_vector="Static IV → Known plaintext attack → Key recovery → Data decryption",
                mitre_technique="T1573 - Encrypted Channel",
            ),
            SecurityCheck(
                id="KT-CRYPTO-005",
                name="Timing Attack Vulnerability",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="String comparison for secrets can leak information via timing attacks",
                pattern=re.compile(r'(?i)(==|!=|equals)\s*\(?\s*\w*(token|password|secret|key|hash)\w*'),
                context_checks=[self._is_constant_time_compare],
                suggestion="Use constant-time comparison for secrets: MessageDigest.isEqual()",
                cwe_id="CWE-208",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val isValid = MessageDigest.isEqual(providedToken.toByteArray(), expectedToken.toByteArray())",
                attack_vector="String comparison → Timing measurement → Character-by-character extraction → Secret recovery",
                mitre_technique="T1573 - Encrypted Channel",
            ),
        ])

        # ====================================================================
        # CATEGORY: AUTHENTICATION & AUTHORIZATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-AUTH-001",
                name="JWT Without Algorithm Validation",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="JWT decode without algorithm validation allows algorithm confusion attacks",
                pattern=re.compile(r'(?i)JWT\.decode\s*\(|JWT\.require\s*\('),
                context_checks=[self._is_jwt_secure],
                suggestion="Always specify algorithm and issuer when decoding JWTs",
                cwe_id="CWE-345",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="val verifier = JWT.require(Algorithm.HMAC256(secret))\n    .withIssuer(\"my-app\")\n    .build()\nval decoded = verifier.verify(token)",
                attack_vector="JWT → Algorithm confusion (HS256→none) → Token forgery → Authentication bypass",
                mitre_technique="T1078 - Valid Accounts",
            ),
            SecurityCheck(
                id="KT-AUTH-002",
                name="OAuth Misconfiguration",
                category="authentication",
                severity=RiskLevel.HIGH,
                description="OAuth implementation without proper state validation is vulnerable to CSRF",
                pattern=re.compile(r'(?i)AuthorizationRequest\.Builder|OAuth2\.authorize'),
                context_checks=[self._is_oauth_secure],
                suggestion="Always include state parameter and validate it on callback",
                cwe_id="CWE-352",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="val state = generateRandomState()\nval request = AuthorizationRequest.Builder()\n    .setState(state)\n    .build()",
                attack_vector="OAuth flow → Missing state → CSRF → Account takeover",
                mitre_technique="T1078 - Valid Accounts",
            ),
            SecurityCheck(
                id="KT-AUTH-003",
                name="Hardcoded Credentials",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="API keys, tokens, or passwords should not be hardcoded in source code",
                pattern=re.compile(r'(?i)(val|var)\s+(api[_-]?key|secret[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key)\s*=\s*"[^"]{8,}"'),
                context_checks=[self._is_test_file],
                suggestion="Use environment variables, BuildConfig, or a secrets manager",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="val apiKey = System.getenv(\"API_KEY\")\n// OR in Android: BuildConfig.API_KEY",
                attack_vector="Hardcoded credentials → Reverse engineering → Credential extraction → Unauthorized access",
                mitre_technique="T1078 - Valid Accounts",
            ),
            SecurityCheck(
                id="KT-AUTH-004",
                name="Missing Rate Limiting",
                category="authentication",
                severity=RiskLevel.MEDIUM,
                description="Authentication endpoints without rate limiting are vulnerable to brute force",
                pattern=re.compile(r'(?i)(login|signin|authenticate|oauth)\s*\('),
                context_checks=[self._has_rate_limiting],
                suggestion="Implement rate limiting for authentication endpoints",
                cwe_id="CWE-307",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="// Use a rate limiter:\nval rateLimiter = RateLimiter.create(5.0) // 5 requests per second\nif (!rateLimiter.tryAcquire()) throw RateLimitExceededException()",
                attack_vector="Login endpoint → No rate limit → Brute force → Account compromise",
                mitre_technique="T1110 - Brute Force",
            ),
        ])

        # ====================================================================
        # CATEGORY: NETWORK & COMMUNICATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-NET-001",
                name="Cleartext Traffic Permitted",
                category="network",
                severity=RiskLevel.HIGH,
                description="Allowing cleartext (HTTP) traffic exposes data to interception",
                pattern=re.compile(r'(?i)usesCleartextTraffic\s*=\s*"true"'),
                context_checks=[],
                suggestion="Disable cleartext traffic and use HTTPS for all network communication",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="<!-- AndroidManifest.xml -->\n<application android:usesCleartextTraffic=\"false\">",
                attack_vector="HTTP traffic → Network sniffing → Data interception → Credential theft",
                mitre_technique="T1040 - Network Sniffing",
            ),
            SecurityCheck(
                id="KT-NET-002",
                name="Missing TLS Certificate Pinning",
                category="network",
                severity=RiskLevel.HIGH,
                description="Without certificate pinning, MITM attacks are possible with compromised CAs",
                pattern=re.compile(r'(?i)(OkHttpClient|HttpsURLConnection|Retrofit\.Builder)\s*\('),
                context_checks=[self._has_certificate_pinning],
                suggestion="Implement certificate pinning for sensitive API connections",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val certificatePinner = CertificatePinner.Builder()\n    .add(\"api.example.com\", \"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\")\n    .build()\nval client = OkHttpClient.Builder()\n    .certificatePinner(certificatePinner)\n    .build()",
                attack_vector="No pinning → Compromised CA → MITM → Data interception",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="KT-NET-003",
                name="Insecure WebSocket Connection",
                category="network",
                severity=RiskLevel.MEDIUM,
                description="Using ws:// instead of wss:// exposes data to interception",
                pattern=re.compile(r'new\s+WebSocket\s*\(\s*["\x27]ws://'),
                context_checks=[],
                suggestion="Use wss:// (WebSocket Secure) for encrypted connections",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val ws = WebSocket.Builder().build(\"wss://example.com/socket\")",
                attack_vector="ws:// → Network sniffing → Data interception → Session hijacking",
                mitre_technique="T1040 - Network Sniffing",
            ),
            SecurityCheck(
                id="KT-NET-004",
                name="SSRF via User-Controlled URL",
                category="network",
                severity=RiskLevel.CRITICAL,
                description="HTTP requests with user-controlled URLs can lead to SSRF",
                pattern=re.compile(r'(?i)(URL|HttpURLConnection|OkHttpClient\.Builder|HttpClient)\s*\([^)]*\$'),
                context_checks=[self._is_safe_url],
                suggestion="Validate URLs against an allowlist before making requests",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="val url = URL(inputUrl)\nrequire(allowedDomains.contains(url.host)) { \"Invalid domain\" }\n// Also block internal IPs:\nrequire(!url.host.matches(Regex(\"10\\..*|192\\.168\\..*|127\\..*\")))",
                attack_vector="User input → URL → Internal network access → Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: DATA STORAGE
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-STORAGE-001",
                name="Sensitive Data in SharedPreferences",
                category="storage",
                severity=RiskLevel.HIGH,
                description="Storing sensitive data in SharedPreferences is insecure - data is stored in plaintext",
                pattern=re.compile(r'(?i)edit\(\)\.put(String|Int|Long|Float|Boolean)\s*\(\s*["\x27](password|token|secret|key|auth|session|jwt|credit|card)'),
                context_checks=[self._is_encrypted_storage],
                suggestion="Use EncryptedSharedPreferences or Android KeyStore for sensitive data",
                cwe_id="CWE-312",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()\nval sharedPreferences = EncryptedSharedPreferences.create(context, \"secret\", masterKey, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)",
                attack_vector="SharedPreferences → Rooted device → File access → Credential theft",
                mitre_technique="T1005 - Data from Local System",
            ),
            SecurityCheck(
                id="KT-STORAGE-002",
                name="Sensitive Data in Logs",
                category="storage",
                severity=RiskLevel.HIGH,
                description="Logging sensitive data exposes it in logcat, accessible to other apps on rooted devices",
                pattern=re.compile(r'(?i)(Log\.[diew]|println|printStackTrace)\s*\([^)]*(password|token|secret|key|auth|credit|card|ssn)'),
                context_checks=[],
                suggestion="Never log sensitive data. Use redaction or remove sensitive fields before logging",
                cwe_id="CWE-532",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="Log.d(\"TAG\", \"User logged in: ${user.id}\") // Safe - no sensitive data",
                attack_vector="Log statement → Logcat access → Data extraction → Credential theft",
                mitre_technique="T1005 - Data from Local System",
            ),
            SecurityCheck(
                id="KT-STORAGE-003",
                name="Sensitive Data in Clipboard",
                category="storage",
                severity=RiskLevel.MEDIUM,
                description="Copying sensitive data to clipboard exposes it to other apps",
                pattern=re.compile(r'(?i)(ClipboardManager|clipboard)\.setPrimaryClip'),
                context_checks=[self._is_safe_clipboard],
                suggestion="Avoid copying sensitive data to clipboard. Use ClipDescription with sensitive flag",
                cwe_id="CWE-312",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val clip = ClipData.newPlainText(\"label\", data)\nclip.description.isSensitiveHint = true\nclipboard.setPrimaryClip(clip)",
                attack_vector="Clipboard → Other app access → Data extraction → Credential theft",
                mitre_technique="T1005 - Data from Local System",
            ),
            SecurityCheck(
                id="KT-STORAGE-004",
                name="Sensitive Data in Intent Extras",
                category="storage",
                severity=RiskLevel.MEDIUM,
                description="Passing sensitive data via Intent extras can expose it to other apps",
                pattern=re.compile(r'(?i)putExtra\s*\(\s*["\x27](password|token|secret|key|auth|session|jwt|credit)'),
                context_checks=[],
                suggestion="Use explicit intents and avoid passing sensitive data between components",
                cwe_id="CWE-312",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Use explicit intent:\nval intent = Intent(this, TargetActivity::class.java)\n// Pass non-sensitive data only, or use secure storage",
                attack_vector="Intent extra → Inter-app communication → Data interception → Credential theft",
                mitre_technique="T1005 - Data from Local System",
            ),
        ])

        # ====================================================================
        # CATEGORY: ANDROID COMPONENTS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-COMP-001",
                name="Exported Activity Without Permission",
                category="components",
                severity=RiskLevel.HIGH,
                description="Exported activities without permissions can be accessed by other apps",
                pattern=re.compile(r'(?i)android:exported\s*=\s*"true"'),
                context_checks=[self._has_permission],
                suggestion="Add permission attributes or set exported=false if not needed",
                cwe_id="CWE-926",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="<activity android:exported=\"true\" android:permission=\"com.example.PERMISSION\" />",
                attack_vector="Exported activity → Malicious app → Intent launch → Unauthorized access",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-COMP-002",
                name="Deep Link Without Validation",
                category="components",
                severity=RiskLevel.HIGH,
                description="Deep links without validation can be exploited for phishing or data theft",
                pattern=re.compile(r'(?i)android:autoVerify\s*=\s*"true"|<data\s+android:scheme'),
                context_checks=[self._has_deep_link_validation],
                suggestion="Validate deep link data before processing. Use app links with verification",
                cwe_id="CWE-926",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="val uri = intent.data\nif (uri?.host != \"expected.example.com\") {\n    throw SecurityException(\"Invalid deep link\")\n}",
                attack_vector="Deep link → Malicious URL → App launch → Data theft",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-COMP-003",
                name="Broadcast Receiver Without Permission",
                category="components",
                severity=RiskLevel.MEDIUM,
                description="Broadcast receivers without permissions can receive intents from malicious apps",
                pattern=re.compile(r'(?i)registerReceiver\s*\('),
                context_checks=[self._has_receiver_permission],
                suggestion="Use LocalBroadcastManager or specify permissions for broadcast receivers",
                cwe_id="CWE-926",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="// Use LocalBroadcastManager:\nLocalBroadcastManager.getInstance(context).registerReceiver(receiver, filter)\n// OR specify permission:\ncontext.registerReceiver(receiver, filter, permission, handler)",
                attack_vector="Broadcast receiver → Malicious app → Intent broadcast → Unauthorized action",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-COMP-004",
                name="Content Provider Without Permission",
                category="components",
                severity=RiskLevel.HIGH,
                description="Content providers without permissions can expose data to other apps",
                pattern=re.compile(r'(?i)android:authorities\s*=\s*"[^"]*"(?!.*android:exported\s*=\s*"false")'),
                context_checks=[self._has_provider_permission],
                suggestion="Set exported=false or add permission attributes to content providers",
                cwe_id="CWE-926",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="<provider android:authorities=\"com.example.provider\"\n    android:exported=\"false\"\n    android:grantUriPermissions=\"true\" />",
                attack_vector="Content provider → Malicious app → Data query → Information disclosure",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: REVERSE ENGINEERING & TAMPERING
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-RE-001",
                name="Missing Root Detection",
                category="reverse-engineering",
                severity=RiskLevel.MEDIUM,
                description="Apps without root detection are vulnerable to tampering on rooted devices",
                pattern=re.compile(r'(?i)(class.*Activity|class.*Application|class.*Fragment)'),
                context_checks=[self._has_root_detection],
                suggestion="Implement root detection to prevent running on compromised devices",
                cwe_id="CWE-354",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if (isDeviceRooted()) {\n    // Show warning or exit\n    Toast.makeText(this, \"Rooted devices not supported\", Toast.LENGTH_LONG).show()\n    finish()\n}",
                attack_vector="Rooted device → System modification → App tampering → Data theft",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-RE-002",
                name="Missing Emulator Detection",
                category="reverse-engineering",
                severity=RiskLevel.MEDIUM,
                description="Apps without emulator detection can be analyzed in emulated environments",
                pattern=re.compile(r'(?i)(class.*Activity|class.*Application|class.*Fragment)'),
                context_checks=[self._has_emulator_detection],
                suggestion="Implement emulator detection to prevent analysis in emulated environments",
                cwe_id="CWE-354",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if (isEmulator()) {\n    // Show warning or exit\n    finish()\n}",
                attack_vector="Emulator → Dynamic analysis → Code inspection → Vulnerability discovery",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-RE-003",
                name="Missing Integrity Checks",
                category="reverse-engineering",
                severity=RiskLevel.HIGH,
                description="Apps without integrity checks can be tampered with and repackaged",
                pattern=re.compile(r'(?i)(class.*Activity|class.*Application|class.*Fragment)'),
                context_checks=[self._has_integrity_checks],
                suggestion="Implement integrity checks using Play Integrity API or SafetyNet",
                cwe_id="CWE-354",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="val integrityManager = IntegrityManagerFactory.create(context)\nval request = IntegrityManager.createIntegrityTokenRequest(IntegrityRequestNonce.Builder().build())\nintegrityManager.requestIntegrityToken(request)",
                attack_vector="App repackaging → Malicious code injection → Data theft → Fraud",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-RE-004",
                name="Debuggable Build in Production",
                category="reverse-engineering",
                severity=RiskLevel.HIGH,
                description="Debuggable builds allow runtime inspection and modification",
                pattern=re.compile(r'(?i)android:debuggable\s*=\s*"true"'),
                context_checks=[],
                suggestion="Set debuggable=false for production builds",
                cwe_id="CWE-354",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="<!-- AndroidManifest.xml -->\n<application android:debuggable=\"false\">",
                attack_vector="Debuggable app → Runtime inspection → Code modification → Data theft",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: CONCURRENCY & RACE CONDITIONS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-CONC-001",
                name="Race Condition via Shared Mutable State",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Shared mutable state without synchronization can cause race conditions",
                pattern=re.compile(r'(?i)(var|val)\s+\w+\s*=\s*(mutableListOf|mutableMapOf|mutableSetOf)'),
                context_checks=[self._has_concurrency_protection],
                suggestion="Use thread-safe collections or synchronize access to mutable state",
                cwe_id="CWE-362",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Use thread-safe alternatives:\nval list = CopyOnWriteArrayList<String>()\n// OR synchronize access:\nsynchronized(sharedList) { sharedList.add(item) }",
                attack_vector="Race condition → Data corruption → Security bypass → Unauthorized access",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-CONC-002",
                name="GlobalScope Coroutine Leak",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="GlobalScope.launch can cause memory leaks and uncontrolled concurrency",
                pattern=re.compile(r'(?i)GlobalScope\.launch'),
                context_checks=[],
                suggestion="Use lifecycle-aware scopes (lifecycleScope, viewModelScope) instead of GlobalScope",
                cwe_id="CWE-404",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="lifecycleScope.launch { /* Work tied to lifecycle */ }",
                attack_vector="Coroutine leak → Resource exhaustion → DoS → Service disruption",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: INPUT VALIDATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-VALID-001",
                name="Missing Input Validation",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="Controller/handler functions without input validation can accept malicious data",
                pattern=re.compile(r'(?i)@(Get|Post|Put|Delete|Patch)Mapping\s*\('),
                context_checks=[self._has_validation],
                suggestion="Add @Valid annotation and validation constraints to request parameters",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="@PostMapping\nfun createUser(@Valid @RequestBody user: UserDto): ResponseEntity<*> { ... }",
                attack_vector="User input → No validation → Malicious data → Injection attack",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="KT-VALID-002",
                name="Missing Input Sanitization",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="User input without sanitization can lead to injection attacks",
                pattern=re.compile(r'(?i)(intent\.getStringExtra|intent\.getIntExtra|bundle\.get)'),
                context_checks=[self._has_sanitization],
                suggestion="Sanitize all user input before processing",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="val rawInput = intent.getStringExtra(\"key\")\nval sanitized = rawInput?.replace(Regex(\"[<>\\\"']\"), \"\")",
                attack_vector="User input → No sanitization → Injection attack → Data theft",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: WEAK RANDOM
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-RANDOM-001",
                name="Weak Random Number Generation",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="java.util.Random is not cryptographically secure",
                pattern=re.compile(r'(?i)(java\.util\.Random|Random\(\))'),
                context_checks=[self._is_safe_random],
                suggestion="Use SecureRandom for security-sensitive operations",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="val secureRandom = SecureRandom()\nval token = ByteArray(32).also { secureRandom.nextBytes(it) }",
                attack_vector="Weak random → Predictable tokens → Session hijacking → Account takeover",
                mitre_technique="T1573 - Encrypted Channel",
            ),
        ])

        # ====================================================================
        # CATEGORY: DESERIALIZATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-DESER-001",
                name="Insecure Deserialization",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="Deserializing untrusted data can lead to remote code execution",
                pattern=re.compile(r'(?i)(ObjectInputStream|readObject|Gson\(\)\.fromJson|kotlinx\.serialization)'),
                context_checks=[self._is_safe_deserialization],
                suggestion="Validate input before deserialization. Use type-safe serializers",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Use kotlinx.serialization with explicit types\nval obj = Json.decodeFromString<DataClass>(jsonString)",
                attack_vector="Untrusted data → Deserialization → Code execution → System compromise",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: DEPRECATED & UNSAFE APIS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-DEPR-001",
                name="Deprecated API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated APIs can lead to security and compatibility issues",
                pattern=re.compile(r'(?i)(AsyncTask|HttpClient\s*\(\)|DefaultHttpClient)'),
                context_checks=[],
                suggestion="Use modern alternatives: Coroutines, OkHttp, or HttpUrlConnection",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Instead of AsyncTask:\nlifecycleScope.launch { val result = withContext(Dispatchers.IO) { ... } }",
                attack_vector="Deprecated API → Known vulnerabilities → Exploitation → Data theft",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: NULL SAFETY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-NULL-001",
                name="Unsafe Null Assertion",
                category="null-safety",
                severity=RiskLevel.MEDIUM,
                description="Using !! operator can cause NullPointerException crashes",
                pattern=re.compile(r'!!\s*[.\[\)]'),
                context_checks=[self._is_safe_null_assertion],
                suggestion="Use safe calls (?.) or elvis operator (?:) instead of !!",
                cwe_id="CWE-476",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="val length = text?.length ?: 0 // Safe null handling",
                attack_vector="Null assertion → Crash → DoS → Service disruption",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: LATEINIT
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-LATE-001",
                name="Unsafe Lateinit Usage",
                category="initialization",
                severity=RiskLevel.MEDIUM,
                description="lateinit var without guaranteed initialization can cause UninitializedPropertyAccessException",
                pattern=re.compile(r'(?i)lateinit\s+var'),
                context_checks=[self._is_safe_lateinit],
                suggestion="Ensure lateinit properties are initialized before use, or use nullable types",
                cwe_id="CWE-665",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="private var _service: Service? = null\nprivate val service: Service get() = _service ?: error(\"Not initialized\")",
                attack_vector="Lateinit → Uninitialized access → Crash → DoS",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: DEBUG & LOGGING
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-DEBUG-001",
                name="Debug Statement",
                category="debug",
                severity=RiskLevel.MEDIUM,
                description="Debugger statements should not be in production code",
                pattern=re.compile(r'\bdebugger\s*;?'),
                context_checks=[self._is_test_file],
                suggestion="Remove debugger statements before deploying to production",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="// Remove debugger; statement",
                attack_vector="Debug statement → Runtime inspection → Code analysis → Vulnerability discovery",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: DOCUMENTATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-DOC-001",
                name="Missing KDoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Public functions and classes should have KDoc documentation",
                pattern=re.compile(r'(?i)(public\s+)?(fun|class|object|interface)\s+\w+'),
                context_checks=[self._has_kdoc],
                suggestion="Add KDoc comments to document the purpose and usage",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/**\n * Description of the function\n * @param param Description\n * @return Description\n */",
                attack_vector="Missing docs → Poor code review → Security issues missed → Vulnerabilities",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: CODE QUALITY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="KT-MAGIC-001",
                name="Magic Number",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numbers should be defined as named constants",
                pattern=re.compile(r'(?i)(if|while|for|return|==|!=|>|<|>=|<=)\s*[^;]*\b\d{2,}\b'),
                context_checks=[self._is_acceptable_magic_number],
                suggestion="Define magic numbers as named constants with descriptive names",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const val MAX_RETRIES = 3\nif (retries >= MAX_RETRIES) { ... }",
                attack_vector="Magic numbers → Hard to audit → Security issues missed → Vulnerabilities",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="KT-IMPORT-001",
                name="Unused Import",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Unused imports clutter code and can cause confusion",
                pattern=re.compile(r'^import\s+[\w.]+'),
                context_checks=[self._is_used_import],
                suggestion="Remove unused imports to keep code clean",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove unused import lines",
                attack_vector="Unused imports → Code clutter → Security issues missed → Vulnerabilities",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        return checks

    # ====================================================================
    # FRAMEWORK DETECTION
    # ====================================================================

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect which frameworks are used in the codebase."""
        frameworks = []

        if re.search(r'import\s+android\.', content):
            frameworks.append('android')

        if re.search(r'import\s+org\.springframework\.|@SpringBootApplication|@RestController', content):
            frameworks.append('spring')

        if re.search(r'import\s+io\.ktor\.|Ktor|embeddedServer', content):
            frameworks.append('ktor')

        if re.search(r'import\s+androidx\.compose\.|@Composable', content):
            frameworks.append('compose')

        if re.search(r'import\s+retrofit2\.|@Retrofit|@GET|@POST', content):
            frameworks.append('retrofit')

        if re.search(r'import\s+org\.jetbrains\.exposed\.|Exposed', content):
            frameworks.append('exposed')

        if re.search(r'import\s+androidx\.room\.|@Entity|@Dao|@Database', content):
            frameworks.append('room')

        if re.search(r'import\s+com\.google\.firebase\.|Firebase', content):
            frameworks.append('firebase')

        if re.search(r'import\s+kotlinx\.coroutines\.|launch|async|withContext', content):
            frameworks.append('coroutines')

        self._framework_cache[file_path.name] = frameworks
        return frameworks

    # ====================================================================
    # CONTEXT CHECKS (False Positive Filters)
    # ====================================================================

    def _passes_context_checks(self, check: SecurityCheck, line: str, content: str, frameworks: List[str]) -> bool:
        """Run all context checks for a security check. Returns True if all pass (not a false positive)."""
        for context_check in check.context_checks:
            if context_check(line, content, frameworks):
                return False
        return True

    def _add_finding(self, result: AnalysisResult, line_num: int, line: str, check: SecurityCheck) -> None:
        """Add a finding to results with full metadata."""
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
    # TAINT ANALYSIS (Source → Sink Tracking)
    # ====================================================================

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Run basic taint analysis to track data flow from sources to sinks."""
        # Define taint sources
        sources = {
            'intent.getStringExtra': 'Intent Extra',
            'intent.getIntExtra': 'Intent Extra',
            'bundle.get': 'Bundle',
            'request.getParameter': 'HTTP Parameter',
            'request.getHeader': 'HTTP Header',
            'request.getQueryString': 'Query String',
            'System.getenv': 'Environment Variable',
            'File.readText': 'File Input',
            'BufferedReader.readLine': 'File Input',
        }

        # Define taint sinks
        sinks = {
            'rawQuery': 'SQL Query',
            'exec': 'SQL Execution',
            'execute': 'SQL Execution',
            'Runtime.getRuntime().exec': 'Command Execution',
            'ProcessBuilder': 'Command Execution',
            'loadUrl': 'WebView Load',
            'loadData': 'WebView Load',
            'loadDataWithBaseURL': 'WebView Load',
            'File(': 'File Operation',
            'FileInputStream': 'File Operation',
            'FileOutputStream': 'File Operation',
            'URL(': 'HTTP Request',
            'HttpURLConnection': 'HTTP Request',
            'OkHttpClient': 'HTTP Request',
        }

        # Track taint propagation
        tainted_vars: Dict[str, str] = {}

        for i, line in enumerate(lines, 1):
            # Check for sources
            for source, source_type in sources.items():
                if source in line:
                    # Extract variable assignment
                    match = re.search(r'val\s+(\w+)\s*=\s*.*' + re.escape(source), line)
                    if match:
                        var_name = match.group(1)
                        tainted_vars[var_name] = source_type

            # Check for sinks with tainted data
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
            issue_type="TAINT-FLOW",
            message=f"[Taint Flow] Data from {source_type} reaches {sink_type} without sanitization",
            risk_level=RiskLevel.HIGH,
            code_snippet=line.strip(),
            suggestion="Sanitize data between source and sink. Use parameterized queries, escape output, or validate input",
        )
        result.findings.append(finding)

    # ====================================================================
    # CROSS-LINE ANALYSIS
    # ====================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Run cross-line pattern detection for complex vulnerabilities."""
        # Check for SQL injection patterns spanning multiple lines
        self._check_multiline_sql(content, lines, result)

        # Check for missing null checks before dangerous operations
        self._check_null_safety(content, lines, result)

        # Check for missing error handling around sensitive operations
        self._check_error_handling(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection patterns spanning multiple lines."""
        sql_pattern = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+')
        concat_pattern = re.compile(r'\+\s*\w+|\w+\s*\+')

        for i, line in enumerate(lines):
            if sql_pattern.search(line):
                # Check next few lines for concatenation
                for j in range(i, min(i + 5, len(lines))):
                    if concat_pattern.search(lines[j]) and '$' not in lines[j]:
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="KT-SQL-007",
                            name="Multi-line SQL Injection",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries instead of string concatenation",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="val query = \"SELECT * FROM users WHERE id = ?\"\npreparedStatement.setString(1, userId)",
                            attack_vector="Multi-line SQL → Concatenation → Injection → Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_null_safety(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for missing null checks before dangerous operations."""
        for i, line in enumerate(lines, 1):
            if '!!' in line and 'isInitialized' not in content:
                # Check if there's a null check nearby
                has_check = False
                for j in range(max(0, i - 5), min(len(lines), i + 5)):
                    if '!= null' in lines[j] or '?.let' in lines[j] or '?: return' in lines[j]:
                        has_check = True
                        break
                if not has_check:
                    self._add_finding(result, i, line, SecurityCheck(
                        id="KT-NULL-002",
                        name="Missing Null Check Before Operation",
                        category="null-safety",
                        severity=RiskLevel.MEDIUM,
                        description="Operation performed without null check can cause crashes",
                        pattern=re.compile(r''),
                        suggestion="Add null check before performing operation",
                        cwe_id="CWE-476",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        remediation_example="val result = data?.let { process(it) } ?: return",
                        attack_vector="Null value → Crash → DoS → Service disruption",
                        mitre_technique="T1083 - File and Directory Discovery",
                    ))

    def _check_error_handling(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for missing error handling around sensitive operations."""
        sensitive_ops = ['File(', 'URL(', 'HttpURLConnection', 'OkHttpClient', 'rawQuery', 'exec']

        for i, line in enumerate(lines, 1):
            for op in sensitive_ops:
                if op in line and 'try' not in line and 'runCatching' not in line:
                    # Check if there's error handling nearby
                    has_handling = False
                    for j in range(max(0, i - 3), min(len(lines), i + 3)):
                        if 'try' in lines[j] or 'runCatching' in lines[j] or 'catch' in lines[j]:
                            has_handling = True
                            break
                    if not has_handling:
                        self._add_finding(result, i, line, SecurityCheck(
                            id="KT-ERR-002",
                            name="Missing Error Handling for Sensitive Operation",
                            category="error-handling",
                            severity=RiskLevel.MEDIUM,
                            description=f"Sensitive operation {op} without error handling can cause crashes",
                            pattern=re.compile(r''),
                            suggestion="Wrap sensitive operations in try-catch or use runCatching",
                            cwe_id="CWE-391",
                            owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                            remediation_example="runCatching {\n    // sensitive operation\n}.onFailure { error ->\n    Log.e(\"TAG\", \"Operation failed\", error)\n}",
                            attack_vector="No error handling → Crash → DoS → Service disruption",
                            mitre_technique="T1083 - File and Directory Discovery",
                        ))
                        break

    # ====================================================================
    # INDIVIDUAL CONTEXT CHECKS
    # ====================================================================

    def _is_parameterized_query(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if query is parameterized."""
        if '?' in line and ('setString' in line or 'setInt' in line or 'setLong' in line):
            return True
        if 'prepareStatement' in line:
            return True
        if ':userId' in line or ':id' in line or ':name' in line:
            return True
        return False

    def _is_safe_command(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if command execution is safe."""
        if re.search(r'exec\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'ProcessBuilder' in line:
            return True
        return False

    def _is_safe_file_path(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if file path is safe."""
        if re.search(r'File\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'canonicalFile' in line or 'canonicalPath' in line:
            return True
        if 'startsWith(baseDir)' in content:
            return True
        return False

    def _is_safe_url(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if URL is safe."""
        if re.search(r'URL\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'allowedDomains' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_safe_webview(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if WebView usage is safe."""
        if 'javaScriptEnabled = false' in line or 'setJavaScriptEnabled(false)' in line:
            return True
        if 'loadUrl("https://' in line:
            return True
        if 'DOMPurify' in content or 'sanitize' in content:
            return True
        return False

    def _is_safe_js_interface(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JS interface is safe."""
        if '@JavascriptInterface' in content:
            return True
        return False

    def _is_non_security_hash(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if hash is used for non-security purposes."""
        if 'checksum' in line.lower() or 'hashcode' in line.lower() or 'equals' in line.lower():
            return True
        return False

    def _is_safe_random(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if random usage is safe."""
        if 'SecureRandom' in line:
            return True
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower():
            return True
        return False

    def _is_safe_deserialization(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if deserialization is safe."""
        if 'kotlinx.serialization' in content or 'Json.decodeFromString' in line:
            return True
        if 'TypeToken' in line:
            return True
        return False

    def _is_test_file(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if this is a test file."""
        if 'test' in line.lower() or 'Test' in line or '@Test' in content:
            return True
        return False

    def _is_jwt_secure(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JWT usage is secure."""
        if 'Algorithm.HMAC256' in content or 'Algorithm.RSA256' in content:
            return True
        if 'withIssuer' in content:
            return True
        return False

    def _is_oauth_secure(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if OAuth is secure."""
        if 'setState' in content or 'state' in line.lower():
            return True
        return False

    def _has_rate_limiting(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if rate limiting is present."""
        if 'RateLimiter' in content or 'rateLimit' in content.lower():
            return True
        return False

    def _has_certificate_pinning(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if certificate pinning is implemented."""
        if 'CertificatePinner' in content or 'certificatePinner' in content:
            return True
        return False

    def _is_encrypted_storage(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if encrypted storage is used."""
        if 'EncryptedSharedPreferences' in content or 'MasterKey' in content:
            return True
        return False

    def _is_safe_clipboard(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if clipboard usage is safe."""
        if 'isSensitiveHint' in content or 'ClipDescription' in content:
            return True
        return False

    def _has_permission(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if component has permission."""
        if 'permission' in line.lower():
            return True
        return False

    def _has_deep_link_validation(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if deep link validation is present."""
        if 'uri?.host' in content or 'validate' in content.lower():
            return True
        return False

    def _has_receiver_permission(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if broadcast receiver has permission."""
        if 'LocalBroadcastManager' in content or 'permission' in line.lower():
            return True
        return False

    def _has_provider_permission(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if content provider has permission."""
        if 'exported="false"' in content or 'permission' in line.lower():
            return True
        return False

    def _has_root_detection(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if root detection is implemented."""
        if 'isDeviceRooted' in content or 'root' in content.lower():
            return True
        return False

    def _has_emulator_detection(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if emulator detection is implemented."""
        if 'isEmulator' in content or 'emulator' in content.lower():
            return True
        return False

    def _has_integrity_checks(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if integrity checks are implemented."""
        if 'IntegrityManager' in content or 'SafetyNet' in content:
            return True
        return False

    def _has_concurrency_protection(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if concurrency protection is present."""
        if 'synchronized' in content or 'Mutex' in content or 'CopyOnWriteArrayList' in content:
            return True
        return False

    def _has_validation(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if validation is present."""
        if '@Valid' in content or '@NotNull' in content or '@NotBlank' in content:
            return True
        if 'require(' in content or 'check(' in content:
            return True
        return False

    def _has_sanitization(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if sanitization is present."""
        if 'sanitize' in content.lower() or 'escape' in content.lower() or 'replace' in content.lower():
            return True
        return False

    def _is_safe_null_assertion(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if null assertion is safe."""
        if 'requireNotNull' in line or 'checkNotNull' in line:
            return True
        return False

    def _is_safe_lateinit(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if lateinit usage is safe."""
        if 'isInitialized' in content:
            return True
        return False

    def _is_constant_time_compare(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if constant-time comparison is used."""
        if 'MessageDigest.isEqual' in content:
            return True
        return False

    def _is_random_iv(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if IV is randomly generated."""
        if 'SecureRandom' in line or 'random' in line.lower():
            return True
        return False

    def _is_safe_storage(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if storage is safe."""
        if 'sanitize' in content.lower() or 'validate' in content.lower():
            return True
        return False

    def _has_kdoc(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if the function/class has KDoc."""
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            if idx > 0:
                prev = lines[idx - 1].strip()
                if prev.endswith('*/') or prev.startswith('*'):
                    return True
        except ValueError:
            pass
        return False

    def _is_acceptable_magic_number(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if magic number is acceptable."""
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const val' in line or 'val' in line:
            return True
        return False

    def _is_used_import(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if import is used."""
        import_match = re.search(r'import\s+([\w.]+)', line)
        if import_match:
            import_path = import_match.group(1)
            class_name = import_path.split('.')[-1]
            if class_name in content:
                return True
        return False
