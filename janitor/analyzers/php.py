"""Elite static analyzer for PHP code with comprehensive security checks."""

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
    """A 'security unit test' for PHP code."""
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


class PHPAnalyzer(BaseAnalyzer):
    """Elite static analyzer for PHP code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "php"

    def get_supported_extensions(self) -> List[str]:
        return [".php", ".phtml", ".php3", ".php4", ".php5"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a PHP file and return results."""
        result = AnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        self._current_path = file_path
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

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by severity."""
        checks = []

        # ====================================================================
        # CRITICAL CHECKS
        # ====================================================================

        checks.extend([
            # PHP-SQL-001: mysqli/PDO concat
            SecurityCheck(
                id="PHP-SQL-001",
                name="SQL Injection via String Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in SQL queries allows SQL injection",
                pattern=re.compile(r'(?i)(mysql_query|mysqli_query|mysqli_prepare|PDO::query|PDO::prepare|PDO->query|PDO->exec|db->query)\s*\([^)]*["\x27][^"\x27]*["\x27]\s*\.'),
                context_checks=[],
                suggestion="Use prepared statements with named placeholders (:param) or ? placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);",
                attack_vector="User input -> SQL string concat -> SQLi -> Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-SQL-002: Variable interpolation
            SecurityCheck(
                id="PHP-SQL-002",
                name="SQL Injection via Variable Interpolation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Variable interpolation in SQL queries enables SQL injection",
                pattern=re.compile(r'(?i)(mysql_query|mysqli_query|mysqli_prepare|PDO::query|PDO::exec|PDO->query|PDO->exec|db->query)\s*\(\s*["\x27][^"\x27]*\$'),
                context_checks=[],
                suggestion="Use prepared statements instead of variable interpolation in SQL strings",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);",
                attack_vector="User input -> Variable in SQL string -> SQLi -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-SQL-003: Laravel DB::raw concat
            SecurityCheck(
                id="PHP-SQL-003",
                name="SQL Injection via Laravel DB::raw",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Laravel DB::raw with concatenated user input allows SQL injection",
                pattern=re.compile(r'(?i)DB::raw\s*\(|DB::select\s*\(|\\DB::raw\s*\(|\\DB::select\s*\('),
                context_checks=[self._is_laravel_sql_safe],
                suggestion="Use Eloquent ORM with parameterized where clauses or Query Builder with bindings",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="$users = DB::select('SELECT * FROM users WHERE id = ?', [$userId]);\n// OR: User::where('id', $userId)->get();",
                attack_vector="User input -> DB::raw -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-SQL-004: WordPress $wpdb
            SecurityCheck(
                id="PHP-SQL-004",
                name="SQL Injection via WordPress $wpdb",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="$wpdb->query/get_results with string concatenation allows SQL injection",
                pattern=re.compile(r'(?i)\$wpdb->(query|get_results|get_var|get_row|prepare|insert|update|delete|replace)\s*\([^)]*\$'),
                context_checks=[self._is_wpdb_safe],
                suggestion="Use $wpdb->prepare() with %d, %s placeholders for all queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="$results = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM {$wpdb->prefix}users WHERE id = %d\", $userId));",
                attack_vector="User input -> $wpdb query -> SQLi -> WordPress compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-CMD-001: exec/system/passthru
            SecurityCheck(
                id="PHP-CMD-001",
                name="Command Injection via Shell Function",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="exec/system/passthru/shell_exec with user input allows command injection",
                pattern=re.compile(r'(?i)\b(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*\$'),
                context_checks=[self._is_cmd_safe],
                suggestion="Use escapeshellarg() or escapeshellcmd(). Better: avoid shell functions entirely",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="exec('ls ' . escapeshellarg($userDir), $output, $ret);\n// Or use Symfony Process component",
                attack_vector="User input -> exec() -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PHP-CMD-002: backtick operator
            SecurityCheck(
                id="PHP-CMD-002",
                name="Command Injection via Backtick Operator",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Backtick (`) shell execution with user input allows command injection",
                pattern=re.compile(r'`[^`]*\$'),
                context_checks=[self._is_cmd_safe],
                suggestion="Use escapeshellarg() on variables within backticks or avoid shell execution",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="$safeInput = escapeshellarg($userInput);\n$output = `ls -la $safeInput`;",
                attack_vector="User input in backticks -> Shell exec -> RCE / Data exposure",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # PHP-EVAL-001: eval injection
            SecurityCheck(
                id="PHP-EVAL-001",
                name="Code Injection via eval()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="eval() with user input allows arbitrary PHP code execution",
                pattern=re.compile(r'(?i)\beval\s*\(\s*\$'),
                context_checks=[],
                suggestion="Never use eval(). Use safer alternatives like call_user_func or dynamic dispatch",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Instead of eval:\n$result = json_decode($jsonString, true);\n// Or use a switch/case for limited options",
                attack_vector="User input -> eval() -> Arbitrary PHP execution -> Full compromise",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PHP-EVAL-002: assert injection
            SecurityCheck(
                id="PHP-EVAL-002",
                name="Code Injection via assert()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="assert() with user input in PHP 7.x allows code execution",
                pattern=re.compile(r'(?i)\bassert\s*\(\s*\$'),
                context_checks=[],
                suggestion="Avoid assert(). In PHP 8, assert() no longer evaluates strings",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="// assert() is dangerous in PHP 7.x:\n// Remove assert calls or upgrade to PHP 8+",
                attack_vector="User input -> assert() -> Code execution -> Application compromise",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PHP-EVAL-003: preg_replace /e modifier
            SecurityCheck(
                id="PHP-EVAL-003",
                name="Code Injection via preg_replace /e Modifier",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="preg_replace with /e modifier evaluates replacement as PHP code",
                pattern=re.compile(r'(?i)preg_replace\s*\([^)]*[\x27"\s]+\/e[\x27"\s)]'),
                context_checks=[],
                suggestion="Use preg_replace_callback() instead of /e modifier",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="$result = preg_replace_callback('/pattern/', function($matches) { return strtoupper($matches[0]); }, $subject);",
                attack_vector="User input via /e modifier -> preg_replace evaluation -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PHP-DESER-001: unserialize
            SecurityCheck(
                id="PHP-DESER-001",
                name="Insecure Deserialization via unserialize()",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="unserialize() with user input enables remote code execution via gadget chains",
                pattern=re.compile(r'(?i)\bunserialize\s*\(\s*\$'),
                context_checks=[self._is_deser_safe],
                suggestion="Use json_decode(). If unserialize is needed, use allowed_classes option",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="$data = json_decode($jsonString, true);\n// OR: unserialize($data, ['allowed_classes' => [MyClass::class]]);",
                attack_vector="Serialized payload -> unserialize -> Gadget chain -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PHP-INCLUDE-001: File inclusion
            SecurityCheck(
                id="PHP-INCLUDE-001",
                name="Local/Remote File Inclusion via include",
                category="file-inclusion",
                severity=RiskLevel.CRITICAL,
                description="include/require with user input allows arbitrary file inclusion (LFI/RFI)",
                pattern=re.compile(r'(?i)\b(include|include_once|require|require_once)\s*\(\s*\$'),
                context_checks=[self._is_include_safe],
                suggestion="Use an allowlist mapping for included files. Never include user-supplied paths",
                cwe_id="CWE-98",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="$pages = ['home' => 'home.php', 'about' => 'about.php'];\ninclude $pages[$input] ?? '404.php';",
                attack_vector="User input -> include() -> LFI/RFI -> Code execution / File read",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-PATH-001: File path traversal
            SecurityCheck(
                id="PHP-PATH-001",
                name="Path Traversal via File Functions",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user-controlled path allow directory traversal",
                pattern=re.compile(r'(?i)\b(fopen|file_get_contents|file_put_contents|readfile|copy|unlink|rename|move_uploaded_file|chmod|chown|file|fwrite|fputs|fread)\s*\(\s*\$'),
                context_checks=[self._is_path_safe],
                suggestion="Use realpath() and verify path prefix against a base directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="$safePath = realpath($baseDir . '/' . basename($userInput));\nif (strpos($safePath, $baseDir) !== 0) { die('Invalid path'); }",
                attack_vector="User input -> File path + ../ -> Arbitrary file access -> Data breach",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # PHP-SSRF-001: file_get_contents SSRF
            SecurityCheck(
                id="PHP-SSRF-001",
                name="Server-Side Request Forgery via file_get_contents",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="file_get_contents with user-controlled URL can target internal services",
                pattern=re.compile(r'(?i)\b(file_get_contents|fopen|readfile)\s*\(\s*\$'),
                context_checks=[self._is_url_safe],
                suggestion="Parse URL and validate hostname against an allowlist before fetching",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="$url = parse_url($userInput);\nif (!in_array($url['host'], $allowedDomains)) { die('Forbidden'); }\n$content = file_get_contents($userInput);",
                attack_vector="User input -> file_get_contents -> Internal network scan -> Data exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # PHP-SSRF-002: curl_exec SSRF
            SecurityCheck(
                id="PHP-SSRF-002",
                name="Server-Side Request Forgery via cURL",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="curl_exec with user-controlled URL in CURLOPT_URL allows SSRF",
                pattern=re.compile(r'(?i)curl_setopt.*CURLOPT_URL.*\$|curl_exec\s*\('),
                context_checks=[self._is_curl_safe],
                suggestion="Validate URL hostname against an allowlist before cURL execution",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="$ch = curl_init();\n$url = parse_url($userInput);\nif (!in_array($url['host'], $allowedDomains)) { die('Forbidden'); }\ncurl_setopt($ch, CURLOPT_URL, $userInput);\n$result = curl_exec($ch);",
                attack_vector="User input -> cURL -> Internal resource access -> Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # PHP-SECRET-001: Hardcoded credential
            SecurityCheck(
                id="PHP-SECRET-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="API keys, passwords, or tokens hardcoded in PHP source code",
                pattern=re.compile(r'(?i)(\$api[_-]?key|\$secret[_-]?key|\$password|\$passwd|\$pwd|\$token|\$auth[_-]?token|\$access[_-]?key|\$jwt[_-]?secret)\s*=\s*["\x27][^"\x27]{8,}["\x27]'),
                context_checks=[self._is_secret_fp],
                suggestion="Use .env files and getenv() or $_ENV for configuration",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="$apiKey = getenv('API_KEY');\n// OR: $apiKey = $_ENV['API_KEY'];",
                attack_vector="Source code leak -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # PHP-XXE-001: XXE
            SecurityCheck(
                id="PHP-XXE-001",
                name="XML External Entity (XXE)",
                category="xxe",
                severity=RiskLevel.CRITICAL,
                description="XML parsers without XXE protection allow file reading and SSRF",
                pattern=re.compile(r'(?i)\b(simplexml_load_string|simplexml_load_file|XMLReader|DOMDocument->loadXML|DOMDocument->load)\s*\('),
                context_checks=[self._is_xxe_safe],
                suggestion="Disable external entity loading with libxml_disable_entity_loader(true)",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="libxml_disable_entity_loader(true);\n$dom = new DOMDocument();\n$dom->loadXML($xmlString, LIBXML_NOENT);",
                attack_vector="XML with external entity -> XXE -> File read / SSRF -> Data breach",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # PHP-XSS-001: echo/print
            SecurityCheck(
                id="PHP-XSS-001",
                name="Reflected XSS via echo/print",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Outputting user input directly without HTML encoding enables XSS",
                pattern=re.compile(r'(?i)\b(echo|print|printf|sprintf)\s*\(\s*\$'),
                context_checks=[self._is_xss_safe],
                suggestion="Use htmlspecialchars() or htmlentities() when outputting user data",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');\n// In Blade: {{ $userInput }} auto-escapes",
                attack_vector="User input -> echo/print -> XSS -> Session theft / Phishing",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PHP-XSS-002: Blade unescaped
            SecurityCheck(
                id="PHP-XSS-002",
                name="XSS via Blade Unescaped Output",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Blade {!! !!} syntax outputs raw HTML, enabling XSS from user data",
                pattern=re.compile(r'\{!!\s*\$'),
                context_checks=[self._is_xss_safe],
                suggestion="Use {{ }} syntax which auto-escapes. Only use {!! !!} with trusted content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="{{ $userInput }} // Auto-escaped\n// Never: {!! $userInput !!}",
                attack_vector="User input -> Blade {!! !!} -> XSS -> Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PHP-CRYPTO-001: Weak hash
            SecurityCheck(
                id="PHP-CRYPTO-001",
                name="Weak Cryptographic Hash (md5/sha1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="md5() and sha1() are broken and vulnerable to collision attacks",
                pattern=re.compile(r'(?i)\b(md5|sha1)\s*\('),
                context_checks=[self._is_crypto_fp],
                suggestion="Use password_hash() for passwords and hash('sha256') for other hashing",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="$hash = password_hash($password, PASSWORD_BCRYPT);\n// Verify: password_verify($password, $hash);",
                attack_vector="Collision on md5/sha1 -> Signature forgery / Auth bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PHP-CRYPTO-002: Weak cipher
            SecurityCheck(
                id="PHP-CRYPTO-002",
                name="Weak Encryption (mcrypt/ecb)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="mcrypt and ECB mode encryption are cryptographically weak",
                pattern=re.compile(r'(?i)\b(mcrypt_decrypt|mcrypt_encrypt|mcrypt_module_open|MCRYPT_RIJNDAEL|MCRYPT_3DES|MCRYPT_BLOWFISH|MCRYPT_DES)\b'),
                context_checks=[],
                suggestion="Use openssl_encrypt with AES-256-GCM or sodium_crypto_aead",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="$encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);\n// Or use libsodium: sodium_crypto_secretbox($data, $nonce, $key);",
                attack_vector="Weak cipher -> Cryptoanalysis -> Data decryption",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PHP-RANDOM-001: Weak random
            SecurityCheck(
                id="PHP-RANDOM-001",
                name="Weak Random Number Generator (rand/mt_rand)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="rand() and mt_rand() are predictable, not cryptographically secure",
                pattern=re.compile(r'(?i)\b(rand|mt_rand)\s*\('),
                context_checks=[self._is_random_fp],
                suggestion="Use random_int() or random_bytes() for security-sensitive operations",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="$token = bin2hex(random_bytes(32));\n$value = random_int(1, 100);",
                attack_vector="Predictable random -> Token forgery -> Auth bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # PHP-UPLOAD-001: Unrestricted upload
            SecurityCheck(
                id="PHP-UPLOAD-001",
                name="Unrestricted File Upload",
                category="upload",
                severity=RiskLevel.HIGH,
                description="File upload without extension/MIME validation allows arbitrary file upload",
                pattern=re.compile(r'(?i)\$_FILES|move_uploaded_file|\\$HTTP_POST_FILES'),
                context_checks=[self._is_upload_safe],
                suggestion="Validate file extension, MIME type, file size. Store outside web root",
                cwe_id="CWE-434",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="$allowed = ['jpg', 'png', 'pdf'];\n$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));\nif (!in_array($ext, $allowed)) { die('Invalid file type'); }",
                attack_vector="Malicious file upload -> PHP shell -> RCE / Server compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-SESSION-001: Session fixation
            SecurityCheck(
                id="PHP-SESSION-001",
                name="Session Fixation Vulnerability",
                category="session",
                severity=RiskLevel.HIGH,
                description="Not regenerating session ID after authentication allows session fixation",
                pattern=re.compile(r'(?i)\$_SESSION\s*\[|session_start'),
                context_checks=[self._is_session_fixed],
                suggestion="Call session_regenerate_id(true) after successful authentication",
                cwe_id="CWE-384",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="session_regenerate_id(true);\n$_SESSION['user_id'] = $userId;",
                attack_vector="Attacker-provided session ID -> User authenticates -> Fixed session -> Hijack",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # PHP-LOG-001: Log injection
            SecurityCheck(
                id="PHP-LOG-001",
                name="Log Injection via Unsanitized Input",
                category="logging",
                severity=RiskLevel.HIGH,
                description="Logging unsanitized user input enables log injection attacks",
                pattern=re.compile(r'(?i)\b(error_log|syslog|trigger_error)\s*\(\s*\$'),
                context_checks=[self._is_log_safe],
                suggestion="Sanitize newlines and special characters before logging user input",
                cwe_id="CWE-117",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="error_log('User input: ' . str_replace([\"\\r\", \"\\n\"], '', $userInput));",
                attack_vector="User input with \\r\\n -> Log injection -> SIEM injection / Log forgery",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # PHP-REFLECT-001: Unsafe reflection
            SecurityCheck(
                id="PHP-REFLECT-001",
                name="Unsafe Dynamic Function Call",
                category="reflection",
                severity=RiskLevel.HIGH,
                description="call_user_func/call_user_func_array with user input allows arbitrary function execution",
                pattern=re.compile(r'(?i)\b(call_user_func|call_user_func_array|forward_static_call|forward_static_call_array)\s*\(\s*\$'),
                context_checks=[],
                suggestion="Validate function names against an allowlist before dynamic invocation",
                cwe_id="CWE-470",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="$allowed = ['sanitizeEmail', 'formatName'];\nif (!in_array($funcName, $allowed)) { die('Invalid function'); }\n$result = call_user_func($funcName, $arg);",
                attack_vector="User input -> call_user_func -> Arbitrary function call -> RCE / Bypass",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # PHP-TYPE-001: Type juggling
            SecurityCheck(
                id="PHP-TYPE-001",
                name="Loose Comparison (Type Juggling)",
                category="type-safety",
                severity=RiskLevel.HIGH,
                description="Loose comparison (==) can bypass authentication (0e123 == hash)",
                pattern=re.compile(r'(?i)\$password\s*==\s*\$|password.*==.*\$hash|==\s*\$.*password'),
                context_checks=[],
                suggestion="Use strict comparison (===) for password and hash comparisons",
                cwe_id="CWE-843",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if (password_verify($password, $hash)) { // strict\n// NOT: if ($password == $hash) { // type juggling bypass",
                attack_vector="Type juggling (0e... == hash) -> Auth bypass -> Account compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-PASSWORD-001: Insecure password storage
            SecurityCheck(
                id="PHP-PASSWORD-001",
                name="Insecure Password Storage",
                category="authentication",
                severity=RiskLevel.HIGH,
                description="Storing passwords with md5/sha1 instead of password_hash()",
                pattern=re.compile(r'(?i)\$password\s*=\s*(md5|sha1)\s*\('),
                context_checks=[],
                suggestion="Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID",
                cwe_id="CWE-916",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="$hash = password_hash($password, PASSWORD_ARGON2ID);\n// Verify: password_verify($password, $hash);",
                attack_vector="Weak password hash -> Fast brute force -> Credential compromise",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # PHP-LDAP-001: LDAP injection
            SecurityCheck(
                id="PHP-LDAP-001",
                name="LDAP Injection via ldap_search",
                category="ldap-injection",
                severity=RiskLevel.HIGH,
                description="Unsanitized user input in LDAP search filters allows injection attacks",
                pattern=re.compile(r'(?i)\b(ldap_search|ldap_list|ldap_read|ldap_get_entries)\s*\('),
                context_checks=[self._is_ldap_safe],
                suggestion="Sanitize LDAP filter input by escaping special characters",
                cwe_id="CWE-90",
                owasp_category="A03:2021 - Injection",
                remediation_example="$filter = ldap_escape($userInput, '', LDAP_ESCAPE_FILTER);\n$results = ldap_search($ldap, $baseDn, $filter);",
                attack_vector="User input -> LDAP search filter -> Injection -> Data extraction / Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-CSRF-001: Missing CSRF token
            SecurityCheck(
                id="PHP-CSRF-001",
                name="Missing CSRF Protection",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="POST handlers without CSRF token validation are vulnerable to cross-site request forgery",
                pattern=re.compile(r'(?i)\$_POST|$_REQUEST.*method.*POST|\$_SERVER.*REQUEST_METHOD.*POST'),
                context_checks=[self._is_csrf_safe],
                suggestion="Generate and validate CSRF tokens for all state-changing POST requests",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="session_start();\nif ($_POST['_token'] !== $_SESSION['csrf_token']) { die('CSRF failed'); }",
                attack_vector="Missing CSRF token -> Forged POST -> State-changing action",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PHP-REDIR-001: Open redirect
            SecurityCheck(
                id="PHP-REDIR-001",
                name="Open Redirect via header() Location",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="header('Location: ...') with user input enables phishing redirects",
                pattern=re.compile(r'(?i)header\s*\(\s*["\x27]Location:\s*\$\s*[\w\[\]>\'\x22]'),
                context_checks=[self._is_redirect_safe],
                suggestion="Validate redirect URL against a whitelist or use relative paths only",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="$allowed = ['/dashboard', '/profile'];\nif (in_array($redirect, $allowed)) { header('Location: ' . $redirect); }",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # PHP-VALID-001: Missing input validation
            SecurityCheck(
                id="PHP-VALID-001",
                name="Missing Input Validation",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="Processing superglobals ($_GET, $_POST) without validation is unsafe",
                pattern=re.compile(r'(?i)\$(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\['),
                context_checks=[self._is_validated],
                suggestion="Use filter_input() with FILTER_VALIDATE_* or validate manually",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\nif ($id === false || $id === null) { die('Invalid id'); }",
                attack_vector="Missing validation -> Malicious input -> Injection / Logic bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-DEPR-001: Deprecated APIs
            SecurityCheck(
                id="PHP-DEPR-001",
                name="Deprecated API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated PHP APIs can cause compatibility and security issues",
                pattern=re.compile(r'(?i)\b(mysql_connect|mysql_query|mysql_fetch|ereg|eregi|split|create_function|each\b|set_magic_quotes)'),
                context_checks=[],
                suggestion="Use PDO/MySQLi, preg_*, anonymous functions, foreach instead",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Instead of mysql_query:\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);",
                attack_vector="Deprecated API may miss security fixes or be removed",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-ERROR-001: Display errors on
            SecurityCheck(
                id="PHP-ERROR-001",
                name="Information Disclosure via display_errors",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="display_errors enabled in production exposes internal paths and logic",
                pattern=re.compile(r'(?i)display_errors\s*=\s*[Oo][Nn]|error_reporting\s*\(\s*E_ALL\b|ini_set.*display_errors.*1'),
                context_checks=[self._is_dev_fp],
                suggestion="Disable display_errors and enable log_errors in production",
                cwe_id="CWE-209",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="ini_set('display_errors', '0');\nini_set('log_errors', '1');",
                attack_vector="Error display -> Paths/versions -> Attack surface mapping",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # PHP-CORS-001: Wildcard CORS
            SecurityCheck(
                id="PHP-CORS-001",
                name="Overly Permissive CORS",
                category="cors",
                severity=RiskLevel.MEDIUM,
                description="Access-Control-Allow-Origin: * exposes API to all websites",
                pattern=re.compile(r'(?i)header\s*\(\s*["\x27]Access-Control-Allow-Origin:\s*\*'),
                context_checks=[self._is_dev_fp],
                suggestion="Set specific allowed origins instead of wildcard",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="header('Access-Control-Allow-Origin: https://example.com');\n// Never: header('Access-Control-Allow-Origin: *');",
                attack_vector="Wildcard CORS -> Any website reads API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # PHP-HEADER-001: Missing security headers
            SecurityCheck(
                id="PHP-HEADER-001",
                name="Missing HTTP Security Headers",
                category="headers",
                severity=RiskLevel.MEDIUM,
                description="PHP app without security headers is vulnerable to clickjacking, MIME attacks",
                pattern=re.compile(r'(?i)\bheader\s*\(\s*["\x27]HTTP|\\$Response|response->header|response->withHeader'),
                context_checks=[self._is_header_safe],
                suggestion="Set X-Content-Type-Options, X-Frame-Options, CSP, HSTS via header()",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="header('X-Content-Type-Options: nosniff');\nheader('X-Frame-Options: DENY');\nheader('Content-Security-Policy: default-src \\'self\\'');",
                attack_vector="Missing headers -> Clickjacking / MIME sniffing -> XSS / Data theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PHP-EXTRACT-001: extract injection
            SecurityCheck(
                id="PHP-EXTRACT-001",
                name="Variable Injection via extract()",
                category="variable-injection",
                severity=RiskLevel.MEDIUM,
                description="extract() with user input can overwrite existing variables",
                pattern=re.compile(r'(?i)\bextract\s*\(\s*\$_|parse_str\s*\(\s*\$_'),
                context_checks=[],
                suggestion="Avoid extract(). Use EXTR_SKIP flag or explicit assignment",
                cwe_id="CWE-621",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="extract($_GET, EXTR_SKIP); // Safer\n// OR: $name = $_GET['name'] ?? null;",
                attack_vector="User input -> extract() -> Variable overwrite -> Auth bypass / Logic exploit",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-CRLF-001: HTTP response splitting
            SecurityCheck(
                id="PHP-CRLF-001",
                name="CRLF Injection via header()",
                category="http",
                severity=RiskLevel.MEDIUM,
                description="User input in header() with \\r\\n allows HTTP response splitting",
                pattern=re.compile(r'(?i)header\s*\(\s*\$'),
                context_checks=[self._is_crlf_safe],
                suggestion="Sanitize newlines in header values or use a framework response object",
                cwe_id="CWE-113",
                owasp_category="A03:2021 - Injection",
                remediation_example="$safeValue = str_replace([\"\\r\", \"\\n\"], '', $userInput);\nheader(\"X-Custom: $safeValue\");",
                attack_vector="User input with \\r\\n -> HTTP response splitting -> Cache poisoning / XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # PHP-NOSQL-001: NoSQL injection via MongoDB
            SecurityCheck(
                id="PHP-NOSQL-001",
                name="NoSQL Injection via MongoDB",
                category="nosql-injection",
                severity=RiskLevel.MEDIUM,
                description="MongoDB query operators ($where, $regex) with user input allow injection",
                pattern=re.compile(r'(?i)\$collection->find|MongoDB\\Collection|MongoDB\\Driver\\Query|->aggregate\s*\('),
                context_checks=[self._is_nosql_safe],
                suggestion="Use type-safe query builders and avoid raw operator injection",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="$filter = ['username' => $username]; // Type-safe\n// Never: $filter = ['$where' => \"this.username == '\" . $userInput . \"'\"];",
                attack_vector="User input with $where -> MongoDB injection -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # PHP-DOS-001: ReDoS
            SecurityCheck(
                id="PHP-DOS-001",
                name="Regex Denial of Service (ReDoS)",
                category="dos",
                severity=RiskLevel.MEDIUM,
                description="Regex with nested quantifiers can cause catastrophic backtracking",
                pattern=re.compile(r'\(\s*.\s*\+\s*\)\s*\+|\(\s*.\s*\*\s*\)\s*\*|\(\s*.\s*\*\s*\)\s*\+'),
                context_checks=[],
                suggestion="Avoid nested quantifiers. Use atomic groups (?>...) or possessive quantifiers",
                cwe_id="CWE-1333",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="if (preg_match('/^(a+)+$/', $input) === 1) { // ReDoS danger\n// Use: '/^a++$/D' (possessive, no backtracking)",
                attack_vector="Crafted input -> Catastrophic backtracking -> CPU exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # PHP-ERROR-002: phpinfo exposed
            SecurityCheck(
                id="PHP-ERROR-002",
                name="phpinfo() Call in Production",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="phpinfo() exposes sensitive configuration details to users",
                pattern=re.compile(r'(?i)\bphpinfo\s*\(\s*\)'),
                context_checks=[],
                suggestion="Remove phpinfo() calls from production code",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Remove: phpinfo();\n// Use: phpinfo() only in controlled admin panels",
                attack_vector="phpinfo() -> Full server configuration disclosure -> Attack surface",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # PHP-DEBUG-001: WP_DEBUG
            SecurityCheck(
                id="PHP-DEBUG-001",
                name="Debug Mode Enabled (WP_DEBUG/APP_DEBUG)",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="WP_DEBUG or APP_DEBUG enabled in production exposes sensitive info",
                pattern=re.compile(r'(?i)(define\s*\(\s*["\x27]WP_DEBUG["\x27]\s*,\s*true|APP_DEBUG\s*=>\s*true|APP_ENV\s*=>\s*["\x27]dev["\x27])'),
                context_checks=[self._is_dev_fp],
                suggestion="Set WP_DEBUG and APP_DEBUG to false in production",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="define('WP_DEBUG', false);\n// OR: 'APP_DEBUG' => env('APP_DEBUG', false),",
                attack_vector="Debug mode -> Detailed errors/queries exposed -> Information disclosure",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # PHP-SMTP-001: SMTP injection via mail
            SecurityCheck(
                id="PHP-SMTP-001",
                name="SMTP Header Injection via mail()",
                category="smtp",
                severity=RiskLevel.MEDIUM,
                description="User input in mail() headers allows injecting additional recipients",
                pattern=re.compile(r'(?i)\bmail\s*\(\s*\$'),
                context_checks=[self._is_smtp_safe],
                suggestion="Sanitize newlines in email headers. Use a mail library that handles this",
                cwe_id="CWE-93",
                owasp_category="A03:2021 - Injection",
                remediation_example="$safeSubject = str_replace([\"\\r\", \"\\n\"], '', $userInput);\nmail($to, $safeSubject, $message, $headers);",
                attack_vector="User input with \\r\\n -> SMTP injection -> Spam relay / Phishing",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # PHP-CONFIG-001: expose_php
            SecurityCheck(
                id="PHP-CONFIG-001",
                name="PHP Version Disclosure (expose_php)",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="expose_php on sends PHP version in HTTP headers, aiding attackers",
                pattern=re.compile(r'(?i)ini_set.*expose_php.*1|expose_php\s*=\s*[Oo][Nn]'),
                context_checks=[],
                suggestion="Set expose_php = Off in php.ini or via ini_set()",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="ini_set('expose_php', '0'); // Hides PHP version header",
                attack_vector="PHP version header -> Known CVE targeting -> Exploit delivery",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # PHP-DOC-001: Missing PHPDoc
            SecurityCheck(
                id="PHP-DOC-001",
                name="Missing PHPDoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Public functions and classes should have PHPDoc documentation",
                pattern=re.compile(r'(?i)(function|class|interface|trait)\s+\w+'),
                context_checks=[self._is_phpdoc_present],
                suggestion="Add PHPDoc comments with @param and @return tags",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/**\n * Validates user email format.\n * @param string $email The email to validate\n * @return bool True if valid\n */\nfunction isValidEmail(string $email): bool { ... }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PHP-MAGIC-001: Magic numbers
            SecurityCheck(
                id="PHP-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(if|while|for|return|==|!=|>|<|>=|<=)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_magic_fp],
                suggestion="Define magic numbers as class constants or define()",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="define('MAX_RETRIES', 3);\nconst TIMEOUT = 30;\nif ($retries >= MAX_RETRIES) { throw new RuntimeException(); }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PHP-COMM-001: TODO
            SecurityCheck(
                id="PHP-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security work",
                pattern=re.compile(r'(?i)\/\/\s*TODO|#\s*TODO|TODO:|/\*\s*TODO'),
                context_checks=[],
                suggestion="Address all TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Resolve all TODOs before production. Track in issue tracker.",
                attack_vector="Unresolved TODO may indicate missing security control",
                mitre_technique="N/A",
            ),
            # PHP-COMM-002: FIXME/HACK
            SecurityCheck(
                id="PHP-COMM-002",
                name="FIXME/HACK Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="FIXME/HACK comments indicate known issues or workarounds",
                pattern=re.compile(r'(?i)(FIXME|HACK|XXX|BUG|TEMP|WORKAROUND)\s*[:!]?'),
                context_checks=[],
                suggestion="Address FIXME/HACK items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove HACK workarounds and implement proper solutions before release",
                attack_vector="Known bug left unaddressed may become exploitable",
                mitre_technique="N/A",
            ),
            # PHP-DEBUG-001: var_dump/print_r
            SecurityCheck(
                id="PHP-DEBUG-001",
                name="Debug Function in Production (var_dump/print_r)",
                category="debug",
                severity=RiskLevel.LOW,
                description="var_dump, print_r, dump, dd in production exposes data",
                pattern=re.compile(r'(?i)\b(var_dump|print_r|dump|dd\s*\(|die\s*\(|exit\s*\(.*\$|echo\s*.*print_r)'),
                context_checks=[self._is_dev_fp],
                suggestion="Remove debug functions before deploying to production",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Remove: var_dump($variable);\n// Use: logger->debug('Variable: {value}', ['value' => $variable]);",
                attack_vector="Debug output in production -> Information disclosure",
                mitre_technique="N/A",
            ),
            # PHP-QUAL-001: Short open tags
            SecurityCheck(
                id="PHP-QUAL-001",
                name="Short Open Tag (<?)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Short open tags (<?) can cause compatibility issues when disabled",
                pattern=re.compile(r'^<\?(?!=|php|xml)'),
                context_checks=[],
                suggestion="Use <?php for better compatibility across PHP installations",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="<?php\n// Instead of <?",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # PHP-QUAL-002: Hardcoded localhost
            SecurityCheck(
                id="PHP-QUAL-002",
                name="Hardcoded localhost Address",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost may indicate test/debug code left in production",
                pattern=re.compile(r'["\x27]localhost["\x27]|["\x27]127\.0\.0\.1["\x27]'),
                context_checks=[self._is_dev_fp],
                suggestion="Use configuration variables for hostnames and ports",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="$host = getenv('DB_HOST') ?: 'localhost';\n$port = getenv('DB_PORT') ?: 3306;",
                attack_vector="Hardcoded addresses may expose internal network configuration",
                mitre_technique="N/A",
            ),
            # PHP-QUAL-003: Unused variable
            SecurityCheck(
                id="PHP-QUAL-003",
                name="Unused Variable in Function",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Variables assigned but never used suggest dead code",
                pattern=re.compile(r'^\s*\$\w+\s*=\s*[^;]+\s*;'),
                context_checks=[self._is_var_used],
                suggestion="Remove unused variables to keep code clean",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove or use the assigned variable",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect frameworks from imports and patterns."""
        frameworks = []
        if re.search(r'use\s+Illuminate\\|class.*extends\s+Controller\b|Route::|\\Illuminate\\', content):
            frameworks.append('laravel')
        if re.search(r'use\s+Symfony\\|extends\s+AbstractController|@Route\(', content):
            frameworks.append('symfony')
        if re.search(r'add_action|add_filter|WP_Query|get_post|wpdb|\\$wpdb', content):
            frameworks.append('wordpress')
        if re.search(r'Mage::|Mage_|\\Magento\\', content):
            frameworks.append('magento')
        if re.search(r'yii\\|Yii::|\\\\yii\\\\', content):
            frameworks.append('yii')
        if re.search(r'CodeIgniter|CI_Controller|\\CI_', content):
            frameworks.append('codeigniter')
        if re.search(r'slim\\|Slim\\App|\\\\Slim\\\\', content):
            frameworks.append('slim')
        if re.search(r'use\s+Doctrine\\', content):
            frameworks.append('doctrine')
        if re.search(r'Cake\\|CakePHP', content):
            frameworks.append('cakephp')
        if re.search(r'Drupal|\\Drupal\\', content):
            frameworks.append('drupal')
        if re.search(r'Zend\\|Laminas\\', content):
            frameworks.append('zend')
        self._framework_cache[file_path.name] = frameworks
        return frameworks

    def _passes_context_checks(self, check: SecurityCheck, line: str, content: str, frameworks: List[str]) -> bool:
        """Run all context checks. Returns True if all pass (not false positive)."""
        for ctx in check.context_checks:
            if ctx(line, content, frameworks):
                return False
        return True

    def _add_finding(self, result: AnalysisResult, line_num: int, line: str, check: SecurityCheck) -> None:
        """Add a finding with full metadata."""
        finding = Finding(
            file=str(result.file_path), line=line_num, column=0,
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
        """Run taint analysis from sources to sinks."""
        sources = {
            '$_GET': 'HTTP GET',
            '$_POST': 'HTTP POST',
            '$_REQUEST': 'HTTP Request',
            '$_COOKIE': 'HTTP Cookie',
            '$_SERVER': 'HTTP Server',
            '$_FILES': 'HTTP Upload',
            '$_ENV': 'Environment',
            'getenv': 'Environment',
            '$_SESSION': 'Session',
            'file_get_contents': 'File Read',
            'php://input': 'Raw Input',
        }
        sinks = {
            'mysqli_query': 'SQL Query',
            'mysqli_prepare': 'SQL Query',
            'PDO::query': 'SQL Query',
            'PDO->query': 'SQL Query',
            'PDO->exec': 'SQL Exec',
            'PDO::prepare': 'SQL Query',
            'PDO->prepare': 'SQL Query',
            'mysql_query': 'SQL Query',
            'exec': 'Command Exec',
            'system': 'Command Exec',
            'shell_exec': 'Command Exec',
            'passthru': 'Command Exec',
            'popen': 'Command Exec',
            'proc_open': 'Command Exec',
            'eval': 'Code Eval',
            'assert': 'Code Eval',
            'include': 'File Include',
            'require': 'File Include',
            'fopen': 'File Open',
            'file_put_contents': 'File Write',
            'unlink': 'File Delete',
            'header': 'Response Header',
            'echo': 'HTML Output',
            'print': 'HTML Output',
            'curl_exec': 'HTTP Request',
        }
        tainted: Dict[str, str] = {}
        for i, line in enumerate(lines, 1):
            for src, stype in sources.items():
                if src in line:
                    m = re.search(r'\$(\w+)\s*=\s*' + re.escape(src), line)
                    if not m:
                        m = re.search(r'\$(\w+)\s*=\s*.*\$_(GET|POST|REQUEST)', line)
                    if m:
                        tainted['$' + m.group(1)] = stype
            for sink, sinktype in sinks.items():
                if sink in line:
                    for var_name, stype in tainted.items():
                        if var_name in line:
                            self._add_taint_finding(result, i, line, stype, sinktype)

    def _add_taint_finding(self, result: AnalysisResult, line_num: int, line: str, source_type: str, sink_type: str) -> None:
        """Add a taint analysis finding."""
        finding = Finding(
            file=str(result.file_path), line=line_num, column=0,
            issue_type="PHP-TAINT-001",
            message=f"[Taint Flow] Data from {source_type} reaches {sink_type} without sanitization",
            risk_level=RiskLevel.HIGH,
            code_snippet=line.strip(),
            suggestion="Sanitize data between source and sink using validation, parameterization, or escaping",
        )
        result.findings.append(finding)

    # ====================================================================
    # CROSS-LINE ANALYSIS
    # ====================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run cross-line pattern detection."""
        self._check_multiline_sql(content, lines, result)
        self._check_multiline_xss(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection across multiple lines."""
        for i, line in enumerate(lines):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+', line):
                for j in range(i, min(i + 5, len(lines))):
                    if '.' in lines[j] and re.search(r'(?i)(query|exec|prepare|get_results)', lines[j]):
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="PHP-SQL-005",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with string concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use prepared statements with placeholders",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);",
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_multiline_xss(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for XSS across multiple lines."""
        for i, line in enumerate(lines):
            if re.search(r'(?i)(echo|print)\s', line) and '$' not in line[:line.find('(') + 1 if '(' in line else len(line)]:
                for j in range(max(0, i - 3), i):
                    if '$' in lines[j] and '=' in lines[j]:
                        var = re.search(r'\$(\w+)', lines[j])
                        if var and var.group(0) in line:
                            self._add_finding(result, i + 1, line, SecurityCheck(
                                id="PHP-XSS-003",
                                name="Multi-line XSS via echo/print",
                                category="xss",
                                severity=RiskLevel.HIGH,
                                description="User-controlled variable from previous line output without encoding",
                                pattern=re.compile(r''),
                                suggestion="htmlspecialchars() all user data before output",
                                cwe_id="CWE-79",
                                owasp_category="A03:2021 - Injection",
                                remediation_example="echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');",
                                attack_vector="Variable from previous line -> echo -> XSS",
                                mitre_technique="T1204.001 - User Execution: Malicious Link",
                            ))
                            break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_laravel_sql_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'where(' in line or '->where(' in line:
            return True
        if 'bindings' in line or '?' in line:
            return True
        return False

    def _is_wpdb_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '$wpdb->prepare' in content and '%' in line:
            return True
        if 'prepare(' in content:
            return True
        return False

    def _is_cmd_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'escapeshellarg' in line or 'escapeshellcmd' in line:
            return True
        if 'Symfony\\\\Component\\\\Process' in content or 'Process' in line:
            return True
        return False

    def _is_deser_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowed_classes' in line or 'allowed_classes' in content:
            return True
        if 'json_decode' in line:
            return True
        return False

    def _is_include_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowed' in line.lower() or 'in_array' in line:
            return True
        if 'switch' in content and 'case' in content:
            return True
        return False

    def _is_path_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'realpath' in line or 'basename' in line:
            return True
        if 'baseDir' in line or 'safePath' in line:
            return True
        return False

    def _is_url_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'parse_url' in line and ('allowedDomains' in content or 'in_array' in content):
            return True
        if 'filter_var' in line and 'FILTER_VALIDATE_URL' in line:
            return True
        if 'allowedDomains' in line or 'allowedHosts' in line:
            return True
        return False

    def _is_curl_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'CURLOPT_URL' in line and 'allowedDomains' in content:
            return True
        if 'parse_url' in content and 'in_array' in content:
            return True
        return False

    def _is_secret_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if 'getenv' in line or '$_ENV' in line:
            return True
        if 'test' in line.lower() or 'PHPUnit' in content:
            return True
        return False

    def _is_xxe_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'libxml_disable_entity_loader' in content:
            return True
        if 'LIBXML_NOENT' not in line and 'LIBXML_DTDLOAD' not in line:
            return True
        return False

    def _is_xss_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'htmlspecialchars' in line or 'htmlentities' in line:
            return True
        if 'e(' in line and '))' in line:
            return True
        if '{{' in line and '!!' not in line:
            return True
        return False

    def _is_crypto_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'hash(' in line and 'sha256' in line.lower():
            return True
        if 'checksum' in line.lower() or 'hashcode' in line.lower():
            return True
        if 'password_hash' in line:
            return True
        return False

    def _is_random_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'random_int' in line or 'random_bytes' in line:
            return True
        if 'animation' in line.lower() or 'game' in line.lower():
            return True
        return False

    def _is_upload_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'in_array' in line and 'ext' in line.lower():
            return True
        if 'mime_content_type' in line or 'finfo' in line:
            return True
        if 'allowed' in line.lower():
            return True
        return False

    def _is_session_fixed(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'session_regenerate_id' in content:
            return True
        return False

    def _is_log_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'str_replace' in line or 'preg_replace' in line:
            return True
        if 'htmlspecialchars' in line:
            return True
        return False

    def _is_csrf_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '_token' in content or 'csrf' in content.lower():
            return True
        if 'verifyCsrfToken' in content or '@csrf' in content:
            return True
        return False

    def _is_redirect_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'in_array' in line or 'allowed' in line.lower():
            return True
        if 'wp_safe_redirect' in line or 'safe_redirect' in line:
            return True
        return False

    def _is_ldap_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ldap_escape' in line or 'ldap_escape' in content:
            return True
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        return False

    def _is_crlf_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'str_replace' in line or 'preg_replace' in line:
            return True
        if 'filter_var' in line:
            return True
        return False

    def _is_nosql_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'filter_input' in content or 'filter_var' in content:
            return True
        return False

    def _is_smtp_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'str_replace' in line or 'preg_replace' in line:
            return True
        return False

    def _is_validated(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'filter_input' in content or 'filter_var' in content:
            return True
        if 'validate' in content.lower() or 'sanitize' in content.lower():
            return True
        if 'preg_match' in content and 'validate' in content.lower():
            return True
        return False

    def _is_dev_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'development' in line.lower() or 'dev' in line.lower() or 'localhost' in line.lower():
            return True
        return False

    def _is_header_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'header(' in content and 'X-Content-Type-Options' in content:
            return True
        if 'header(' in content and 'X-Frame-Options' in content:
            return True
        if 'Content-Security-Policy' in content or 'Strict-Transport-Security' in content:
            return True
        return False

    def _is_phpdoc_present(self, line: str, content: str, frameworks: List[str]) -> bool:
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            if idx > 0:
                for j in range(idx - 1, max(0, idx - 3), -1):
                    prev = lines[j].strip()
                    if prev.endswith('*/') or prev.startswith('*'):
                        return True
        except ValueError:
            pass
        return False

    def _is_magic_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const' in line or 'define(' in line:
            return True
        return False

    def _is_var_used(self, line: str, content: str, frameworks: List[str]) -> bool:
        var_match = re.search(r'^\s*(\$\w+)\s*=', line)
        if var_match:
            var_name = var_match.group(1)
            count = content.count(var_name)
            if count <= 1:
                return False
            return True
        return True
