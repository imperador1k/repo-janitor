"""Elite static analyzer for Go code with comprehensive security checks."""

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
    """A 'security unit test' for Go code."""
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


class GoAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Go code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "go"

    def get_supported_extensions(self) -> List[str]:
        return [".go"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Go file and return results."""
        result = AnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
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
            # GO-SQL-001: Sprintf in Query
            SecurityCheck(
                id="GO-SQL-001",
                name="SQL Injection via fmt.Sprintf in Database Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Using fmt.Sprintf to build SQL queries allows SQL injection",
                pattern=re.compile(r'(?i)(Query|QueryContext|Exec|ExecContext|Prepare|PrepareContext)\s*\([^)]*fmt\.Sprintf'),
                context_checks=[],
                suggestion="Use parameterized queries with $N placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="rows, err := db.QueryContext(ctx, \"SELECT * FROM users WHERE id = $1\", userId)",
                attack_vector="User input -> fmt.Sprintf in SQL -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-SQL-002: String concat in Query
            SecurityCheck(
                id="GO-SQL-002",
                name="SQL Injection via String Concatenation in Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in SQL queries allows injection attacks",
                pattern=re.compile(r'(?i)(Query|QueryContext|Exec|ExecContext|Prepare)\s*\(\s*"[^"]*"\s*\+'),
                context_checks=[],
                suggestion="Use parameterized queries with $N placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="rows, err := db.QueryContext(ctx, \"SELECT * FROM users WHERE id = $1\", userId)",
                attack_vector="User input + SQL string -> SQLi -> Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-SQL-003: GORM raw/exec
            SecurityCheck(
                id="GO-SQL-003",
                name="SQL Injection via GORM Raw Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="GORM .Raw() or .Exec() with string formatting enables SQL injection",
                pattern=re.compile(r'(?i)\.(Raw|Exec)\s*\(\s*fmt\.Sprintf|\.Raw\s*\(\s*["\x27][^"\x27]*"\s*\+'),
                context_checks=[],
                suggestion="Use GORM's parameterized placeholders (?) in raw queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="db.Raw(\"SELECT * FROM users WHERE id = ?\", userId).Scan(&result)",
                attack_vector="User input -> GORM Raw -> SQLi -> Database access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-CMD-001: exec.Command injection
            SecurityCheck(
                id="GO-CMD-001",
                name="Command Injection via exec.Command",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="exec.Command with user input concatenated into string allows injection",
                pattern=re.compile(r'(?i)exec\.Command\s*\([^)]*\+'),
                context_checks=[self._is_fp_command],
                suggestion="Pass arguments as separate slice entries, not concatenated strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="cmd := exec.Command(\"ls\", \"-la\", sanitizedDir)  // Safe: separate args\n// NOT: exec.Command(\"ls -la \" + userInput)",
                attack_vector="User input -> exec.Command concat -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # GO-CMD-002: exec.CommandContext injection
            SecurityCheck(
                id="GO-CMD-002",
                name="Command Injection via exec.CommandContext",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="exec.CommandContext with concatenated string arguments allows injection",
                pattern=re.compile(r'(?i)exec\.CommandContext\s*\([^)]*\+'),
                context_checks=[self._is_fp_command],
                suggestion="Pass arguments as separate slice entries, not concatenated",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="cmd := exec.CommandContext(ctx, \"ls\", \"-la\", sanitizedDir)",
                attack_vector="User input -> CommandContext concat -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # GO-PATH-001: Path traversal
            SecurityCheck(
                id="GO-PATH-001",
                name="Path Traversal via File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user-controlled path can access arbitrary files via ../",
                pattern=re.compile(r'(?i)(os\.Open|os\.Create|os\.Remove|os\.Stat|os\.ReadFile|os\.WriteFile|ioutil\.ReadFile|ioutil\.WriteFile|os\.OpenFile)\s*\([^)]*\+'),
                context_checks=[self._is_fp_file_op],
                suggestion="Use filepath.Clean() and verify path prefix against allowed directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="cleanPath := filepath.Join(baseDir, filepath.Clean(userInput))\nif !strings.HasPrefix(cleanPath, baseDir) { return errors.New(\"invalid path\") }",
                attack_vector="User input -> File path + ../ -> Arbitrary file read/write",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # GO-PATH-002: filepath.Join traversal risk
            SecurityCheck(
                id="GO-PATH-002",
                name="Path Traversal via filepath.Join with User Input",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="filepath.Join with user input starting with / can escape base directory",
                pattern=re.compile(r'(?i)filepath\.(Join|Clean)\s*\([^)]*(user|input|name|path|file|arg|val|param)'),
                context_checks=[self._is_fp_join],
                suggestion="Always validate that resolved path starts with the base directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="joined := filepath.Join(baseDir, userInput)\nif !strings.HasPrefix(joined, baseDir) { return errors.New(\"path traversal\") }",
                attack_vector="User input starting with / -> filepath.Join -> Path escape",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # GO-SSRF-001: SSRF
            SecurityCheck(
                id="GO-SSRF-001",
                name="Server-Side Request Forgery (SSRF)",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="HTTP requests with user-controlled URL can target internal services",
                pattern=re.compile(r'(?i)(http\.Get|http\.Post|http\.PostForm|http\.Head|client\.Get|client\.Post|client\.Do|client\.Head)\s*\([^)]*\+|fmt\.Sprintf.*http\.Get'),
                context_checks=[self._is_fp_url],
                suggestion="Parse URL and validate hostname against an allowlist of external domains",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="u, err := url.Parse(userInput)\nif err != nil { return err }\nif !allowedDomains[u.Hostname()] { return errors.New(\"forbidden\") }",
                attack_vector="User input -> HTTP request -> Internal network scan -> Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # GO-DESER-001: gob deserialization
            SecurityCheck(
                id="GO-DESER-001",
                name="Insecure Deserialization via gob",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="gob.NewDecoder from untrusted input can execute arbitrary code",
                pattern=re.compile(r'(?i)gob\.NewDecoder'),
                context_checks=[self._is_fp_deser],
                suggestion="Avoid deserializing untrusted data with gob. Use JSON with strict schema",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Validate input before deserialization\n// Prefer json.Unmarshal with known struct types",
                attack_vector="Malicious gob payload -> Arbitrary type reconstruction -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # GO-DESER-002: yaml.Unmarshal
            SecurityCheck(
                id="GO-DESER-002",
                name="Unsafe Deserialization via yaml.Unmarshal",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="yaml.Unmarshal can interpret aliases and anchors, leading to unexpected behavior",
                pattern=re.compile(r'(?i)yaml\.(Unmarshal|NewDecoder)\s*\('),
                context_checks=[self._is_fp_deser],
                suggestion="Use yaml.Decoder with known struct types. Validate input beforehand",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Use JSON instead for untrusted data\nvar data SafeStruct\nif err := json.Unmarshal(raw, &data); err != nil { ... }",
                attack_vector="Malicious YAML anchors/aliases -> Unexpected struct fields -> Logic bypass",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # GO-SECRET-001: Hardcoded credential
            SecurityCheck(
                id="GO-SECRET-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="API keys, passwords, tokens hardcoded in source code",
                pattern=re.compile(r'(?i)(?:var|const)\s+\w*(?:api[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key|secret[_-]?key|secret)\w*\s*=\s*["\x27][^"\x27]{8,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables (os.Getenv) or a secrets manager (Vault)",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="apiKey := os.Getenv(\"API_KEY\")\nif apiKey == \"\" { log.Fatal(\"API_KEY not set\") }",
                attack_vector="Source code leak -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # GO-SECRET-002: JWT hardcoded secret
            SecurityCheck(
                id="GO-SECRET-002",
                name="Hardcoded JWT Secret",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="JWT signing key hardcoded in source allows token forgery",
                pattern=re.compile(r'(?i)jwt.*key\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]|jwtSecret\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use os.Getenv with a strong random JWT secret",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="jwtSecret := os.Getenv(\"JWT_SECRET\")\n// Never hardcode JWT secrets in source",
                attack_vector="Hardcoded JWT secret -> Forge any JWT -> Auth bypass",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # GO-TEMPLATE-001: text/template XSS
            SecurityCheck(
                id="GO-TEMPLATE-001",
                name="XSS via text/template (not html/template)",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Using text/template for HTML output disables auto-escaping, enabling XSS",
                pattern=re.compile(r'(?i)"text/template"'),
                context_checks=[self._is_fp_text_template],
                suggestion="Use html/template for HTML output to get automatic XSS protection",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="import \"html/template\"  // Auto-escapes HTML, JS, CSS, URLs",
                attack_vector="text/template for HTML -> No auto-escaping -> XSS -> Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # GO-UNSAFE-001: unsafe package
            SecurityCheck(
                id="GO-UNSAFE-001",
                name="Unsafe Pointer Operations",
                category="unsafe",
                severity=RiskLevel.CRITICAL,
                description="unsafe package bypasses Go's type safety and can cause memory corruption",
                pattern=re.compile(r'(?i)unsafe\.(Pointer|Sizeof|Alignof|Offsetof|Slice|String)'),
                context_checks=[self._is_fp_unsafe],
                suggestion="Avoid unsafe package. Use encoding/binary for byte conversions",
                cwe_id="CWE-825",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Use safe conversions:\nbuf := new(bytes.Buffer)\nbinary.Write(buf, binary.LittleEndian, value)",
                attack_vector="Unsafe pointer -> Memory corruption -> Arbitrary code execution",
                mitre_technique="T1055 - Process Injection",
            ),
            # GO-PANIC-001: panic
            SecurityCheck(
                id="GO-PANIC-001",
                name="Panic in Production Code",
                category="error-handling",
                severity=RiskLevel.CRITICAL,
                description="panic() in production crashes the application and can cause DoS",
                pattern=re.compile(r'(?i)\bpanic\s*\('),
                context_checks=[self._is_fp_panic],
                suggestion="Return errors instead of panicking. Use panic only in init() for unrecoverable states",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="if err != nil {\n    return fmt.Errorf(\"operation failed: %w\", err)\n}",
                attack_vector="panic triggered -> Application crash -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # GO-CRYPTO-001: Weak hash
            SecurityCheck(
                id="GO-CRYPTO-001",
                name="Weak Cryptographic Hash (MD5/SHA1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks",
                pattern=re.compile(r'(?i)(crypto/md5|crypto/sha1|\"md5\"|\"sha1\"|md5\.New|sha1\.New)'),
                context_checks=[self._is_fp_hash],
                suggestion="Use crypto/sha256 or crypto/sha512 for security-sensitive hashing",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import \"crypto/sha256\"\nhash := sha256.Sum256(data)  // Secure",
                attack_vector="Collision attack on MD5/SHA1 -> Signature forgery",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # GO-CRYPTO-002: Hardcoded crypto key
            SecurityCheck(
                id="GO-CRYPTO-002",
                name="Hardcoded Encryption Key",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Encryption keys hardcoded in source can be extracted from leaks",
                pattern=re.compile(r'(?i)(aes|des|rsa|hmac|secret).*(key|secret)\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Store encryption keys in environment variables or a KMS",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="key := os.Getenv(\"ENCRYPTION_KEY\")\nif key == \"\" { log.Fatal(\"ENCRYPTION_KEY not set\") }",
                attack_vector="Hardcoded encryption key -> Decrypt all protected data",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # GO-TLS-001: InsecureSkipVerify
            SecurityCheck(
                id="GO-TLS-001",
                name="TLS Certificate Verification Disabled",
                category="tls",
                severity=RiskLevel.HIGH,
                description="InsecureSkipVerify: true disables TLS certificate validation, enabling MITM",
                pattern=re.compile(r'(?i)InsecureSkipVerify\s*:\s*true'),
                context_checks=[self._is_fp_dev],
                suggestion="Never set InsecureSkipVerify to true in production. Use proper CA certificates",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="tlsConfig := &tls.Config{\n    RootCAs: certPool,\n    // InsecureSkipVerify: false (default)\n}",
                attack_vector="TLS verification disabled -> MITM -> Credential theft",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # GO-RANDOM-001: math/rand
            SecurityCheck(
                id="GO-RANDOM-001",
                name="Weak Random Number Generator (math/rand)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="math/rand is predictable and should not be used for security tokens",
                pattern=re.compile(r'(?i)(math/rand|\"math/rand\"|rand\.(Int|Intn|Int63|Float64|Uint32|Uint64|Seed))'),
                context_checks=[self._is_fp_random],
                suggestion="Use crypto/rand package for security-sensitive randomness",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import \"crypto/rand\"\nn, err := rand.Int(rand.Reader, big.NewInt(maxVal))",
                attack_vector="Predictable random -> Session token forgery -> Auth bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # GO-CRYPTO-003: Timing attack
            SecurityCheck(
                id="GO-CRYPTO-003",
                name="Timing Attack via String Comparison",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Using == or reflect.DeepEqual for secret comparison leaks timing information",
                pattern=re.compile(r'(?i)(==\s*\w*(Secret|Token|Key|Password|Hash|Signature)|hmac\.Equal|crypto\.subtle)'),
                context_checks=[self._is_fp_timing],
                suggestion="Use crypto/subtle.ConstantTimeCompare for constant-time comparison",
                cwe_id="CWE-208",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import \"crypto/subtle\"\nif subtle.ConstantTimeCompare(a, b) == 1 { /* match */ }",
                attack_vector="Timing side-channel -> Character-by-character secret recovery",
                mitre_technique="T1600.002 - Weaken Encryption: Reducing Key Space",
            ),
            # GO-XSS-001: Gin/Echo XSS (Reflected)
            SecurityCheck(
                id="GO-XSS-001",
                name="Reflected XSS via Raw HTML Response",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Writing user input directly to HTTP response without escaping enables XSS",
                pattern=re.compile(r'(?i)(fmt\.Fprint|io\.WriteString|w\.Write)\s*\([^)]*\+.*(r\.|c\.|req\.|ctx\.)'),
                context_checks=[self._is_fp_xss],
                suggestion="Always HTML-escape user input before writing to HTTP response",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="import \"html\"\nfmt.Fprint(w, html.EscapeString(userInput))",
                attack_vector="User input written to response -> XSS -> Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # GO-GOROUTINE-001: Goroutine leak
            SecurityCheck(
                id="GO-GOROUTINE-001",
                name="Potential Goroutine Leak",
                category="concurrency",
                severity=RiskLevel.HIGH,
                description="Goroutines without context cancellation can leak resources and cause DoS",
                pattern=re.compile(r'(?i)go\s+func\s*\('),
                context_checks=[self._is_fp_goroutine],
                suggestion="Use context.Context for cancellation and ensure goroutines exit via ctx.Done()",
                cwe_id="CWE-404",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="ctx, cancel := context.WithCancel(context.Background())\ndefer cancel()\ngo func(ctx context.Context) {\n    select {\n    case <-ctx.Done():\n        return\n    default:\n        process()\n    }\n}(ctx)",
                attack_vector="Unmanaged goroutine -> Resource exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # GO-HTTP-001: HTTP without TLS
            SecurityCheck(
                id="GO-HTTP-001",
                name="HTTP Server Without TLS",
                category="http",
                severity=RiskLevel.HIGH,
                description="http.ListenAndServe uses plain HTTP, exposing traffic to interception",
                pattern=re.compile(r'(?i)http\.ListenAndServe\s*\('),
                context_checks=[self._is_fp_http_tls],
                suggestion="Use http.ListenAndServeTLS or a reverse proxy with TLS termination",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="log.Fatal(http.ListenAndServeTLS(\":443\", \"cert.pem\", \"key.pem\", handler))",
                attack_vector="Plain HTTP -> Traffic interception -> Data exposure",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # GO-LOG-001: Log injection
            SecurityCheck(
                id="GO-LOG-001",
                name="Log Injection via User Input",
                category="logging",
                severity=RiskLevel.HIGH,
                description="Logging unsanitized user input can inject log entries or exploit log viewers",
                pattern=re.compile(r'(?i)(log\.Print|log\.Printf|log\.Println|log\.Fatal|log\.Fatalf|log\.Fatalln)\s*\([^)]*\+'),
                context_checks=[self._is_fp_log],
                suggestion="Use structured logging with parameterized messages, or sanitize newlines",
                cwe_id="CWE-117",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="log.Printf(\"User action: %s\", sanitizeLogField(userInput))",
                attack_vector="User input with \\r\\n -> Log injection -> SIEM injection / Log forgery",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # GO-ASSERT-001: Unsafe type assertion
            SecurityCheck(
                id="GO-ASSERT-001",
                name="Unsafe Type Assertion (Without ok Check)",
                category="type-safety",
                severity=RiskLevel.HIGH,
                description="Type assertion without comma-ok idiom panics on type mismatch",
                pattern=re.compile(r'\.\s*\(\s*\w+\s*\)(?![^(]*ok)'),
                context_checks=[self._is_fp_assertion],
                suggestion="Always use the comma-ok idiom (val, ok := iface.(Type))",
                cwe_id="CWE-704",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="val, ok := iface.(string)\nif !ok { return errors.New(\"unexpected type\") }",
                attack_vector="Type assertion panic -> Application crash -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # GO-CORS-001: CORS wildcard
            SecurityCheck(
                id="GO-CORS-001",
                name="Overly Permissive CORS Policy",
                category="cors",
                severity=RiskLevel.HIGH,
                description="Access-Control-Allow-Origin: * or AllowedOrigins: [\"*\"] exposes API to all origins",
                pattern=re.compile(r"(?i)(Access-Control-Allow-Origin\s*:\s*\*|AllowedOrigins\s*:\s*\[\s*\"\*\"|AllowAllOrigins\s*:\s*true)"),
                context_checks=[self._is_fp_dev],
                suggestion="Specify exact allowed origins instead of wildcard",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="cors.New(cors.Options{\n    AllowedOrigins: []string{\"https://app.example.com\"},\n})",
                attack_vector="Wildcard CORS -> Any domain reads API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # GO-CSRF-001: Missing CSRF
            SecurityCheck(
                id="GO-CSRF-001",
                name="Missing CSRF Protection",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="Web application without CSRF protection allows cross-site request forgery",
                pattern=re.compile(r'(?i)(gin\.New|echo\.New|mux\.NewRouter|chi\.NewRouter|fiber\.New)\s*\('),
                context_checks=[self._is_fp_csrf],
                suggestion="Implement CSRF tokens (Gin: csrf middleware, Echo: nosurf)",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="// Gin CSRF middleware\nr.Use(csrf.Middleware(csrf.Options{\n    Secret: csrfSecret,\n    ErrorFunc: errorHandler,\n}))",
                attack_vector="Missing CSRF token -> Attacker forges authenticated request -> State change",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # GO-VALID-001: Missing input validation
            SecurityCheck(
                id="GO-VALID-001",
                name="Handler Without Input Validation",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="HTTP handler without input validation can accept malicious payloads",
                pattern=re.compile(r'(?i)(HandleFunc|Handle|router\.(GET|POST|PUT|DELETE)|\.GET\s*\(|\.POST\s*\()'),
                context_checks=[self._is_fp_validation],
                suggestion="Validate struct tags with go-playground/validator or custom validation",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="type Request struct {\n    Email string `json:\"email\" validate:\"required,email\"`\n}\nif err := validator.Struct(req); err != nil { http.Error(w, err.Error(), 400) }",
                attack_vector="Missing validation -> Malicious payload accepted -> Logic exploitation",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-ERROR-001: Ignored error
            SecurityCheck(
                id="GO-ERROR-001",
                name="Ignored Error Return",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Ignoring returned errors can hide security-critical failures",
                pattern=re.compile(r'(?i)_\s*:=\s*\w+\.\w+\s*\(|_\s*=\s*\w+\.\w+\s*\('),
                context_checks=[self._is_fp_ignored_error],
                suggestion="Always check error returns using the if err != nil pattern",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="result, err := doSomething()\nif err != nil {\n    return fmt.Errorf(\"failed: %w\", err)\n}",
                attack_vector="Error ignored -> Security mechanism silently fails",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # GO-HEADER-001: Missing security headers
            SecurityCheck(
                id="GO-HEADER-001",
                name="Missing HTTP Security Headers",
                category="headers",
                severity=RiskLevel.MEDIUM,
                description="Missing security headers (CSP, HSTS, X-Frame-Options) increase attack surface",
                pattern=re.compile(r'(?i)(http\.Handle|http\.Handler|http\.HandlerFunc|NewServeMux|mux|router|engine)'),
                context_checks=[self._is_fp_headers],
                suggestion="Add security headers middleware: CSP, HSTS, X-Content-Type-Options, X-Frame-Options",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="func securityHeaders(next http.Handler) http.Handler {\n    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n        w.Header().Set(\"X-Content-Type-Options\", \"nosniff\")\n        w.Header().Set(\"X-Frame-Options\", \"DENY\")\n        w.Header().Set(\"Content-Security-Policy\", \"default-src 'self'\")\n        next.ServeHTTP(w, r)\n    })\n}",
                attack_vector="Missing security headers -> Clickjacking / MIME sniffing / XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # GO-DEPR-001: Deprecated ioutil
            SecurityCheck(
                id="GO-DEPR-001",
                name="Deprecated ioutil Package Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="ioutil is deprecated since Go 1.16, use os and io packages instead",
                pattern=re.compile(r'(?i)(ioutil\.ReadAll|ioutil\.ReadFile|ioutil\.WriteFile|ioutil\.TempFile|ioutil\.TempDir|ioutil\.NopCloser|ioutil\.Discard)'),
                context_checks=[],
                suggestion="Use os.ReadFile, os.WriteFile, io.ReadAll instead of ioutil functions",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Go 1.16+: use os.ReadFile(filename) instead of ioutil.ReadFile(filename)\ndata, err := os.ReadFile(filename)",
                attack_vector="Deprecated API may miss security fixes",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-RACE-001: Race condition
            SecurityCheck(
                id="GO-RACE-001",
                name="Potential Race Condition (Unprotected Shared Variable)",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Shared variable access without sync protection can cause race conditions",
                pattern=re.compile(r'(?i)(sync\.Mutex|sync\.RWMutex|sync\.WaitGroup|sync\.Once|atomic\.)'),
                context_checks=[self._is_fp_race],
                suggestion="Use mutexes (sync.Mutex), channels, or atomic operations for shared state",
                cwe_id="CWE-362",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="var mu sync.Mutex\nmu.Lock()\nsharedVar = newValue\nmu.Unlock()\n// Or: atomic.StoreInt64(&counter, 5)",
                attack_vector="Race condition -> Data corruption -> Auth bypass / Privilege escalation",
                mitre_technique="T1055 - Process Injection",
            ),
            # GO-CONFIG-001: Debug mode in production
            SecurityCheck(
                id="GO-CONFIG-001",
                name="Debug Mode Enabled",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="Gin debug mode or Revel dev mode in production exposes sensitive information",
                pattern=re.compile(r'(?i)(gin\.Mode\s*=\s*debug|gin\.SetMode\(.*debug|RevelDevMode|pprof|net/http/pprof)'),
                context_checks=[self._is_fp_dev],
                suggestion="Use gin.ReleaseMode or remove debug endpoints before production",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="gin.SetMode(gin.ReleaseMode)  // Production mode",
                attack_vector="Debug mode -> Stack traces/pprof -> Information disclosure",
                mitre_technique="T1214 - Credentials in Registry",
            ),
            # GO-DB-001: NoSQL injection
            SecurityCheck(
                id="GO-DB-001",
                name="NoSQL Injection (MongoDB $where)",
                category="nosql-injection",
                severity=RiskLevel.MEDIUM,
                description="MongoDB queries with user input using $where can allow injection",
                pattern=re.compile(r'(?i)(bson\.M|bson\.D|Find|FindOne|UpdateOne|DeleteOne)\s*\([^)]*\$where|\$regex'),
                context_checks=[self._is_fp_nosql],
                suggestion="Sanitize query keys using a helper that removes $ operators",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="filter := bson.M{}\nfor k, v := range userQuery {\n    if !strings.HasPrefix(k, \"$\") { filter[k] = v }\n}",
                attack_vector="User input with $where -> MongoDB injection -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # GO-REDIR-001: Open redirect
            SecurityCheck(
                id="GO-REDIR-001",
                name="Open Redirect via User-Controlled URL",
                category="redirect",
                severity=RiskLevel.MEDIUM,
                description="Redirecting to user-controlled URLs enables phishing attacks",
                pattern=re.compile(r'(?i)(http\.Redirect|c\.Redirect|ctx\.Redirect|fiber\.Redirect)\s*\('),
                context_checks=[self._is_fp_redirect],
                suggestion="Validate redirect URLs against an allowlist of trusted domains",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="allowedHosts := map[string]bool{\"example.com\": true}\nu, err := url.Parse(redirectURL)\nif err != nil || !allowedHosts[u.Host] { http.Error(w, \"invalid redirect\", 400); return }",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # GO-DOC-001: Missing godoc
            SecurityCheck(
                id="GO-DOC-001",
                name="Missing Godoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Exported functions/types should have godoc comments",
                pattern=re.compile(r'(?i)^(func|type|const|var)\s+[A-Z]'),
                context_checks=[self._is_fp_godoc],
                suggestion="Add godoc comments with package descriptions and usage examples",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// ProcessUser validates and processes user data.\n// It returns the processed result or an error.\nfunc ProcessUser(ctx context.Context, user *User) (*Result, error) {",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # GO-MAGIC-001: Magic numbers
            SecurityCheck(
                id="GO-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(if|for|return|==|!=|>|<|>=|<=|case)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_fp_magic],
                suggestion="Define magic numbers as constants (const maxRetries = 5)",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const maxRetries = 5\nif retries >= maxRetries { return errors.New(\"max retries\") }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # GO-COMM-001: TODO comments
            SecurityCheck(
                id="GO-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security work",
                pattern=re.compile(r'(?i)\/\/\s*TODO|TODO:|TODO\s*\('),
                context_checks=[],
                suggestion="Address TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Address all TODOs before deploying to production",
                attack_vector="Unresolved TODO may indicate missing security control",
                mitre_technique="N/A",
            ),
            # GO-COMM-002: FIXME/HACK
            SecurityCheck(
                id="GO-COMM-002",
                name="FIXME/HACK Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="FIXME/HACK comments indicate known issues or workarounds",
                pattern=re.compile(r'(?i)(FIXME|HACK|XXX|BUG|TEMP)\s*[:!]?'),
                context_checks=[],
                suggestion="Address FIXME/HACK items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove HACK workarounds and implement proper solutions",
                attack_vector="Known bug left unaddressed may become a vulnerability",
                mitre_technique="N/A",
            ),
            # GO-QUAL-001: Goto statement
            SecurityCheck(
                id="GO-QUAL-001",
                name="Goto Statement Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="goto can make code flow difficult to audit and maintain",
                pattern=re.compile(r'(?i)\bgoto\s+\w+'),
                context_checks=[],
                suggestion="Use structured control flow (if/for/switch) instead of goto",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Restructure without goto:\nif err != nil { return err }\nprocess()",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # GO-QUAL-002: Hardcoded localhost
            SecurityCheck(
                id="GO-QUAL-002",
                name="Hardcoded localhost Address",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost may indicate test/debug code left in production",
                pattern=re.compile(r'["\x27]localhost["\x27]|["\x27]127\.0\.0\.1["\x27]|["\x27]:\d{4,5}["\x27]'),
                context_checks=[self._is_fp_dev],
                suggestion="Use configuration variables for host:port values",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="addr := os.Getenv(\"LISTEN_ADDR\")\nif addr == \"\" { addr = \":8080\" }  // Configurable default",
                attack_vector="Hardcoded addresses may expose internal port information",
                mitre_technique="N/A",
            ),
            # GO-QUAL-003: Blank identifier misuse
            SecurityCheck(
                id="GO-QUAL-003",
                name="Blank Identifier Ignoring Error",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Using _ for error return ignores potential failures",
                pattern=re.compile(r'(?i)err\s*=\s*\w+\.\w+\([^)]*\)\s*\n'),
                context_checks=[self._is_fp_blank_err],
                suggestion="Check errors explicitly with if err != nil { ... }",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="result, err := doSomething()\nif err != nil {\n    return fmt.Errorf(\"failed: %w\", err)\n}",
                attack_vector="Silent failure -> Security mechanism bypassed",
                mitre_technique="T1564 - Hide Artifacts",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect frameworks from Go imports."""
        frameworks = []
        if re.search(r'github\.com/gin-gonic/gin', content):
            frameworks.append('gin')
        if re.search(r'github\.com/labstack/echo', content):
            frameworks.append('echo')
        if re.search(r'github\.com/gorilla/mux', content):
            frameworks.append('gorilla')
        if re.search(r'github\.com/go-chi/chi', content):
            frameworks.append('chi')
        if re.search(r'google\.golang\.org/grpc', content):
            frameworks.append('grpc')
        if re.search(r'github\.com/gofiber/fiber', content):
            frameworks.append('fiber')
        if re.search(r'github\.com/spf13/cobra', content):
            frameworks.append('cobra')
        if re.search(r'github\.com/jinzhu/gorm|gorm\.io/gorm', content):
            frameworks.append('gorm')
        if re.search(r'github\.com/jmoiron/sqlx', content):
            frameworks.append('sqlx')
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
            'r.URL.Query': 'HTTP Query',
            'r.FormValue': 'HTTP Form',
            'r.Form': 'HTTP Form',
            'r.PostFormValue': 'HTTP POST',
            'r.Header': 'HTTP Header',
            'c.Query': 'Gin Query',
            'c.Param': 'Gin Param',
            'c.PostForm': 'Gin POST',
            'c.FormValue': 'Gin Form',
            'ctx.Query': 'Echo Query',
            'ctx.Param': 'Echo Param',
            'ctx.FormValue': 'Echo Form',
            'os.Getenv': 'Environment Var',
            'os.Args': 'CLI Args',
        }
        sinks = {
            'db.Query': 'SQL Query',
            'db.Exec': 'SQL Exec',
            'db.QueryContext': 'SQL Query',
            'db.ExecContext': 'SQL Exec',
            'exec.Command': 'Command Exec',
            'exec.CommandContext': 'Command Exec',
            'os.Open': 'File Open',
            'os.Create': 'File Create',
            'http.Get': 'HTTP Request',
            'client.Get': 'HTTP Request',
        }
        tainted: Dict[str, str] = {}
        for i, line in enumerate(lines, 1):
            for src, stype in sources.items():
                if src in line:
                    m = re.search(r':=\s*\w+\s*=\s*.*' + re.escape(src), line)
                    if m:
                        tainted[m.group(1)] = stype
            for sink, sinktype in sinks.items():
                if sink in line:
                    for var_name, stype in tainted.items():
                        if var_name in line:
                            self._add_taint_finding(result, i, line, stype, sinktype)

    def _add_taint_finding(self, result: AnalysisResult, line_num: int, line: str, source_type: str, sink_type: str) -> None:
        """Add a taint finding."""
        finding = Finding(
            file=str(result.file_path), line=line_num, column=0,
            issue_type="GO-TAINT-001",
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

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection across multiple lines."""
        for i, line in enumerate(lines):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+', line):
                for j in range(i, min(i + 4, len(lines))):
                    if '+' in lines[j] and re.search(r'(?i)(Query|Exec)', lines[j]):
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="GO-SQL-004",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries with $N placeholders",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example='rows, err := db.Query("SELECT * FROM users WHERE id = $1", userId)',
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_fp_command(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'exec\.Command\s*\(\s*"[^"]*"\s*[,\)]', line):
            return True
        if 'exec.CommandContext' in line and 'ctx' in line:
            return True
        return False

    def _is_fp_file_op(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'(os\.Open|os\.Create|os\.ReadFile)\s*\(\s*"[^"]*"\s*[,\)]', line):
            return True
        if 'filepath.Clean' in line or 'filepath.Join' in content:
            return True
        return False

    def _is_fp_join(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'strings.HasPrefix' in content:
            return True
        return False

    def _is_fp_url(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'(http\.Get|client\.Get)\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'allowedDomains' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_fp_deser(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'json.Unmarshal' in line and 'SafeStruct' in content:
            return True
        return False

    def _is_fp_secret(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if 'os.Getenv' in line:
            return True
        return False

    def _is_fp_text_template(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'html/template' in content:
            return True
        return False

    def _is_fp_unsafe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'cgo' in content or 'syscall' in content:
            return True
        return False

    def _is_fp_panic(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'func init' in content:
            return True
        return False

    def _is_fp_hash(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sha256' in line or 'sha512' in line or 'sha3' in line:
            return True
        if 'checksum' in line.lower():
            return True
        return False

    def _is_fp_random(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'crypto/rand' in content:
            return True
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower():
            return True
        return False

    def _is_fp_timing(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ConstantTimeCompare' in content or 'subtle' in content:
            return True
        return False

    def _is_fp_xss(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'EscapeString' in line or 'html/template' in content:
            return True
        return False

    def _is_fp_goroutine(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'context.Context' in content or 'ctx.Done()' in content:
            return True
        if 'defer cancel()' in content:
            return True
        return False

    def _is_fp_http_tls(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ListenAndServeTLS' in content:
            return True
        return False

    def _is_fp_log(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        if '%s' in line or '%v' in line:
            return True
        return False

    def _is_fp_assertion(self, line: str, content: str, frameworks: List[str]) -> bool:
        if ', ok' in line or ', ok ' in line:
            return True
        if 'switch' in content and 'case' in content:
            return True
        return False

    def _is_fp_dev(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'development' in line.lower() or 'localhost' in line.lower():
            return True
        return False

    def _is_fp_csrf(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'csrf' in line.lower() or 'nosurf' in line.lower():
            return True
        return False

    def _is_fp_validation(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'validator' in content.lower() or 'Validate' in content:
            return True
        if 'if err' in content:
            return True
        return False

    def _is_fp_ignored_error(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'if err' in content:
            return True
        return False

    def _is_fp_headers(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'X-Content-Type-Options' in content or 'X-Frame-Options' in content:
            return True
        if 'Content-Security-Policy' in content:
            return True
        if 'Strict-Transport-Security' in content:
            return True
        return False

    def _is_fp_race(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'mu.Lock()' in content or 'atomic.' in content:
            return True
        return False

    def _is_fp_nosql(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'strings.HasPrefix' in line:
            return True
        return False

    def _is_fp_redirect(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowedHosts' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_fp_godoc(self, line: str, content: str, frameworks: List[str]) -> bool:
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            if idx > 0:
                for j in range(idx - 1, max(0, idx - 3), -1):
                    if lines[j].strip().startswith('//'):
                        return True
        except ValueError:
            pass
        return False

    def _is_fp_magic(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const' in line or ':=' in line:
            return True
        return False

    def _is_fp_blank_err(self, line: str, content: str, frameworks: List[str]) -> bool:
        return True
