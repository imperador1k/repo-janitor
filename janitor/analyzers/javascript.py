"""Elite static analyzer for JavaScript code with comprehensive security checks."""

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
    """A 'security unit test' for JavaScript code."""
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


class JavaScriptAnalyzer(BaseAnalyzer):
    """Elite static analyzer for JavaScript code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "javascript"

    def get_supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".mjs", ".cjs"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a JavaScript file and return results."""
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
            # JS-XSS-001: innerHTML injection
            SecurityCheck(
                id="JS-XSS-001",
                name="XSS via innerHTML",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Direct innerHTML assignment with user input enables script injection",
                pattern=re.compile(r'\binnerHTML\s*='),
                context_checks=[self._is_fp_innerhtml],
                suggestion="Use textContent, createElement(), or sanitize with DOMPurify",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="element.textContent = userInput;\n// OR\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);",
                attack_vector="User input -> innerHTML -> Script injection -> XSS -> Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-002: document.write
            SecurityCheck(
                id="JS-XSS-002",
                name="XSS via document.write",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="document.write() with user input injects arbitrary HTML/scripts",
                pattern=re.compile(r'\bdocument\.write\s*\('),
                context_checks=[self._is_fp_doc_write],
                suggestion="Use DOM manipulation methods instead of document.write",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const container = document.getElementById('app');\ncontainer.textContent = userData;",
                attack_vector="User input -> document.write -> DOM injection -> XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-003: outerHTML injection
            SecurityCheck(
                id="JS-XSS-003",
                name="XSS via outerHTML",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="outerHTML replaces the entire element including the tag, enabling script injection",
                pattern=re.compile(r'\bouterHTML\s*='),
                context_checks=[self._is_fp_innerhtml],
                suggestion="Use textContent or createElement to manipulate DOM safely",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const newEl = document.createElement('div');\nnewEl.textContent = userData;\nelement.parentNode.replaceChild(newEl, element);",
                attack_vector="User input -> outerHTML -> Element replacement with script -> XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-004: insertAdjacentHTML
            SecurityCheck(
                id="JS-XSS-004",
                name="XSS via insertAdjacentHTML",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="insertAdjacentHTML parses HTML strings and can execute scripts",
                pattern=re.compile(r'\binsertAdjacentHTML\s*\('),
                context_checks=[self._is_fp_innerhtml],
                suggestion="Use insertAdjacentText or createElement with textContent",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="element.insertAdjacentText('beforeend', userData);  // Safe - no HTML parsing",
                attack_vector="User input -> insertAdjacentHTML -> Script injection -> XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-005: jQuery HTML injection
            SecurityCheck(
                id="JS-XSS-005",
                name="XSS via jQuery HTML Methods",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="jQuery .html(), .append(), .prepend(), .after(), .before() parse HTML strings",
                pattern=re.compile(r'\$\([^)]*\)\.(html|append|prepend|after|before)\s*\('),
                context_checks=[self._is_fp_jquery],
                suggestion="Use .text() instead of .html() for text content. Sanitize with DOMPurify",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="$('#target').text(userData);  // Safe - no HTML parsing\n// OR sanitize:\n$('#target').html(DOMPurify.sanitize(userData));",
                attack_vector="User input -> jQuery .html() -> HTML parsing -> XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-006: location/URL injection
            SecurityCheck(
                id="JS-XSS-006",
                name="XSS via javascript: URL",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Assigning user input to window.location or anchor.href can execute javascript: URLs",
                pattern=re.compile(r'(window\.location|location\.href|\.src|\.href)\s*=\s*'),
                context_checks=[self._is_fp_url_assign],
                suggestion="Validate URLs against an allowlist. Block javascript: protocol",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const allowed = ['https://trusted.com'];\nconst url = new URL(userInput);\nif (url.protocol === 'https:' && allowed.includes(url.origin)) {\n  window.location = url;\n}",
                attack_vector="User input -> javascript: URL -> XSS via protocol handler",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-XSS-007: Script element injection
            SecurityCheck(
                id="JS-XSS-007",
                name="XSS via Script Element Creation",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Creating script elements with user-controlled src enables arbitrary code execution",
                pattern=re.compile(r'(createElement\s*\(\s*["\x27]script["\x27]|\.src\s*=\s*\$|\binnerText\s*=|\btextContent\s*=\s*\$|\bappendChild.*script)'),
                context_checks=[self._is_fp_script_elem],
                suggestion="Never dynamically create script elements with user input",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const img = document.createElement('img');\nimg.src = sanitizedUrl(imgUrl);  // Validate URL",
                attack_vector="User input -> <script> element -> Arbitrary JS execution",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-CODE-001: eval
            SecurityCheck(
                id="JS-CODE-001",
                name="Code Injection via eval()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="eval() executes arbitrary JavaScript code from string input",
                pattern=re.compile(r'\beval\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Use JSON.parse() for JSON, or proper parsers. Never pass user input to eval",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="const data = JSON.parse(jsonString);  // eval('(' + jsonString + ')') is dangerous",
                attack_vector="User input -> eval() -> RCE -> Full compromise",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # JS-CODE-002: Function constructor
            SecurityCheck(
                id="JS-CODE-002",
                name="Code Injection via Function Constructor",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="new Function() creates a function from a string, equivalent to eval",
                pattern=re.compile(r'\bnew\s+Function\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Use regular functions or arrow functions. Never pass user input to Function",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="const fn = (x, y) => x + y;  // new Function('x', 'y', 'return x + y') is dangerous",
                attack_vector="User input -> Function constructor -> Code execution",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # JS-CODE-003: setTimeout/setInterval string
            SecurityCheck(
                id="JS-CODE-003",
                name="Code Injection via setTimeout String",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="setTimeout/setInterval with string argument is equivalent to eval",
                pattern=re.compile(r'(setTimeout|setInterval)\s*\(\s*["\x27]'),
                context_checks=[],
                suggestion="Use function references instead of strings for timers",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="setTimeout(() => { /* code */ }, 1000);  // Function, not string",
                attack_vector="User input -> setTimeout(string) -> Code execution",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # JS-CMD-001: child_process exec
            SecurityCheck(
                id="JS-CMD-001",
                name="Command Injection via child_process.exec",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="child_process.exec() with shell string allows command injection",
                pattern=re.compile(r'\b(exec|execSync)\s*\('),
                context_checks=[self._is_fp_command],
                suggestion="Use execFile() or spawn() with argument arrays (shell: false)",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="const { execFile } = require('child_process');\nexecFile('ls', ['-la', safeDir], (err, stdout) => {});",
                attack_vector="User input -> exec() -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # JS-CMD-002: spawn shell:true
            SecurityCheck(
                id="JS-CMD-002",
                name="Command Injection via spawn shell:true",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="spawn with shell:true passes strings through shell, enabling injection",
                pattern=re.compile(r'spawn\s*\([^)]*shell\s*:\s*true'),
                context_checks=[],
                suggestion="Use spawn with array arguments and shell:false (default)",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="spawn('ls', ['-la', dirPath], { shell: false });  // Default is safe",
                attack_vector="User input -> spawn(shell:true) -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # JS-SQL-001: SQL template literal
            SecurityCheck(
                id="JS-SQL-001",
                name="SQL Injection via Template Literal",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Template literals in SQL queries concatenate user input, enabling injection",
                pattern=re.compile(r'(?i)(query|execute|run)\s*\(\s*`[^`]*\$\{'),
                context_checks=[self._is_fp_sql],
                suggestion="Use parameterized queries with placeholders ($1, ?, :param)",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="db.query('SELECT * FROM users WHERE id = $1', [userId]);",
                attack_vector="User input -> template literal in SQL -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JS-PATH-001: Path traversal
            SecurityCheck(
                id="JS-PATH-001",
                name="Path Traversal via File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with unsanitized user input can access arbitrary files",
                pattern=re.compile(r'\bfs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|stat|statSync|readdir|readdirSync|rm|rmSync|rmdir)\s*\('),
                context_checks=[self._is_fp_file_op],
                suggestion="Validate paths against allowed directory. Use path.resolve() and check prefix",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const safePath = path.resolve(allowedDir, userInput);\nif (!safePath.startsWith(path.resolve(allowedDir))) throw new Error('Invalid path');",
                attack_vector="User input -> fs.readFile -> ../ traversal -> Arbitrary file read",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # JS-SSRF-001: SSRF
            SecurityCheck(
                id="JS-SSRF-001",
                name="Server-Side Request Forgery (SSRF)",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="HTTP requests with user-controlled URLs can target internal services",
                pattern=re.compile(r'\b(fetch|axios|got|superagent|request|node-fetch|undici\.request|http\.(get|request)|https\.(get|request))\s*\('),
                context_checks=[self._is_fp_url],
                suggestion="Validate URL hostname against an allowlist of external domains",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="const allowed = ['api.trusted.com'];\nconst host = new URL(url).hostname;\nif (!allowed.includes(host)) throw new Error('Forbidden');",
                attack_vector="User input -> HTTP request -> Internal service scan / Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # JS-PROTO-001: Prototype pollution
            SecurityCheck(
                id="JS-PROTO-001",
                name="Prototype Pollution via __proto__",
                category="prototype-pollution",
                severity=RiskLevel.CRITICAL,
                description="Direct __proto__ or constructor.prototype manipulation can pollute Object.prototype",
                pattern=re.compile(r'(__proto__|constructor\.prototype|Object\.prototype)'),
                context_checks=[self._is_fp_proto],
                suggestion="Use Object.create(null) for dictionaries. Avoid prototype manipulation",
                cwe_id="CWE-1321",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const safeDict = Object.create(null);  // No prototype chain\nsafeDict[key] = value;",
                attack_vector="User input with __proto__ -> Object.assign/merge -> All objects affected",
                mitre_technique="T1055 - Process Injection",
            ),
            # JS-AUTH-001: Hardcoded secrets
            SecurityCheck(
                id="JS-AUTH-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded API keys, passwords, tokens, or secrets in source code",
                pattern=re.compile(r'(?i)(api[_-]?key|secret[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key|secret)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables, .env files, or a secrets manager",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="const apiKey = process.env.API_KEY;\n// Never: const API_KEY = 'sk-123456...'",
                attack_vector="Source code leak -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # JS-JWT-001: JWT algorithm confusion
            SecurityCheck(
                id="JS-JWT-001",
                name="JWT Algorithm Confusion",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="JWT verify without algorithm restriction allows 'alg: none' attacks",
                pattern=re.compile(r'jwt\.(verify|decode)\s*\('),
                context_checks=[self._is_fp_jwt],
                suggestion="Always specify algorithms array in jwt.verify()",
                cwe_id="CWE-345",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="jwt.verify(token, secret, { algorithms: ['HS256'] });  // Restrict algorithms",
                attack_vector="JWT with 'alg: none' -> Bypassed verification -> Auth bypass",
                mitre_technique="T1553.002 - Subvert Trust Controls: Code Signing",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # JS-CRYPTO-001: Math.random
            SecurityCheck(
                id="JS-CRYPTO-001",
                name="Insecure Random (Math.random) for Security",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Math.random() is predictable and should not be used for tokens/CSRF/secrets",
                pattern=re.compile(r'\bMath\.random\s*\('),
                context_checks=[self._is_fp_random],
                suggestion="Use crypto.randomBytes() (Node) or crypto.getRandomValues() (browser)",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const token = crypto.randomBytes(32).toString('hex');  // Node\n// const arr = new Uint32Array(1); crypto.getRandomValues(arr);  // Browser",
                attack_vector="Predictable token -> Session hijacking / CSRF bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JS-CRYPTO-002: Weak hash
            SecurityCheck(
                id="JS-CRYPTO-002",
                name="Weak Hashing Algorithm (MD5/SHA1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks",
                pattern=re.compile(r"(?i)crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]"),
                context_checks=[self._is_fp_hash],
                suggestion="Use SHA-256 or SHA-3 from Node crypto module",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const hash = crypto.createHash('sha256').update(data).digest('hex');  // Secure",
                attack_vector="Collision attack on MD5/SHA1 -> Signature forgery",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JS-CRYPTO-003: Timing attack
            SecurityCheck(
                id="JS-CRYPTO-003",
                name="Timing Attack via Insecure Comparison",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="String comparison (===) of secrets leaks timing information",
                pattern=re.compile(r'(===)\s*\w*(Secret|secret|Token|token|Key|key|Password|password|Hash|hash|Signature|signature)'),
                context_checks=[self._is_fp_timing],
                suggestion="Use crypto.timingSafeEqual() for constant-time comparison",
                cwe_id="CWE-208",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const { timingSafeEqual } = require('crypto');\nif (timingSafeEqual(Buffer.from(a), Buffer.from(b))) { /* match */ }",
                attack_vector="Timing side-channel -> Character-by-character secret recovery",
                mitre_technique="T1600.002 - Weaken Encryption: Reducing Key Space",
            ),
            # JS-NOSQL-001: NoSQL injection
            SecurityCheck(
                id="JS-NOSQL-001",
                name="NoSQL Injection (MongoDB operators)",
                category="nosql-injection",
                severity=RiskLevel.HIGH,
                description="User input with $ operators ($gt, $ne, $where) can bypass MongoDB auth",
                pattern=re.compile(r'(?i)(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne)\s*\(\s*\{[^}]*\$\w+'),
                context_checks=[self._is_fp_nosql],
                suggestion="Validate and sanitize user input. Reject query operators ($, $regex, $ne)",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="const sanitized = Object.fromEntries(\n  Object.entries(body).filter(([k]) => !k.startsWith('$'))\n);",
                attack_vector="User input with $ne -> MongoDB query bypass -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JS-POSTMSG-001: postMessage wildcard
            SecurityCheck(
                id="JS-POSTMSG-001",
                name="postMessage with Wildcard Origin",
                category="communication",
                severity=RiskLevel.HIGH,
                description="postMessage with '*' targetOrigin leaks data to any listening window",
                pattern=re.compile(r'postMessage\s*\([^,]+,\s*["\x27]\*["\x27]'),
                context_checks=[],
                suggestion="Specify exact targetOrigin instead of wildcard '*'",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="targetWindow.postMessage(data, 'https://trusted-app.com');",
                attack_vector="Evil page listens for messages -> Data leakage to unauthorized origin",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # JS-REDIR-001: Open redirect
            SecurityCheck(
                id="JS-REDIR-001",
                name="Open Redirect via User-Controlled URL",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="Redirecting to user-controlled URLs enables phishing",
                pattern=re.compile(r'(window\.location\s*(=|\.href\s*=|\.replace\s*\()|res\.redirect\s*\()'),
                context_checks=[self._is_fp_redirect],
                suggestion="Validate redirect URLs against an allowlist of trusted domains",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const allowed = ['https://app.example.com'];\nif (allowed.includes(url)) window.location.href = url;",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # JS-CORS-001: CORS misconfiguration
            SecurityCheck(
                id="JS-CORS-001",
                name="Overly Permissive CORS Policy",
                category="cors",
                severity=RiskLevel.HIGH,
                description="CORS with origin: true or Access-Control-Allow-Origin: * exposes API to all domains",
                pattern=re.compile(r"(origin\s*:\s*true|Access-Control-Allow-Origin\s*:\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"])"),
                context_checks=[self._is_fp_cors],
                suggestion="Specify exact allowed origins in an allowlist",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="app.use(cors({ origin: ['https://app.example.com'] }));",
                attack_vector="Wildcard CORS -> Any domain can read API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # JS-XXE-001: XXE
            SecurityCheck(
                id="JS-XXE-001",
                name="XML External Entity (XXE) Injection",
                category="xxe",
                severity=RiskLevel.HIGH,
                description="XML parsing without disabling external entities enables file read/SSRF",
                pattern=re.compile(r'(?i)(new\s+DOMParser|parseXML|xml2js|libxmljs|fast-xml-parser|sax)'),
                context_checks=[self._is_fp_xxe],
                suggestion="Disable external entity processing when parsing XML",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="const parser = new DOMParser();\n// Configure to disable external entities",
                attack_vector="Malicious XML with external entity -> File read / SSRF",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # JS-REDOS-001: ReDoS
            SecurityCheck(
                id="JS-REDOS-001",
                name="Regular Expression Denial of Service (ReDoS)",
                category="redos",
                severity=RiskLevel.HIGH,
                description="Regex with nested quantifiers can cause catastrophic backtracking",
                pattern=re.compile(r'(?i)(new\s+RegExp|\.match|\.replace|\.search|\.split)\s*\(\s*["\x27/]'),
                context_checks=[self._is_fp_redos],
                suggestion="Avoid nested quantifiers. Use re2 or redos-detector library",
                cwe_id="CWE-1333",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Instead of /(\\w+)+$/, use /^\\w+$/\nconst safeRegex = /^[a-zA-Z]+$/;",
                attack_vector="Crafted input triggers backtracking -> CPU exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # JS-CSRF-001: Missing CSRF
            SecurityCheck(
                id="JS-CSRF-001",
                name="Missing CSRF Protection",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="Express app without CSRF middleware is vulnerable to CSRF attacks",
                pattern=re.compile(r"app\.use\s*\(|router\.use\s*\("),
                context_checks=[self._is_fp_csrf],
                suggestion="Use csurf middleware or implement double-submit cookie pattern",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const csrf = require('csurf');\napp.use(csrf({ cookie: true }));",
                attack_vector="Attacker forges authenticated request -> State-changing operation",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JS-STORAGE-001: localStorage secrets
            SecurityCheck(
                id="JS-STORAGE-001",
                name="Sensitive Data in localStorage/sessionStorage",
                category="storage",
                severity=RiskLevel.HIGH,
                description="Storing tokens, passwords, or secrets in storage is XSS-accessible",
                pattern=re.compile(r'(localStorage|sessionStorage)\.setItem\s*\(\s*["\x27](token|password|secret|key|auth|session|jwt|refresh)["\x27]'),
                context_checks=[],
                suggestion="Use httpOnly cookies or in-memory storage for sensitive data",
                cwe_id="CWE-312",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Use httpOnly, secure cookies set by server\n// Or in-memory: let token = null;",
                attack_vector="XSS vulnerability -> localStorage read -> Token theft",
                mitre_technique="T1555 - Credentials from Password Stores",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # JS-WS-001: Insecure WebSocket
            SecurityCheck(
                id="JS-WS-001",
                name="Insecure WebSocket Connection (ws://)",
                category="websocket",
                severity=RiskLevel.MEDIUM,
                description="Using ws:// exposes WebSocket traffic to interception over network",
                pattern=re.compile(r'new\s+WebSocket\s*\(\s*["\x27]ws://'),
                context_checks=[],
                suggestion="Use wss:// (WebSocket Secure) for encrypted communication",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const ws = new WebSocket('wss://example.com/socket');  // Encrypted",
                attack_vector="Network attacker intercepts ws:// traffic -> Data injection/theft",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # JS-STORAGE-002: Insecure cookies
            SecurityCheck(
                id="JS-STORAGE-002",
                name="Insecure Cookie Configuration",
                category="storage",
                severity=RiskLevel.MEDIUM,
                description="Cookies without httpOnly, secure, or SameSite flags are vulnerable to theft",
                pattern=re.compile(r'res\.cookie\s*\(\s*["\x27]|cookieParser|cookie\(|express\.session\s*\(\s*\{'),
                context_checks=[self._is_fp_cookie],
                suggestion="Set httpOnly: true, secure: true, sameSite: 'strict' on cookies",
                cwe_id="CWE-614",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict'\n});",
                attack_vector="Missing cookie flags -> XSS reads cookie / CSRF uses cookie",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # JS-DEPR-001: Deprecated APIs
            SecurityCheck(
                id="JS-DEPR-001",
                name="Deprecated API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated JavaScript APIs that may have security implications",
                pattern=re.compile(r'\b(document\.(all|domain|layers)|event\.(layerX|layerY|which)|escape|unescape)\b'),
                context_checks=[],
                suggestion="Replace deprecated APIs with modern alternatives",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Use encodeURIComponent() instead of escape()\nconst encoded = encodeURIComponent(userInput);",
                attack_vector="Deprecated API may bypass security boundaries",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JS-ERR-001: Empty catch
            SecurityCheck(
                id="JS-ERR-001",
                name="Empty Catch Block (Swallowed Error)",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Empty catch blocks silently hide errors and failures",
                pattern=re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}'),
                context_checks=[],
                suggestion="Log errors and re-throw or handle appropriately",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="try { ... } catch (error) {\n  console.error('Failed:', error);\n  throw error;\n}",
                attack_vector="Error hidden -> Security mechanism silently fails",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # JS-ERR-002: Unhandled promise
            SecurityCheck(
                id="JS-ERR-002",
                name="Unhandled Promise Rejection (.then without .catch)",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Promise chains without .catch() can silently swallow rejections",
                pattern=re.compile(r'\.then\s*\(\s*[^)]*\s*\)(?!\s*\.catch)'),
                context_checks=[self._is_fp_promise],
                suggestion="Always add .catch() to promises or use try/catch with async/await",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="asyncFunction()\n  .then(result => process(result))\n  .catch(err => console.error('Failed:', err));",
                attack_vector="Unhandled rejection -> Process crash / Undefined behavior",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # JS-DEBUG-001: debugger
            SecurityCheck(
                id="JS-DEBUG-001",
                name="Debugger Statement in Production",
                category="debug",
                severity=RiskLevel.MEDIUM,
                description="Debugger statements halt execution and should not be in production",
                pattern=re.compile(r'\bdebugger\s*;?'),
                context_checks=[self._is_fp_test],
                suggestion="Remove debugger statements before deployment",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="// Remove 'debugger;' before production",
                attack_vector="debugger halts JS execution -> DoS",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # JS-INJECT-001: Template injection
            SecurityCheck(
                id="JS-INJECT-001",
                name="Server-Side Template Injection (SSTI)",
                category="template-injection",
                severity=RiskLevel.MEDIUM,
                description="Passing user input to template engines (EJS, Pug, Handlebars) can enable SSTI",
                pattern=re.compile(r'(?i)(render|template|compile|ejs|pug|handlebars|nunjucks|liquid|mustache)\s*\('),
                context_checks=[self._is_fp_ssti],
                suggestion="Pass user input as template variables, never as template code",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="res.render('page', { message: userInput });  // Safe as variable\n// res.render('page', userInput); would be dangerous",
                attack_vector="User input in template -> SSTI -> RCE",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # JS-AUTH-002: Missing auth middleware
            SecurityCheck(
                id="JS-AUTH-002",
                name="Route Without Authentication Middleware",
                category="authentication",
                severity=RiskLevel.MEDIUM,
                description="Route handler without auth middleware allows unauthenticated access",
                pattern=re.compile(r'(app|router)\.(get|post|put|delete|patch)\s*\(\s*["\x27][^"\x27]*["\x27]\s*,\s*\(?\s*(req|async\s+req)'),
                context_checks=[self._is_fp_auth_middleware],
                suggestion="Apply authentication middleware to all protected routes",
                cwe_id="CWE-862",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="router.get('/admin/users', authenticate, async (req, res) => { ... });",
                attack_vector="No auth middleware -> Unauthenticated access to sensitive endpoint",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JS-XSS-008: DOM clobbering
            SecurityCheck(
                id="JS-XSS-008",
                name="DOM Clobbering via id/name Attributes",
                category="xss",
                severity=RiskLevel.MEDIUM,
                description="Elements with id/name can override global variables, enabling DOM clobbering",
                pattern=re.compile(r'(getElementById|getElementsByName|querySelector)\s*\(\s*["\x27]'),
                context_checks=[self._is_fp_dom_clobber],
                suggestion="Use unique, non-conflicting IDs. Avoid relying on global variable resolution",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Use specific selectors that don't create globals:\nconst el = document.querySelector('[data-safe-id=\"...\"]');",
                attack_vector="Attacker-controlled HTML element id -> Variable shadowing -> Logic bypass",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # JS-LOG-001: console.log
            SecurityCheck(
                id="JS-LOG-001",
                name="Console Statement in Production",
                category="logging",
                severity=RiskLevel.LOW,
                description="Console statements may leak data to browser console or stdout",
                pattern=re.compile(r'\bconsole\.(log|warn|error|info|debug|trace|dir|table)\s*\('),
                context_checks=[self._is_fp_console],
                suggestion="Use a proper logging library (winston, pino) instead of console",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="import logger from './logger';\nlogger.info('Operation completed');",
                attack_vector="Console output -> Sensitive data exposure",
                mitre_technique="N/A",
            ),
            # JS-DOC-001: Missing JSDoc
            SecurityCheck(
                id="JS-DOC-001",
                name="Missing JSDoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Functions and exports should have JSDoc documentation",
                pattern=re.compile(r'(?i)(function\s+\w+|module\.exports\s*=|export\s+(default\s+)?(function|class|const))'),
                context_checks=[self._is_fp_jsdoc],
                suggestion="Add JSDoc comments explaining purpose, params, and returns",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/**\n * Fetches user data\n * @param {number} id - User ID\n * @returns {Promise<Object>}\n */",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JS-MAGIC-001: Magic numbers
            SecurityCheck(
                id="JS-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(?:if|while|for|return|case|===|!==|>=|<=|>|<|==)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_fp_magic],
                suggestion="Define magic numbers as named constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const MAX_RETRIES = 5;\nconst TIMEOUT_SECONDS = 3600;\nif (retries >= MAX_RETRIES) { ... }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JS-COMM-001: TODO comments
            SecurityCheck(
                id="JS-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security measures",
                pattern=re.compile(r'(?i)\/\/\s*TODO|TODO:|\/\*\s*TODO'),
                context_checks=[],
                suggestion="Address TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Address all TODOs before shipping",
                attack_vector="Unaddressed TODO may be a missing security check",
                mitre_technique="N/A",
            ),
            # JS-COMM-002: FIXME/HACK comments
            SecurityCheck(
                id="JS-COMM-002",
                name="FIXME/HACK Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="FIXME/HACK/XXX comments indicate known issues or workarounds",
                pattern=re.compile(r'(?i)(FIXME|HACK|XXX|BUG|TEMP)\s*[:!]?'),
                context_checks=[],
                suggestion="Address FIXME/HACK items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove HACK workarounds and implement proper solutions",
                attack_vector="Known bug left unaddressed could be a vulnerability",
                mitre_technique="N/A",
            ),
            # JS-QUAL-001: Nested callbacks
            SecurityCheck(
                id="JS-QUAL-001",
                name="Deeply Nested Callbacks (Callback Hell)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="More than 3 levels of nesting indicates poor error handling",
                pattern=re.compile(r'(?s)\{[\s\S]*?\{[\s\S]*?\{[\s\S]*?\{'),
                context_checks=[self._is_fp_test],
                suggestion="Use async/await or Promise chains to flatten nested callbacks",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="async function process() {\n  const a = await step1();\n  const b = await step2(a);\n  return step3(b);\n}",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JS-QUAL-002: var keyword
            SecurityCheck(
                id="JS-QUAL-002",
                name="Use of 'var' Instead of 'let' or 'const'",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="'var' has function scope and can cause unintended hoisting/bugs",
                pattern=re.compile(r'\bvar\s+\w+'),
                context_checks=[self._is_fp_test],
                suggestion="Use 'const' for constants and 'let' for mutable variables",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const MAX_SIZE = 100;\nlet counter = 0;\n// 'var' should be avoided in modern JS",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JS-QUAL-003: == vs ===
            SecurityCheck(
                id="JS-QUAL-003",
                name="Loose Equality Operator (==)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="== can cause type coercion bugs leading to unexpected behavior",
                pattern=re.compile(r'(?<![=!])==(?!=)'),
                context_checks=[self._is_fp_eq],
                suggestion="Use === (strict equality) to avoid type coercion issues",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if (userInput === expected) { /* strict */ }\n// if (userInput == expected) { /* loose - may coerce */ }",
                attack_vector="Type coercion via == -> Auth bypass (e.g., '0' == false is true)",
                mitre_technique="N/A",
            ),
            # JS-QUAL-004: Duplicate string literals
            SecurityCheck(
                id="JS-QUAL-004",
                name="Duplicate String Literal",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Repeated string literals should be named constants",
                pattern=re.compile(r'["\x27][A-Za-z0-9_/]{10,}["\x27]'),
                context_checks=[self._is_fp_dup_string],
                suggestion="Extract repeated strings as named constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const API_ENDPOINT = '/api/v2/users';  // Instead of repeating 5 times",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect which frameworks are used."""
        frameworks = []

        if re.search(r'(?i)require\s*\(\s*["\x27]express|from\s+["\x27]express|app\.(get|post|put|delete)', content):
            frameworks.append('express')

        if re.search(r'(?i)require\s*\(\s*["\x27](react|react-dom)|from\s+["\x27](react|react-dom)', content):
            frameworks.append('react')

        if re.search(r'(?i)require\s*\(\s*["\x27]vue|from\s+["\x27]vue|new\s+Vue', content):
            frameworks.append('vue')

        if re.search(r'(?i)require\s*\(\s*["\x27]jquery|\$\.|\$\(', content):
            frameworks.append('jquery')

        if re.search(r'(?i)require\s*\(\s*["\x27]mongoose|mongoose\.', content):
            frameworks.append('mongoose')

        if re.search(r'(?i)require\s*\(\s*["\x27]socket\.io|io\s*\(\s*http', content):
            frameworks.append('socketio')

        if re.search(r'(?i)require\s*\(\s*["\x27]next|from\s+["\x27]next', content):
            frameworks.append('nextjs')

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
        """Run taint tracking from browser/Node sources to dangerous sinks."""
        sources = {
            'window.location': 'URL Location',
            'location.search': 'Query String',
            'location.hash': 'URL Hash',
            'location.href': 'URL Href',
            'document.cookie': 'Document Cookie',
            'localStorage.getItem': 'LocalStorage',
            'sessionStorage.getItem': 'SessionStorage',
            'req.query': 'Express Query',
            'req.body': 'Express Body',
            'req.params': 'Express Params',
            'req.headers': 'Express Headers',
            'req.cookies': 'Express Cookies',
            'process.env': 'Environment Variable',
        }

        sinks = {
            'innerHTML': 'DOM HTML',
            'outerHTML': 'DOM HTML',
            'insertAdjacentHTML': 'DOM HTML',
            'document.write': 'Document Write',
            'eval(': 'Code Eval',
            'Function(': 'Function Ctor',
            'exec(': 'Shell Exec',
            'execSync(': 'Shell Exec',
            'query(': 'SQL Query',
        }

        tainted_vars: Dict[str, str] = {}

        for i, line in enumerate(lines, 1):
            for source, source_type in sources.items():
                if source in line:
                    match = re.search(r'(const|let|var)\s+(\w+)\s*=\s*.*' + re.escape(source), line)
                    if match:
                        tainted_vars[match.group(2)] = source_type

            for sink, sink_type in sinks.items():
                if sink in line:
                    for var_name, source_type in tainted_vars.items():
                        if var_name in line:
                            self._add_taint_finding(result, i, line, source_type, sink_type)

    def _add_taint_finding(self, result: AnalysisResult, line_num: int, line: str, source_type: str, sink_type: str) -> None:
        """Add a taint finding."""
        finding = Finding(
            file=str(result.file_path), line=line_num, column=0,
            issue_type="JS-TAINT-001",
            message=f"[Taint Flow] Data from {source_type} reaches {sink_type} without sanitization",
            risk_level=RiskLevel.HIGH,
            code_snippet=line.strip(),
            suggestion="Sanitize data between source and sink using parameterization, escaping, or validation",
        )
        result.findings.append(finding)

    # ====================================================================
    # CROSS-LINE ANALYSIS
    # ====================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run cross-line detection for multi-line patterns."""
        self._check_multiline_sql(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL built across multiple lines."""
        sql_keywords = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+')
        concat_pattern = re.compile(r'\+\s*\w+|\w+\s*\+')

        for i, line in enumerate(lines):
            if sql_keywords.search(line):
                for j in range(i, min(i + 4, len(lines))):
                    if concat_pattern.search(lines[j]) and 'query(' in lines[j]:
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="JS-SQL-002",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with string concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries instead of concatenation",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="db.query('SELECT * FROM users WHERE id = $1', [userId]);",
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_fp_innerhtml(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if innerHTML/outerHTML/insertAdjacentHTML is safe."""
        if '+' in line:
            return False
        if re.search(r'(innerHTML|outerHTML|insertAdjacentHTML)\s*=\s*["\x27][^"\x27]*["\x27]\s*[;]?$', line.strip()):
            return True
        if 'DOMPurify' in line:
            return True
        return False

    def _is_fp_doc_write(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if document.write is a static string."""
        if re.search(r'document\.write\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_jquery(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if jQuery HTML method is safe."""
        if re.search(r'\.(html|append|prepend)\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'DOMPurify' in line or 'sanitize' in line.lower():
            return True
        return False

    def _is_fp_url_assign(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if URL assignment is safe."""
        if re.search(r'(location\.href|\.src)\s*=\s*["\x27]https?://', line):
            return True
        if 'allowed' in line or 'validate' in line.lower():
            return True
        return False

    def _is_fp_script_elem(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if script element is safe."""
        if 'sanitize' in line.lower() or 'validate' in line.lower():
            return True
        return False

    def _is_fp_eval(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if eval/Function is false positive."""
        if re.search(r'(eval|Function)\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_command(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if command execution is safe."""
        if re.search(r'(exec|execSync)\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        if 'execFile' in line:
            return True
        return False

    def _is_fp_sql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SQL is parameterized."""
        if re.search(r'(query|execute)\s*\(\s*["\x27][^"\x27]*["\x27]\s*,', line):
            return True
        return False

    def _is_fp_file_op(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if file operation is safe."""
        if '+' not in line and re.search(r'fs\.\w+\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'path.resolve' in line or 'startsWith' in line:
            return True
        return False

    def _is_fp_url(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if URL is safe."""
        if re.search(r'(fetch|axios|get|post)\s*\(\s*["\x27]https?://', line):
            return True
        if 'allowed' in line.lower() or 'allowedOrigins' in line:
            return True
        return False

    def _is_fp_proto(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if prototype manipulation is safe."""
        if 'Object.create(null)' in line or 'hasOwnProperty' in line:
            return True
        return False

    def _is_fp_secret(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if secret is example/placeholder."""
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if 'process.env' in line:
            return True
        return False

    def _is_fp_jwt(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JWT is safe."""
        if 'algorithms' in line and 'verify' in line:
            return True
        return False

    def _is_fp_random(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if Math.random is acceptable."""
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower() or 'color' in line.lower():
            return True
        return False

    def _is_fp_hash(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if hash is safe."""
        if 'sha256' in line or 'sha384' in line or 'sha512' in line:
            return True
        if 'checksum' in line.lower():
            return True
        return False

    def _is_fp_timing(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if comparison is constant-time."""
        if 'timingSafeEqual' in content or 'timingSafeEqual' in line:
            return True
        return False

    def _is_fp_nosql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if NoSQL is safe."""
        if 'sanitize' in line or 'escape' in line:
            return True
        return False

    def _is_fp_redirect(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if redirect is safe."""
        if re.search(r'(location|redirect)\s*=\s*["\x27]https?://', line):
            return True
        if 'allowed' in line.lower():
            return True
        return False

    def _is_fp_cors(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if CORS is development."""
        if 'development' in line.lower() or 'localhost' in line.lower():
            return True
        return False

    def _is_fp_xxe(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if XML parsing is safe."""
        if 'disableEntities' in line or 'noExternalEntities' in line:
            return True
        return False

    def _is_fp_redos(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if regex is safe."""
        if 'safe-regex' in line or 'redos' in line.lower() or 're2' in line.lower():
            return True
        return False

    def _is_fp_csrf(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if CSRF protection exists."""
        if 'csrf' in line.lower() or 'csurf' in line.lower() or 'nonce' in line.lower():
            return True
        return False

    def _is_fp_cookie(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if cookie is secure."""
        if 'httpOnly' in line or 'secure' in line or 'sameSite' in line:
            return True
        return False

    def _is_fp_ssti(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if template rendering is safe."""
        if re.search(r'render\s*\(\s*["\x27][^"\x27]*["\x27]\s*,', line):
            return True
        return False

    def _is_fp_promise(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if promise has .catch."""
        if '.catch' in line:
            return True
        return False

    def _is_fp_auth_middleware(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if route has auth."""
        if 'authenticate' in line or 'auth' in line.lower() or 'isAuthenticated' in line:
            return True
        return False

    def _is_fp_test(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if test file."""
        if 'test' in line.lower() or 'spec' in line.lower() or 'mock' in line.lower():
            return True
        return False

    def _is_fp_console(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if console is in test."""
        if 'test' in line.lower() or 'spec' in line.lower():
            return True
        return False

    def _is_fp_jsdoc(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JSDoc exists (previous or next line)."""
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            if idx + 1 < len(lines):
                if '/**' in lines[idx + 1] or '*/' in lines[idx + 1]:
                    return True
            for j in range(max(0, idx - 1), max(0, idx - 3), -1):
                if '/**' in lines[j] or '*/' in lines[j]:
                    return True
        except ValueError:
            pass
        return False

    def _is_fp_magic(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if magic number is acceptable."""
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const' in line or 'let' in line or 'var' in line:
            return True
        return False

    def _is_fp_eq(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if == false positive."""
        if '===' in line or '!==' in line:
            return True
        if '//' in line:
            return True
        return False

    def _is_fp_dom_clobber(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if DOM clobbering false positive."""
        return True

    def _is_fp_dup_string(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if string duplication is acceptable."""
        return False
