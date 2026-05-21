"""Elite static analyzer for TypeScript/TSX code with comprehensive security checks."""

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
    """A 'security unit test' for TypeScript code."""
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


class TypeScriptAnalyzer(BaseAnalyzer):
    """Elite static analyzer for TypeScript/TSX code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}

    def get_language(self) -> str:
        return "typescript"

    def get_supported_extensions(self) -> List[str]:
        return [".ts", ".tsx"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a TypeScript/TSX file and return results."""
        result = AnalysisResult(file_path=file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            result.has_errors = True
            result.error_message = f"Error reading file: {e}"
            return result

        lines = content.split("\n")
        self._current_path = file_path
        detected_frameworks = self._detect_frameworks(content, file_path)
        result.metadata["frameworks"] = detected_frameworks

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*') or stripped.startswith('import '):
                continue
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
        # CRITICAL CHECKS - Can lead to complete system compromise
        # ====================================================================

        checks.extend([
            # TS-XSS-001: Classic innerHTML injection
            SecurityCheck(
                id="TS-XSS-001",
                name="XSS via innerHTML Assignment",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Direct assignment to innerHTML with user input enables script injection",
                pattern=re.compile(r'\binnerHTML\s*='),
                context_checks=[self._is_fp_innerhtml],
                suggestion="Use textContent, createElement(), or sanitize with DOMPurify",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="element.textContent = userInput;\n// OR\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);",
                attack_vector="User input ��' innerHTML ��' Script execution ��' XSS ��' Session theft / Data exfil",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-002: React dangerouslySetInnerHTML
            SecurityCheck(
                id="TS-XSS-002",
                name="XSS via dangerouslySetInnerHTML (React)",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="React's dangerouslySetInnerHTML bypasses built-in XSS protection",
                pattern=re.compile(r'dangerouslySetInnerHTML\s*='),
                context_checks=[self._is_fp_react_sanitized],
                suggestion="Sanitize HTML with DOMPurify before passing or use React components",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
                attack_vector="User input ��' dangerouslySetInnerHTML ��' React XSS ��' Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-003: Vue v-html
            SecurityCheck(
                id="TS-XSS-003",
                name="XSS via v-html (Vue)",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Vue's v-html directive renders raw HTML, enabling script injection",
                pattern=re.compile(r'v-html\s*='),
                context_checks=[self._is_fp_vue_sanitized],
                suggestion="Use text interpolation {{ }} or sanitize with DOMPurify",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="<div>{{ userInput }}</div>  <!-- Safe text interpolation -->",
                attack_vector="User input ��' v-html directive ��' XSS ��' Data exfiltration",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-004: Angular innerHTML binding
            SecurityCheck(
                id="TS-XSS-004",
                name="XSS via [innerHTML] (Angular)",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Angular [innerHTML] binding with bypassSecurityTrustHtml can allow XSS",
                pattern=re.compile(r'\[innerHTML\]\s*='),
                context_checks=[self._is_fp_angular_sanitized],
                suggestion="Use Angular's built-in sanitization; bypassSecurityTrustHtml only for trusted content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="import { DomSanitizer } from '@angular/platform-browser';\nthis.sanitizer.sanitize(SecurityContext.HTML, userInput);",
                attack_vector="User input ��' innerHTML binding ��' Angular XSS ��' Session theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-005: document.write injection
            SecurityCheck(
                id="TS-XSS-005",
                name="XSS via document.write",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="document.write() with user input can inject arbitrary HTML and scripts",
                pattern=re.compile(r'\bdocument\.write\s*\('),
                context_checks=[self._is_fp_doc_write],
                suggestion="Avoid document.write entirely. Use DOM manipulation methods instead",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const container = document.getElementById('app');\ncontainer.textContent = userData;  // Safe",
                attack_vector="User input ��' document.write() ��' DOM injection ��' XSS",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-006: Script injection via createElement
            SecurityCheck(
                id="TS-XSS-006",
                name="XSS via Script Element Injection",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Creating script elements with user-controlled src or content enables code execution",
                pattern=re.compile(r'(createElement\s*\(\s*["\x27]script["\x27]|\.src\s*=\s*\$|\.innerText\s*=.*\$|\.textContent\s*=.*\$)'),
                context_checks=[self._is_fp_script_elem],
                suggestion="Validate and sanitize any user input used in script element creation",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="const img = document.createElement('img');\nimg.src = DOMPurify.sanitize(userUrl);  // Sanitize URL",
                attack_vector="User input ��' <script> element creation ��' Arbitrary JS execution",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-XSS-007: CSS injection
            SecurityCheck(
                id="TS-XSS-007",
                name="CSS Expression Injection via style",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Setting style properties with user input can enable CSS injection attacks in legacy browsers",
                pattern=re.compile(r'(\.style\s*\.\w+\s*=\s*\$|\.cssText\s*=)'),
                context_checks=[self._is_fp_css_injection],
                suggestion="Avoid setting CSS properties directly from user input. Use class toggling instead",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Use CSS classes instead:\nelement.className = allowedClasses[userInput] ? `style-${userInput}` : '';",
                attack_vector="User input ��' CSS expression ��' Script execution (legacy IE) / Data exfil",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-CODE-001: eval / Function
            SecurityCheck(
                id="TS-CODE-001",
                name="Code Injection via eval()",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="eval() executes arbitrary JavaScript strings and enables full code injection",
                pattern=re.compile(r'\beval\s*\('),
                context_checks=[self._is_fp_eval],
                suggestion="Never use eval. Use JSON.parse() for JSON, or proper parsers for other formats",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="const data = JSON.parse(jsonString);  // Safe for JSON\n// eval('(' + jsonString + ')') is dangerous",
                attack_vector="User input ��' eval() ��' Arbitrary code execution ��' Full compromise",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # TS-CODE-002: Function constructor
            SecurityCheck(
                id="TS-CODE-002",
                name="Code Injection via Function Constructor",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="new Function() creates a function from a string, equivalent to eval",
                pattern=re.compile(r'\bnew\s+Function\s*\('),
                context_checks=[self._is_fp_function_ctor],
                suggestion="Use regular functions or arrow functions. Never pass user input to Function constructor",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="const fn = (x, y) => x + y;  // Safe\n// new Function('x', 'y', 'return x + y') is dangerous",
                attack_vector="User input ��' Function() ��' Code execution",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # TS-CODE-003: setTimeout/setInterval string
            SecurityCheck(
                id="TS-CODE-003",
                name="Code Injection via setTimeout String",
                category="code-injection",
                severity=RiskLevel.CRITICAL,
                description="setTimeout/setInterval with string argument is equivalent to eval",
                pattern=re.compile(r'(setTimeout|setInterval)\s*\(\s*["\x27]'),
                context_checks=[],
                suggestion="Use function references instead of strings for setTimeout/setInterval",
                cwe_id="CWE-95",
                owasp_category="A03:2021 - Injection",
                remediation_example="setTimeout(() => { /* safe code */ }, 1000);  // Function reference, not string",
                attack_vector="User input ��' setTimeout(string) ��' Code execution",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # TS-CMD-001: Command injection via child_process
            SecurityCheck(
                id="TS-CMD-001",
                name="Command Injection via child_process",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="child_process.exec() with shell string allows command injection",
                pattern=re.compile(r'\b(exec|execSync)\s*\('),
                context_checks=[self._is_fp_command],
                suggestion="Use execFile() or spawn() with argument arrays instead of shell strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="import { execFile } from 'child_process';\nexecFile('ls', ['-la', 'safeDir'], (err, stdout) => {});",
                attack_vector="User input ��' exec() ��' Shell injection ��' RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # TS-CMD-002: spawn shell mode
            SecurityCheck(
                id="TS-CMD-002",
                name="Command Injection via spawn with shell",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="spawn with shell:true enables shell injection attacks",
                pattern=re.compile(r'spawn\s*\([^)]*shell\s*:\s*true'),
                context_checks=[],
                suggestion="Use spawn with array arguments and shell:false (default)",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="spawn('ls', ['-la', dirPath], { shell: false });  // Default is false",
                attack_vector="User input ��' spawn(shell:true) ��' Shell injection ��' RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # TS-SQL-001: Template literal SQL injection
            SecurityCheck(
                id="TS-SQL-001",
                name="SQL Injection via Template Literal",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Template literals in SQL queries concatenate user input, enabling injection",
                pattern=re.compile(r'(?i)(query|execute|run)\s*\([^)]*`[^`]*\$\{|"SELECT|`SELECT|`INSERT|`UPDATE|`DELETE'),
                context_checks=[self._is_fp_sql],
                suggestion="Use parameterized queries with placeholders ($1, ?, :param)",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="await db.query('SELECT * FROM users WHERE id = $1', [userId]);",
                attack_vector="User input ��' Template literal in SQL ��' SQLi ��' Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-SQL-002: ORM raw query injection
            SecurityCheck(
                id="TS-SQL-002",
                name="SQL Injection via ORM Raw Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="ORM raw/unsafe queries bypass parameterization and allow injection",
                pattern=re.compile(r'(?i)(raw\s*\(|$queryRaw\s*\(|createQueryRunner|query\s*\(["\x27`])'),
                context_checks=[self._is_fp_orm_raw],
                suggestion="Use ORM query builder methods or parameterized raw queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Prisma safe query:\nconst users = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;",
                attack_vector="User input ��' ORM raw query ��' SQLi ��' Database export",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-SQL-003: Second-order SQL injection
            SecurityCheck(
                id="TS-SQL-003",
                name="Second-Order SQL Injection",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Stored user input used in later SQL queries without re-parameterization",
                pattern=re.compile(r'(?i)(SELECT\s+.*FROM\s+\w+\s+WHERE\s+\w+\s*=\s*["\x27`]\s*["\x27`]?\s*\+\s*\w+|INSERT\s+INTO.*VALUES\s*\(.*\$)'),
                context_checks=[self._is_fp_second_order],
                suggestion="Always parameterize queries even when reading previously stored data",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="db.query('SELECT * FROM logs WHERE data = $1', [storedValue]);  // Always parameterize",
                attack_vector="Stored malicious input ��' Second query without parameterization ��' SQLi",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-PATH-001: Path traversal
            SecurityCheck(
                id="TS-PATH-001",
                name="Path Traversal",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with unsanitized user input can access arbitrary files",
                pattern=re.compile(r'\bfs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|stat|statSync|mkdir|mkdirSync|readdir|readdirSync|rm|rmSync|rmdir|rmdirSync)\s*\('),
                context_checks=[self._is_fp_file_op],
                suggestion="Validate paths against an allowed directory. Use path.resolve() and check prefix",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const safePath = path.resolve(allowedDir, userInput);\nif (!safePath.startsWith(allowedDir)) throw new Error('Invalid path');",
                attack_vector="User input ��' File path ��' Arbitrary file read/write ��' Data breach / RCE",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # TS-PATH-002: Zip slip / archive traversal
            SecurityCheck(
                id="TS-PATH-002",
                name="Path Traversal via Archive Extraction (Zip Slip)",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="Extracting archive entries without path validation can overwrite files via ../",
                pattern=re.compile(r'(extractAllTo|extractEntry|Entries\s*\(|entries\s*\{)'),
                context_checks=[self._is_fp_zip_slip],
                suggestion="Validate each extracted path is within the target directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const resolved = path.resolve(extractDir, entryPath);\nif (!resolved.startsWith(path.resolve(extractDir))) throw new Error('Zip slip');",
                attack_vector="Malicious archive ../entries ��' File overwrite outside target dir ��' RCE",
                mitre_technique="T1565.001 - Data Manipulation: Stored Data Manipulation",
            ),
            # TS-SSRF-001: Server-Side Request Forgery
            SecurityCheck(
                id="TS-SSRF-001",
                name="Server-Side Request Forgery (SSRF)",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="HTTP requests with user-controlled URLs can target internal services",
                pattern=re.compile(r'\b(fetch|axios\.(get|post|put|delete|patch|head|request|all)|got|superagent|request|node-fetch|undici\.request)\s*\('),
                context_checks=[self._is_fp_url],
                suggestion="Use a URL allowlist. Validate hostname resolves to an external IP only",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="const allowedHosts = ['api.trusted.com'];\nconst host = new URL(url).hostname;\nif (!allowedHosts.includes(host)) throw new Error('Forbidden');",
                attack_vector="User input ��' HTTP client ��' Internal network scan / Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # TS-AUTH-001: JWT algorithm confusion
            SecurityCheck(
                id="TS-AUTH-001",
                name="JWT Algorithm Confusion",
                category="authentication",
                severity=RiskLevel.CRITICAL,
                description="JWT verification without algorithm restriction allows 'alg: none' attacks",
                pattern=re.compile(r'jwt\.(verify|decode)\s*\('),
                context_checks=[self._is_fp_jwt],
                suggestion="Always pass algorithms array to jwt.verify()",
                cwe_id="CWE-345",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="jwt.verify(token, secret, { algorithms: ['HS256'] });  // Restrict algorithms",
                attack_vector="JWT with 'alg: none' ��' Bypassed verification ��' Authentication bypass",
                mitre_technique="T1553.002 - Subvert Trust Controls: Code Signing",
            ),
            # TS-PROTO-001: Prototype pollution
            SecurityCheck(
                id="TS-PROTO-001",
                name="Prototype Pollution",
                category="prototype-pollution",
                severity=RiskLevel.CRITICAL,
                description="Merging user objects without prototype checks can pollute Object.prototype",
                pattern=re.compile(r'(__proto__|constructor\.prototype|Object\.prototype)'),
                context_checks=[self._is_fp_proto],
                suggestion="Use Object.create(null) or sanitize object keys before merge/assign",
                cwe_id="CWE-1321",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const safe = Object.create(null);\nsafe[userKey] = userValue;  // No prototype chain",
                attack_vector="User input with __proto__ ��' Object.assign/merge ��' Prototype pollution ��' All objects affected",
                mitre_technique="T1055 - Process Injection",
            ),
            # TS-PROTO-002: Unsafe merge / deep assign
            SecurityCheck(
                id="TS-PROTO-002",
                name="Prototype Pollution via Deep Merge",
                category="prototype-pollution",
                severity=RiskLevel.CRITICAL,
                description="Lodash _.merge / deepmerge with user input can pollute Object.prototype",
                pattern=re.compile(r'(_.merge|_.defaultsDeep|merge\s*\(|cloneDeep\s*\(|deepmerge|deepMerge)'),
                context_checks=[self._is_fp_deep_merge],
                suggestion="Use lodash.mergeWith with customizer that rejects '__proto__' keys",
                cwe_id="CWE-1321",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="import mergeWith from 'lodash.mergewith';\nmergeWith(target, source, (obj, src, key) => {\n  if (key === '__proto__' || key === 'constructor') throw new Error('Prototype pollution');\n});",
                attack_vector="User input ��' _.merge() ��' Prototype pollution ��' Application compromise",
                mitre_technique="T1055 - Process Injection",
            ),
            # TS-DESER-001: Unsafe JSON.parse
            SecurityCheck(
                id="TS-DESER-001",
                name="Unsafe Deserialization via JSON.parse",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="JSON.parse of user input with reviver callback can execute arbitrary logic",
                pattern=re.compile(r'JSON\.parse\s*\([^)]+,\s*'),
                context_checks=[self._is_fp_deser],
                suggestion="Avoid custom reviver functions that execute based on parsed values",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const data = JSON.parse(userInput);  // No reviver - safe\n// JSON.parse(userInput, (k, v) => eval(v)) is dangerous",
                attack_vector="User input ��' JSON.parse reviver ��' Code execution during parsing",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS - Significant security risk
        # ====================================================================

        checks.extend([
            # TS-CRYPTO-001: Math.random for security
            SecurityCheck(
                id="TS-CRYPTO-001",
                name="Insecure Random for Security Context",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Math.random() is predictable and should not be used for security tokens, CSRF, or IDs",
                pattern=re.compile(r'\bMath\.random\s*\('),
                context_checks=[self._is_fp_random],
                suggestion="Use crypto.randomBytes() (Node) or crypto.getRandomValues() (browser)",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import crypto from 'crypto';\nconst token = crypto.randomBytes(32).toString('hex');",
                attack_vector="Predictable token ��' Session hijacking / CSRF bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # TS-CRYPTO-002: Weak hash
            SecurityCheck(
                id="TS-CRYPTO-002",
                name="Weak Hashing Algorithm (MD5/SHA1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks",
                pattern=re.compile(r"(?i)createHash\s*\(\s*['\"](md5|sha1)['\"]"),
                context_checks=[self._is_fp_hash],
                suggestion="Use SHA-256 or SHA-3 for hashing; bcrypt/scrypt/argon2 for passwords",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const hash = crypto.createHash('sha256').update(data).digest('hex');",
                attack_vector="Collision attack on MD5/SHA1 ��' Signature forgery / Password bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # TS-CRYPTO-003: Timing attack
            SecurityCheck(
                id="TS-CRYPTO-003",
                name="Timing Attack via Insecure Comparison",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="String/length comparison of secrets leaks timing information",
                pattern=re.compile(r'(===|==)\s*((\w+Secret)|(password)|(token)|(apiKey)|(hmac)|(signature))|(compare\s*\(.*,\s*.*===)'),
                context_checks=[self._is_fp_timing],
                suggestion="Use constant-time comparison: timingSafeEqual for Node, subtle.constantTime for Web",
                cwe_id="CWE-208",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="import { timingSafeEqual } from 'crypto';\nif (timingSafeEqual(Buffer.from(a), Buffer.from(b))) { /* match */ }",
                attack_vector="Timing side-channel ��' Character-by-character secret recovery",
                mitre_technique="T1600.002 - Weaken Encryption: Reducing Key Space",
            ),
            # TS-CRYPTO-004: Weak encryption algorithm
            SecurityCheck(
                id="TS-CRYPTO-004",
                name="Weak Encryption Algorithm (DES/RC4)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="DES, 3DES, and RC4 are deprecated and easily broken",
                pattern=re.compile(r"(?i)(createCipheriv|createDecipheriv|createCipher|createDecipher)\s*\(\s*['\"](des|des-ede3|rc4|rc4-40)['\"]"),
                context_checks=[],
                suggestion="Use AES-256-GCM or ChaCha20-Poly1305 for encryption",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
                attack_vector="Weak cipher used ��' Plaintext recovery by attacker",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # TS-NOSQL-001: NoSQL injection
            SecurityCheck(
                id="TS-NOSQL-001",
                name="NoSQL Injection (MongoDB operators)",
                category="nosql-injection",
                severity=RiskLevel.HIGH,
                description="User input with $ operators ($gt, $ne, $where) can bypass authentication in MongoDB",
                pattern=re.compile(r'(?i)(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne)\s*\(\s*\{[^}]*\$\w+'),
                context_checks=[self._is_fp_nosql],
                suggestion="Validate and sanitize user input. Reject query operators ($, $gt, $ne)",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="const sanitized = Object.fromEntries(\n  Object.entries(body).filter(([k]) => !k.startsWith('$'))\n);\ndb.collection.find(sanitized);",
                attack_vector="User input with $ne operator ��' MongoDB query bypass ��' Authentication bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-POSTMSG-001: postMessage wildcard
            SecurityCheck(
                id="TS-POSTMSG-001",
                name="postMessage with Wildcard Origin",
                category="communication",
                severity=RiskLevel.HIGH,
                description="postMessage with '*' targetOrigin leaks data to any listening window",
                pattern=re.compile(r'postMessage\s*\([^,]+,\s*["\x27]\*["\x27]'),
                context_checks=[],
                suggestion="Always specify exact targetOrigin instead of wildcard '*'",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="targetWindow.postMessage(data, 'https://trusted-app.com');",
                attack_vector="Evil page listens for messages ��' Data leakage to unauthorized origin",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # TS-REDIR-001: Open redirect
            SecurityCheck(
                id="TS-REDIR-001",
                name="Open Redirect via User-Controlled URL",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="Redirecting to user-controlled URLs enables phishing attacks",
                pattern=re.compile(r'(window\.location\s*(=|\.href\s*=|\.replace\s*\()|res\.redirect\s*\(|router\.push\s*\()'),
                context_checks=[self._is_fp_redirect],
                suggestion="Validate redirect URLs against an allowlist of trusted domains",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const allowed = ['https://app.example.com'];\nif (allowed.includes(url)) window.location.href = url;\nelse window.location.href = '/fallback';",
                attack_vector="Evil redirect URL ��' Phishing page ��' Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # TS-SECRET-001: Hardcoded secrets
            SecurityCheck(
                id="TS-SECRET-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.HIGH,
                description="Hardcoded API keys, tokens, passwords, and secrets in source code",
                pattern=re.compile(r'(?i)(api[_-]?key|secret[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key|secret[_-]?access|private[_-]?key|ssh[_-]?key|aws[_-]?secret|gcp[_-]?key|azure[_-]?key)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variables, secrets manager (Vault, AWS Secrets Manager), or .env",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="const apiKey = process.env.API_KEY;\n// Never hardcode: const apiKey = 'sk-...'",
                attack_vector="Source leak (GitHub) ��' Hardcoded secret exposed ��' Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # TS-SECRET-002: Hardcoded JWT secret
            SecurityCheck(
                id="TS-SECRET-002",
                name="Hardcoded JWT Secret",
                category="secrets",
                severity=RiskLevel.HIGH,
                description="JWT secret hardcoded in source allows token forgery",
                pattern=re.compile(r'(?i)(jwtSecret|jwt[_-]?secret|secretOrKey|SECRET)\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'),
                context_checks=[self._is_fp_secret],
                suggestion="Use environment variable or secrets manager for JWT secret",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="const jwtSecret = process.env.JWT_SECRET;\n// Never: const jwtSecret = 'mySuperSecretKey123'",
                attack_vector="Hardcoded JWT secret found ��' Forge any JWT token ��' Authentication bypass",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # TS-CORS-001: CORS misconfiguration
            SecurityCheck(
                id="TS-CORS-001",
                name="Overly Permissive CORS Policy",
                category="cors",
                severity=RiskLevel.HIGH,
                description="CORS with origin: true or Access-Control-Allow-Origin: * exposes API to all domains",
                pattern=re.compile(r"(origin\s*:\s*true|Access-Control-Allow-Origin\s*:\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"])"),
                context_checks=[self._is_fp_cors],
                suggestion="Specify exact allowed origins in an allowlist",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="app.use(cors({ origin: ['https://app.example.com', 'https://admin.example.com'] }));",
                attack_vector="Any domain can make API calls ��' CSRF + data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # TS-XXE-001: XXE
            SecurityCheck(
                id="TS-XXE-001",
                name="XML External Entity (XXE) Injection",
                category="xxe",
                severity=RiskLevel.HIGH,
                description="XML parsing without disabling external entities can expose files or enable SSRF",
                pattern=re.compile(r'(?i)(new\s+DOMParser|xml2js\.parseString|parse\s*\(|libxmljs|sax-parser|fast-xml-parser)'),
                context_checks=[self._is_fp_xxe],
                suggestion="Disable external entities and DTD processing when parsing XML",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="import { XMLParser } from 'fast-xml-parser';\nconst parser = new XMLParser({ processEntities: false, ignoreAttributes: false });",
                attack_vector="Malicious XML with external entity ��' File read / SSRF",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # TS-REDOS-001: ReDoS
            SecurityCheck(
                id="TS-REDOS-001",
                name="Regular Expression Denial of Service (ReDoS)",
                category="redos",
                severity=RiskLevel.HIGH,
                description="Regex with nested quantifiers (/(a+)+$/) can cause catastrophic backtracking",
                pattern=re.compile(r'(?i)(new\s+RegExp|\.match|\.replace|\.search|\.split)\s*\(\s*["\x27/]'),
                context_checks=[self._is_fp_redos],
                suggestion="Avoid nested quantifiers. Use re2 or test with redos-detector library",
                cwe_id="CWE-1333",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Instead of /(\\w+)+$/, use /^\\w+$/\nconst safeRegex = /^[a-zA-Z]+$/;  // No nested groups",
                attack_vector="Crafted input triggers backtracking ��' CPU exhaustion ��' DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # TS-CSRF-001: Missing CSRF protection
            SecurityCheck(
                id="TS-CSRF-001",
                name="Missing CSRF Protection in Express",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="Express app without csurf or csrf middleware is vulnerable to CSRF",
                pattern=re.compile(r"app\.use\s*\(|router\.use\s*\("),
                context_checks=[self._is_fp_csrf],
                suggestion="Use csurf middleware or implement double-submit cookie pattern",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="import csurf from 'csurf';\napp.use(csurf({ cookie: true }));",
                attack_vector="Attacker forges authenticated request ��' State-changing operation performed",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-CSP-001: CSP bypass
            SecurityCheck(
                id="TS-CSP-001",
                name="CSP Bypass via JSONP / Script Gadgets",
                category="csp",
                severity=RiskLevel.HIGH,
                description="Allowing 'unsafe-inline' or 'unsafe-eval' in CSP defeats its purpose",
                pattern=re.compile(r"(?i)(unsafe-inline|unsafe-eval|script-src.*['\"]\*['\"]|default-src\s+['\"]\*['\"])"),
                context_checks=[self._is_fp_dev],
                suggestion="Use strict CSP with nonces or hashes. Avoid unsafe-inline and unsafe-eval",
                cwe_id="CWE-1021",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}';",
                attack_vector="CSP with unsafe-inline ��' XSS not blocked by CSP",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # TS-UPLOAD-001: Unsafe file upload
            SecurityCheck(
                id="TS-UPLOAD-001",
                name="Unrestricted File Upload",
                category="file-upload",
                severity=RiskLevel.HIGH,
                description="File upload without extension/content-type validation can lead to RCE",
                pattern=re.compile(r"(multer|formidable|busboy|multiparty|upload|saveFile|writeFile)\s*\([^)]*\bfile\b"),
                context_checks=[self._is_fp_upload],
                suggestion="Validate file extension, MIME type, and content. Store outside webroot",
                cwe_id="CWE-434",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="const allowed = ['.jpg', '.png', '.pdf'];\nconst ext = path.extname(file.name);\nif (!allowed.includes(ext)) throw new Error('Invalid file type');",
                attack_vector="Upload .php/.aspx file ��' Web shell uploaded ��' RCE",
                mitre_technique="T1505.003 - Server Software Component: Web Shell",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS - Moderate security risk
        # ====================================================================

        checks.extend([
            # TS-WS-001: Insecure WebSocket
            SecurityCheck(
                id="TS-WS-001",
                name="Insecure WebSocket Connection (ws://)",
                category="websocket",
                severity=RiskLevel.MEDIUM,
                description="Using ws:// exposes all WebSocket traffic to interception over network",
                pattern=re.compile(r'new\s+WebSocket\s*\(\s*["\x27]ws://'),
                context_checks=[],
                suggestion="Use wss:// (WebSocket Secure) for encrypted communication",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="const ws = new WebSocket('wss://example.com/socket');  // Encrypted",
                attack_vector="Network attacker intercepts ws:// traffic ��' Data injection / theft",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # TS-STORAGE-001: localStorage sensitive data
            SecurityCheck(
                id="TS-STORAGE-001",
                name="Sensitive Data in localStorage",
                category="storage",
                severity=RiskLevel.MEDIUM,
                description="Storing tokens, passwords, or secrets in localStorage is XSS-accessible",
                pattern=re.compile(r'localStorage\.setItem\s*\(\s*["\x27](token|password|secret|key|auth|session|jwt|refresh)["\x27]'),
                context_checks=[],
                suggestion="Use httpOnly cookies or in-memory storage for sensitive data",
                cwe_id="CWE-312",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Use httpOnly, secure cookies set by server\n// Or in-memory variable: let authToken = null;",
                attack_vector="XSS vulnerability ��' localStorage read ��' Token theft",
                mitre_technique="T1555 - Credentials from Password Stores",
            ),
            # TS-STORAGE-002: Insecure cookies
            SecurityCheck(
                id="TS-STORAGE-002",
                name="Insecure Cookie Configuration",
                category="storage",
                severity=RiskLevel.MEDIUM,
                description="Cookies without httpOnly, secure, or SameSite flags are vulnerable to theft",
                pattern=re.compile(r'''res\.cookie\s*\(\s*['\"]|cookieParser|cookie\(|express\.session\s*\(\s*\{'''),
                context_checks=[self._is_fp_cookie],
                suggestion="Set httpOnly: true, secure: true, sameSite: 'strict' on all cookies",
                cwe_id="CWE-614",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict'\n});",
                attack_vector="Missing cookie flags ��' XSS reads cookie / CSRF uses cookie",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # TS-DEPR-001: Deprecated APIs
            SecurityCheck(
                id="TS-DEPR-001",
                name="Deprecated DOM API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated APIs like document.all, document.domain, event.layerX/Y",
                pattern=re.compile(r'\b(document\.(all|domain|layers(all|left|top)|implementation)|event\.(layerX|layerY|which))\b'),
                context_checks=[],
                suggestion="Replace with modern alternatives. document.domain is a security risk",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Replace document.domain with postMessage + origin verification",
                attack_vector="Deprecated API may bypass security boundaries",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-ERR-001: Empty catch
            SecurityCheck(
                id="TS-ERR-001",
                name="Empty Catch Block (Swallowed Error)",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Empty catch blocks silently hide errors and failures",
                pattern=re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}'),
                context_checks=[],
                suggestion="Log errors and re-throw or handle appropriately",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="try { ... } catch (error) {\n  console.error('Operation failed:', error);\n  throw error;\n}",
                attack_vector="Error hidden ��' Security mechanism silently fails",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # TS-ERR-002: Unhandled promise rejection
            SecurityCheck(
                id="TS-ERR-002",
                name="Unhandled Promise Rejection via .catch()",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Promises without .catch() will silently swallow rejections in older Node versions",
                pattern=re.compile(r'\.then\s*\(\s*[^)]*\s*\)(?!\s*\.catch)'),
                context_checks=[self._is_fp_promise],
                suggestion="Always add .catch() to promises or use try/catch with async/await",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="await riskyOperation().catch(err => {\n  console.error('Operation failed:', err);\n  throw err;\n});",
                attack_vector="Promise rejection unhandled ��' Process crash / undefined behavior",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # TS-TYPE-001: Unsafe any
            SecurityCheck(
                id="TS-TYPE-001",
                name="Unsafe 'any' Type Usage",
                category="type-safety",
                severity=RiskLevel.MEDIUM,
                description="Using 'any' disables TypeScript's type checking for that variable",
                pattern=re.compile(r':\s*any\b'),
                context_checks=[self._is_fp_type_safety],
                suggestion="Use specific types, 'unknown' with type guards, or generics",
                cwe_id="CWE-704",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="function process<T>(input: T): T { return input; }  // Generic\n// Instead of: function process(input: any): any",
                attack_vector="any type ��' Type confusion ��' Logic bugs / Security bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-TYPE-002: @ts-ignore
            SecurityCheck(
                id="TS-TYPE-002",
                name="TypeScript @ts-ignore Directive",
                category="type-safety",
                severity=RiskLevel.MEDIUM,
                description="@ts-ignore suppresses compile errors and can hide type vulnerabilities",
                pattern=re.compile(r'\/\/\s*@ts-ignore'),
                context_checks=[],
                suggestion="Fix the underlying type error instead of suppressing it",
                cwe_id="CWE-704",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove @ts-ignore and fix the type error\nconst result = await db.query<User>(sql, params);",
                attack_vector="Type error hidden ��' Runtime type confusion",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-TYPE-003: @ts-nocheck
            SecurityCheck(
                id="TS-TYPE-003",
                name="TypeScript @ts-nocheck Directive",
                category="type-safety",
                severity=RiskLevel.MEDIUM,
                description="@ts-nocheck disables all type checking for the entire file",
                pattern=re.compile(r'\/\/\s*@ts-nocheck'),
                context_checks=[],
                suggestion="Enable strict mode and fix errors incrementally",
                cwe_id="CWE-704",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove @ts-nocheck and enable strict mode\n// tsconfig.json: \"strict\": true",
                attack_vector="Full file type unchecked ��' Undetected type vulnerabilities",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-DEBUG-001: debugger
            SecurityCheck(
                id="TS-DEBUG-001",
                name="Debugger Statement in Production Code",
                category="debug",
                severity=RiskLevel.MEDIUM,
                description="Debugger statements halt execution and should not be in production",
                pattern=re.compile(r'\bdebugger\s*;?'),
                context_checks=[self._is_fp_test],
                suggestion="Remove debugger statements before production deployment",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="// Remove 'debugger;' statements before production",
                attack_vector="debugger halts JS execution ��' Denial of service",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # TS-INJECT-001: Template injection
            SecurityCheck(
                id="TS-INJECT-001",
                name="Server-Side Template Injection (SSTI)",
                category="template-injection",
                severity=RiskLevel.MEDIUM,
                description="Passing user input to template engines (EJS, Handlebars, Pug) can enable SSTI",
                pattern=re.compile(r'(?i)(res\.render|this\.render|template\s*\(|compile\s*\(|ejs|handlebars|pug|nunjucks|liquid|mustache).*(render|compile)'),
                context_checks=[self._is_fp_ssti],
                suggestion="Pass user input as template variables only, never as template code",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Safe: pass as variable\nres.render('page', { message: userInput });\n// Dangerous: res.render('page', userInput);",
                attack_vector="User input in template ��' SSTI ��' RCE",
                mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
            ),
            # TS-AUTH-003: Missing auth middleware
            SecurityCheck(
                id="TS-AUTH-003",
                name="Route Without Authentication Middleware",
                category="authentication",
                severity=RiskLevel.MEDIUM,
                description="Route handler without auth middleware can be accessed by unauthenticated users",
                pattern=re.compile(r'router\.(get|post|put|delete|patch)\s*\(\s*["\x27][^"\x27]*["\x27]\s*,\s*\(?\s*(req|async\s+req)'),
                context_checks=[self._is_fp_auth_middleware],
                suggestion="Apply authentication middleware to all protected routes",
                cwe_id="CWE-862",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="router.get('/admin/users', authenticate, async (req, res) => { ... });",
                attack_vector="No auth on route ��' Unauthenticated access to sensitive endpoint",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # TS-AUTH-004: Weak password policy
            SecurityCheck(
                id="TS-AUTH-004",
                name="Weak Password Policy Configuration",
                category="authentication",
                severity=RiskLevel.MEDIUM,
                description="Minimal password length < 8 or no complexity requirements are insecure",
                pattern=re.compile(r'(minLength\s*[:=]\s*[0-7]|minlength\s*[:=]\s*[0-7]|password.*length.*[0-7]|passport.*Local)'),
                context_checks=[self._is_fp_test],
                suggestion="Enforce minimum 8 characters with complexity requirements",
                cwe_id="CWE-521",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="password: { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 }",
                attack_vector="Weak password policy ��' Brute-force / dictionary attack succeeds",
                mitre_technique="T1110 - Brute Force",
            ),
        ])

        # ====================================================================
        # LOW CHECKS - Informational / Code Quality
        # ====================================================================

        checks.extend([
            # TS-LOG-001: console.log
            SecurityCheck(
                id="TS-LOG-001",
                name="Console Statement in Production Code",
                category="logging",
                severity=RiskLevel.LOW,
                description="Console statements may leak sensitive data to browser console or stdout",
                pattern=re.compile(r'\bconsole\.(log|warn|error|info|debug|trace|dir|table)\s*\('),
                context_checks=[self._is_fp_console],
                suggestion="Use a proper logging library (winston, pino) instead of console",
                cwe_id="CWE-489",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="import logger from './logger';\nlogger.info('Operation completed');",
                attack_vector="Console output in production ��' Sensitive data exposure",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # TS-DOC-001: Missing JSDoc
            SecurityCheck(
                id="TS-DOC-001",
                name="Missing JSDoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Exported functions/classes should be documented with JSDoc",
                pattern=re.compile(r'(?im)^\s*export\s+(function|class|const|let|var|async\s+function)\s+\w+'),
                context_checks=[self._is_fp_jsdoc],
                suggestion="Add JSDoc comments explaining purpose, params, and returns",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/**\n * Description of the function\n * @param userId - The user ID\n * @returns User object\n */",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # TS-MAGIC-001: Magic numbers
            SecurityCheck(
                id="TS-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(?:if|while|for|return|case|&&|\|\||!==|===|>=|<=|>|<|==)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_fp_magic],
                suggestion="Define magic numbers as named constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const MAX_LOGIN_ATTEMPTS = 5;\nconst SESSION_TIMEOUT_MS = 3600000;\nif (attempts >= MAX_LOGIN_ATTEMPTS) { lockAccount(); }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # TS-COMM-001: TODO comments
            SecurityCheck(
                id="TS-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security measures",
                pattern=re.compile(r'(?i)\/\/\s*TODO|<!--\s*TODO|TODO:'),
                context_checks=[self._is_fp_dev],
                suggestion="Address TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Address TODOs before shipping\n// TODO: Add input validation  ->  Add during development sprint",
                attack_vector="Unaddressed TODO may be a missing security check",
                mitre_technique="N/A",
            ),
            # TS-COMM-002: FIXME comments
            SecurityCheck(
                id="TS-COMM-002",
                name="FIXME Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="FIXME comments indicate known bugs needing resolution",
                pattern=re.compile(r'(?i)(FIXME|HACK|XXX|BUG|TEMP)\s*[:!]?'),
                context_checks=[self._is_fp_dev],
                suggestion="Address FIXME/HACK items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Instead of // FIXME: this is terrible\nrequestValidator.validate(input);  // Properly implemented",
                attack_vector="Known bug left unaddressed could be a vulnerability",
                mitre_technique="N/A",
            ),
            # TS-QUAL-001: Nested callbacks
            SecurityCheck(
                id="TS-QUAL-001",
                name="Deeply Nested Callbacks (Callback Hell)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="More than 3 levels of nesting indicates poor error handling patterns",
                pattern=re.compile(r'(?s)\{[\s\S]*?\{[\s\S]*?\{[\s\S]*?\{[\s\S]*?function'),
                context_checks=[self._is_fp_test],
                suggestion="Use async/await or Promise chains to flatten nested callbacks",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="async function process() {\n  const a = await step1();\n  const b = await step2(a);\n  return step3(b);\n}",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # TS-QUAL-002: Long function warning
            SecurityCheck(
                id="TS-QUAL-002",
                name="Excessive Function Length",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Functions over 80 lines are harder to audit for security",
                pattern=re.compile(r'(?i)^\s*export\s+(async\s+)?function\s+\w+'),
                context_checks=[self._is_fp_test],
                suggestion="Break long functions into smaller, focused functions",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Break into: validate(), process(), notify()\nfunction processUser(user) {\n  validate(user);\n  const result = transform(user);\n  notify(result);\n}",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # TS-QUAL-003: Duplicate string literals
            SecurityCheck(
                id="TS-QUAL-003",
                name="Duplicate String Literal",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Repeated string literals should be constants for consistency",
                pattern=re.compile(r'["\x27][A-Za-z0-9_]{10,}["\x27]'),
                context_checks=[self._is_fp_dup_string],
                suggestion="Extract repeated strings as named constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="const API_ENDPOINT = '/api/v2/users';\n// Instead of '/api/v2/users' appearing 5 times",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # TS-SECRET-003: Hardcoded IP address
            SecurityCheck(
                id="TS-SECRET-003",
                name="Hardcoded IP Address or Host",
                category="secrets",
                severity=RiskLevel.LOW,
                description="Hardcoded IP addresses may leak internal network topology",
                pattern=re.compile(r'["\x27](https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\x27]'),
                context_checks=[self._is_fp_ip],
                suggestion="Use environment variables or config files for IP addresses",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="const DB_HOST = process.env.DB_HOST || 'localhost';",
                attack_vector="Source code leak exposes internal IP addresses",
                mitre_technique="T1590 - Gather Victim Network Information",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect which frameworks are used in the codebase."""
        frameworks = []

        if file_path.suffix == '.tsx' or 'react' in content.lower():
            if re.search(r'import\s+React|from\s+[\'"]react[\'"]|jsx|tsx', content):
                frameworks.append('react')

        if re.search(r'import\s+.*from\s+[\'"]vue[\'"]|v-bind|v-model|v-if|v-for', content):
            frameworks.append('vue')

        if re.search(r'import\s+.*from\s+[\'"]@angular|@Component|@NgModule|@Injectable', content):
            frameworks.append('angular')

        if re.search(r'import\s+.*from\s+[\'"]express[\'"]|app\.(get|post|put|delete)|router\.', content):
            frameworks.append('express')

        if re.search(r'import\s+.*from\s+[\'"]@nestjs|@Controller|@Module|@Injectable|@Get|@Post', content):
            frameworks.append('nestjs')

        if re.search(r'import\s+.*from\s+[\'"]next[\'"]|getServerSideProps|getStaticProps|getInitialProps', content):
            frameworks.append('nextjs')

        if re.search(r'import\s+.*from\s+[\'"]prisma[\'"]|@prisma|\.\$queryRaw|\.\$executeRaw', content):
            frameworks.append('prisma')

        if re.search(r'import\s+.*from\s+[\'"]typeorm[\'"]|EntityRepository|getRepository|@Entity|getConnection', content):
            frameworks.append('typeorm')

        self._framework_cache[file_path.name] = frameworks
        return frameworks

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
    # TAINT ANALYSIS
    # ====================================================================

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run taint tracking analysis to detect data flow from sources to sinks."""
        sources = {
            'req.query': 'URL Query Parameter',
            'req.body': 'Request Body',
            'req.params': 'URL Route Parameter',
            'req.headers': 'HTTP Header',
            'req.cookies': 'Cookie',
            'window.location': 'URL Location',
            'new URL(': 'URL Constructor',
            'location.search': 'Query String',
            'location.hash': 'URL Hash',
            'document.cookie': 'Document Cookie',
            'process.env': 'Environment Variable',
            'localStorage.getItem': 'LocalStorage Read',
            'sessionStorage.getItem': 'SessionStorage Read',
        }

        sinks = {
            'innerHTML': 'DOM HTML Assignment',
            'outerHTML': 'DOM HTML Assignment',
            'insertAdjacentHTML': 'DOM HTML Insertion',
            'document.write': 'Document Write',
            'eval(': 'Code Execution',
            'Function(': 'Code Execution',
            'exec(': 'Shell Execution',
            'execSync(': 'Shell Execution',
            'query(': 'SQL Query',
            'execute(': 'SQL Execution',
            'raw(': 'Raw SQL Query',
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
        """Add a taint analysis finding."""
        finding = Finding(
            file=str(result.file_path),
            line=line_num,
            column=0,
            issue_type="TS-TAINT-001",
            message=f"[Taint Flow] Data from {source_type} reaches {sink_type} without sanitization",
            risk_level=RiskLevel.HIGH,
            code_snippet=line.strip(),
            suggestion="Sanitize data between source and sink. Use parameterization, escaping, or validation",
        )
        result.findings.append(finding)

    # ====================================================================
    # CROSS-LINE ANALYSIS
    # ====================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Run cross-line pattern detection for multi-line vulnerabilities."""
        self._check_multiline_sql(content, lines, result)
        self._check_promise_chaining(content, lines, result)
        self._check_try_catch_wrapping(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection across multiple lines."""
        sql_keywords = re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+')
        concat_pattern = re.compile(r'\+\s*\w+|\w+\s*\+')

        for i, line in enumerate(lines):
            if sql_keywords.search(line):
                for j in range(i, min(i + 5, len(lines))):
                    if concat_pattern.search(lines[j]) and 'query(' in lines[j]:
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="TS-SQL-004",
                            name="Multi-line SQL Injection",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with string concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries instead of string concatenation",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="const sql = `SELECT * FROM users WHERE id = $1`;\ndb.query(sql, [userId]);",
                            attack_vector="Multi-line SQL concat ��' Injection vector ��' Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_promise_chaining(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for missing error handling in promise chains."""
        for i, line in enumerate(lines, 1):
            if '.then(' in line:
                has_catch = False
                for j in range(i, min(i + 3, len(lines) + 1)):
                    if j < len(lines) and '.catch(' in lines[j]:
                        has_catch = True
                        break
                if not has_catch:
                    self._add_finding(result, i, line, SecurityCheck(
                        id="TS-ERR-003",
                        name="Promise Chain Missing Error Handling",
                        category="error-handling",
                        severity=RiskLevel.MEDIUM,
                        description="Promise chain without .catch() can swallow rejections",
                        pattern=re.compile(r''),
                        suggestion="Add .catch() to handle promise rejections",
                        cwe_id="CWE-391",
                        owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                        remediation_example="asyncFunction()\n  .then(result => process(result))\n  .catch(err => console.error('Failed:', err));",
                        attack_vector="Unhandled promise rejection ��' Silent failure / Process crash",
                        mitre_technique="T1564 - Hide Artifacts",
                    ))
                    break

    def _check_try_catch_wrapping(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for missing try/catch around sensitive operations."""
        sensitive_ops = ['JSON.parse(', 'fetch(', 'axios.', 'query(', 'execute(', 'writeFile', 'readFile']

        for i, line in enumerate(lines, 1):
            for op in sensitive_ops:
                if op in line and 'try' not in line:
                    has_handling = False
                    prev_lines = lines[:i]
                    for prev in reversed(prev_lines[-3:]):
                        if 'try' in prev or 'catch' in prev:
                            has_handling = True
                            break
                    if not has_handling:
                        self._add_finding(result, i, line, SecurityCheck(
                            id="TS-ERR-004",
                            name="Sensitive Operation Without try/catch",
                            category="error-handling",
                            severity=RiskLevel.MEDIUM,
                            description=f"Sensitive operation ({op}) without error handling may crash on failure",
                            pattern=re.compile(r''),
                            suggestion="Wrap sensitive operations in try/catch blocks",
                            cwe_id="CWE-391",
                            owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                            remediation_example="try {\n  const data = JSON.parse(userInput);\n} catch (error) {\n  console.error('Invalid input:', error);\n  throw new BadRequestError('Invalid data');\n}",
                            attack_vector="No error handling ��' Crash / DoS",
                            mitre_technique="T1499 - Endpoint Denial of Service",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_fp_innerhtml(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if innerHTML usage is a false positive (static string)."""
        if '+' in line:
            return False
        if re.search(r'innerHTML\s*=\s*["\x27][^"\x27]*["\x27]\s*[;]?$', line.strip()):
            return True
        if 'DOMPurify' in line:
            return True
        return False

    def _is_fp_react_sanitized(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if React dangerouslySetInnerHTML is sanitized."""
        if 'DOMPurify' in line or 'sanitize' in line.lower() or 'trusted' in line.lower():
            return True
        if 'bypassSecurityTrustHtml' in line:
            return True
        return False

    def _is_fp_vue_sanitized(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if Vue v-html is sanitized."""
        if 'DOMPurify' in line or 'sanitize' in line.lower():
            return True
        if re.search(r'v-html\s*=\s*["\x27]\s*["\x27]', line):
            return True
        if re.search(r'v-html\s*=\s*["\x27]\d+["\x27]', line):
            return True
        return False

    def _is_fp_angular_sanitized(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if Angular innerHTML binding is safe."""
        if 'bypassSecurityTrustHtml' in line or 'sanitize' in line.lower():
            return True
        return False

    def _is_fp_doc_write(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if document.write is false positive."""
        if re.search(r'document\.write\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_script_elem(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if script element creation is safe."""
        if 'sanitize' in line.lower() or 'validate' in line.lower():
            return True
        return False

    def _is_fp_css_injection(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if CSS injection is false positive."""
        if re.search(r'\.style\.\w+\s*=\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'cssText' in line and 'sanitize' in line:
            return True
        return False

    def _is_fp_eval(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if eval usage is safe."""
        if re.search(r'eval\s*\(\s*["\x27][^"\x27]*["\x27]\s*\)', line):
            return True
        return False

    def _is_fp_function_ctor(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if Function constructor usage is safe."""
        if re.search(r'new\s+Function\s*\(\s*["\x27][^"\x27]*["\x27]', line):
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
        """Check if SQL usage is safe."""
        if re.search(r'(query|execute)\s*\(\s*["\x27][^"\x27]*["\x27]\s*,', line):
            return True
        if 'parameterized' in line.lower() or 'prepared' in line.lower():
            return True
        return False

    def _is_fp_orm_raw(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if ORM raw query is safe."""
        if 'Parameterized' in line or 'sanitize' in line.lower():
            return True
        if re.search(r'\$queryRaw\s*`[^`]*\$', line):
            return True
        return False

    def _is_fp_second_order(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if second-order SQL is false positive."""
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        return False

    def _is_fp_file_op(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if file operation is safe."""
        if '+' in line and '"/' in line:
            return False
        if re.search(r'(readFile|writeFile|readFileSync|writeFileSync)\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            if '+' not in line:
                return True
        if 'path.resolve' in line or 'path.join' in line:
            return True
        return False

    def _is_fp_zip_slip(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if zip extraction is safe."""
        if 'resolve' in line or 'startsWith' in line:
            return True
        return False

    def _is_fp_url(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if URL/source is safe."""
        if re.search(r'(fetch|axios)\s*\(\s*["\x27]https?://', line):
            return True
        if 'allowedDomains' in line or 'allowedHosts' in line:
            return True
        return False

    def _is_fp_jwt(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JWT usage is safe."""
        if 'algorithms' in line and 'verify' in line:
            return True
        return False

    def _is_fp_proto(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if prototype manipulation is safe."""
        if 'Object.create(null)' in line or 'hasOwnProperty' in line:
            return True
        return False

    def _is_fp_deep_merge(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if deep merge is safe."""
        if 'customizer' in line or 'mergeWith' in line or 'sanitize' in line.lower():
            return True
        if '__proto__' in content.lower():
            return True
        return False

    def _is_fp_deser(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if deserialization is safe."""
        if re.search(r'JSON\.parse\s*\(\s*["\x27][^"\x27]*["\x27]', line):
            return True
        if 'reviver' not in line:
            return True
        return False

    def _is_fp_random(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if Math.random usage is acceptable."""
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower() or 'color' in line.lower():
            return True
        if re.search(r'Math\.random\s*\(\s*\)\s*[\*\+-]', line):
            return True
        return False

    def _is_fp_hash(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if hash usage is acceptable."""
        if 'sha256' in line or 'sha384' in line or 'sha512' in line:
            return True
        if 'checksum' in line.lower() or 'non-security' in line.lower():
            return True
        return False

    def _is_fp_timing(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if comparison is constant-time."""
        if 'timingSafeEqual' in content or 'timingSafeEqual' in line:
            return True
        if 'subtle.constantTime' in content:
            return True
        return False

    def _is_fp_nosql(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if NoSQL query is safe."""
        if 'sanitize' in line or 'escape' in line:
            return True
        return False

    def _is_fp_redirect(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if redirect is safe."""
        if re.search(r'(window\.location|res\.redirect)\s*=\s*["\x27]https?://', line):
            return True
        if 'allowedDomains' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_fp_secret(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if secret is false positive."""
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if '.env' in line or 'process.env' in line:
            return True
        return False

    def _is_fp_cors(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if CORS config is development."""
        if 'development' in line.lower() or 'localhost' in line.lower():
            return True
        if 'allowedOrigins' in line:
            return True
        return False

    def _is_fp_xxe(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if XML parsing is safe."""
        if 'noEntities' in line or 'disableEntities' in line or 'safeParse' in line:
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

    def _is_fp_dev(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if development config."""
        if 'development' in line.lower() or 'dev' in line.lower() or 'localhost' in line.lower():
            return True
        return False

    def _is_fp_upload(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if file upload is safe."""
        if 'extname' in content or 'mimetype' in content.lower() or 'validate' in content.lower():
            return True
        return False

    def _is_fp_cookie(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if cookie is secure."""
        if 'httpOnly' in line or 'secure' in line or 'sameSite' in line:
            return True
        return False

    def _is_fp_promise(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if promise has error handling."""
        if '.catch' in line:
            return True
        return False

    def _is_fp_type_safety(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if type false positive."""
        if '.d.ts' in str(getattr(self, '_current_path', '')):
            return True
        return False

    def _is_fp_test(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if test file."""
        if 'test' in line.lower() or 'spec' in line.lower() or 'mock' in line.lower():
            return True
        return False

    def _is_fp_ssti(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if SSTI is false positive."""
        if re.search(r'render\s*\(\s*["\x27][^"\x27]*["\x27]\s*,', line):
            return True
        return False

    def _is_fp_auth_middleware(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if route has auth middleware."""
        if 'authenticate' in line or 'auth' in line.lower() or 'isAuthenticated' in line:
            return True
        return False

    def _is_fp_console(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if console is in test."""
        if 'test' in line.lower() or 'spec' in line.lower():
            return True
        return False

    def _is_fp_jsdoc(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if JSDoc exists."""
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

    def _is_fp_magic(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if magic number is acceptable."""
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const' in line or 'let' in line or 'var' in line:
            return True
        return False

    def _is_fp_ip(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if IP is false positive."""
        if 'example' in line.lower() or 'localhost' in line.lower() or '0.0.0.0' in line:
            return True
        if re.search(r'127\.0\.0\.1|255\.255\.255\.255', line):
            return True
        return False

    def _is_fp_dup_string(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if string false positive."""
        return False

    # Custom property for path in context checks
    _current_path: Path = Path("")
