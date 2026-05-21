"""Elite static analyzer for C# code with comprehensive security checks."""

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
    """A 'security unit test' for C# code."""
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


class CSharpAnalyzer(BaseAnalyzer):
    """Elite static analyzer for C# code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "csharp"

    def get_supported_extensions(self) -> List[str]:
        return [".cs", ".csx"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a C# file and return results."""
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
            # CS-SQL-001: SqlCommand concat
            SecurityCheck(
                id="CS-SQL-001",
                name="SQL Injection via String Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in SqlCommand allows SQL injection",
                pattern=re.compile(r'(?i)(SqlCommand|SqlDataAdapter|DbCommand)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use parameterized queries with @param placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="using var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn);\ncmd.Parameters.AddWithValue(\"@id\", userId);",
                attack_vector="User input -> SQL string concat -> SQLi -> Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SQL-002: String interpolation in SQL
            SecurityCheck(
                id="CS-SQL-002",
                name="SQL Injection via String Interpolation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String interpolation in SQL queries allows injection attacks",
                pattern=re.compile(r'(?i)(SqlCommand|DbCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(\s*\$"[^"]*\{'),
                context_checks=[],
                suggestion="Use parameterized queries with @param placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="using var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn);\ncmd.Parameters.AddWithValue(\"@id\", userId);",
                attack_vector="User input in $ string interpolation -> SQLi -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SQL-003: EntityFramework FromSqlRaw
            SecurityCheck(
                id="CS-SQL-003",
                name="SQL Injection via EntityFramework FromSqlRaw",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="FromSqlRaw/ExecuteSqlRaw with string concatenation enables SQL injection",
                pattern=re.compile(r'(?i)\.(FromSqlRaw|ExecuteSqlRaw|FromSqlInterpolated|ExecuteSqlInterpolated)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use FromSqlInterpolated with interpolated string parameterization",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="var users = await db.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE id = {userId}\").ToListAsync();\n// Never: FromSqlRaw(\"SELECT * FROM Users WHERE id = \" + userId)",
                attack_vector="User input -> EF Raw SQL -> SQLi -> Data theft",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SQL-004: Dapper concat
            SecurityCheck(
                id="CS-SQL-004",
                name="SQL Injection via Dapper Query Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Dapper Query/Execute with string concatenation allows SQL injection",
                pattern=re.compile(r'(?i)(connection\.Query|connection\.Execute|conn\.Query|conn\.Execute|db\.Query|db\.Execute)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use Dapper's parameterized syntax with anonymous objects",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="var users = conn.Query<User>(\"SELECT * FROM Users WHERE id = @Id\", new { Id = userId });",
                attack_vector="User input -> Dapper concat -> SQLi -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SQL-005: NPoco/PetaPoco concat
            SecurityCheck(
                id="CS-SQL-005",
                name="SQL Injection via ORM Raw Query",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="ORM raw queries (NPoco, PetaPoco, ServiceStack) with concat allow injection",
                pattern=re.compile(r'(?i)(db\.Fetch|db\.Query|db\.Execute|db\.Single|db\.First)\s*<[^>]*>\s*\(\s*"[^"]*"\s*\+'),
                context_checks=[],
                suggestion="Use parameterized ORM queries with @0, @1 placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="var users = db.Fetch<User>(\"SELECT * FROM Users WHERE id = @0\", userId);",
                attack_vector="User input -> ORM raw SQL -> SQLi -> Data exfil",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SQL-006: LinqToSql concat
            SecurityCheck(
                id="CS-SQL-006",
                name="SQL Injection via LINQ to SQL ExecuteQuery",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="LINQ to SQL ExecuteQuery/ExecuteCommand with concat allows SQL injection",
                pattern=re.compile(r'(?i)(ExecuteQuery|ExecuteCommand|DataContext\.Execute)\s*<[^>]*>\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use parameterized LINQ queries with {0}, {1} placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="var users = db.ExecuteQuery<User>(\"SELECT * FROM Users WHERE id = {0}\", userId);",
                attack_vector="User input -> LINQ ExecuteQuery -> SQLi -> DB access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-XXE-001: XmlDocument
            SecurityCheck(
                id="CS-XXE-001",
                name="XML External Entity (XXE) via XmlDocument",
                category="xxe",
                severity=RiskLevel.CRITICAL,
                description="XmlDocument loads DTDs by default, enabling XXE attacks",
                pattern=re.compile(r'(?i)XmlDocument\.\w+|new\s+XmlDocument\s*\(\)'),
                context_checks=[self._is_xxe_safe],
                suggestion="Disable DTD processing and set XmlResolver to null",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="var doc = new XmlDocument { XmlResolver = null }; // Safe\n// Or use XmlReader with DtdProcessing.Prohibit",
                attack_vector="XML with external entity -> XmlDocument -> File read / SSRF",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-XXE-002: XDocument/LINQ to XML
            SecurityCheck(
                id="CS-XXE-002",
                name="XML External Entity (XXE) via XDocument",
                category="xxe",
                severity=RiskLevel.CRITICAL,
                description="XDocument loads DTDs by default, enabling XXE attacks",
                pattern=re.compile(r'(?i)XDocument\.(Load|Parse)|XElement\.(Load|Parse)'),
                context_checks=[self._is_xxe_safe],
                suggestion="Use XmlReader with DtdProcessing.Prohibit for secure XML parsing",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };\nusing var reader = XmlReader.Create(stream, settings);\nvar doc = XDocument.Load(reader);",
                attack_vector="XML with external entity -> XDocument -> SSRF / Information disclosure",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-CMD-001: Process.Start concat
            SecurityCheck(
                id="CS-CMD-001",
                name="Command Injection via Process.Start",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Process.Start with concatenated user input allows command injection",
                pattern=re.compile(r'(?i)Process\.Start\s*\([^)]*\+'),
                context_checks=[self._is_cmd_safe],
                suggestion="Use ProcessStartInfo with separate arguments, never concatenate",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="var psi = new ProcessStartInfo { FileName = \"ls\", Arguments = \"-la \" + sanitizedDir, UseShellExecute = false };\nProcess.Start(psi);",
                attack_vector="User input -> Process.Start concat -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # CS-CMD-002: ProcessStartInfo bis
            SecurityCheck(
                id="CS-CMD-002",
                name="Command Injection via ProcessStartInfo",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="ProcessStartInfo Arguments with concatenated input allows injection",
                pattern=re.compile(r'(?i)ProcessStartInfo.*Arguments\s*\+=\s*|Arguments\s*=\s*"[^"]*"\s*\+'),
                context_checks=[self._is_cmd_safe],
                suggestion="Use argument arrays via ArgumentList on .NET 6+ or sanitize thoroughly",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="psi.ArgumentList.Add(\"--file\");\npsi.ArgumentList.Add(sanitizedPath); // .NET 6+ safe API",
                attack_vector="User input -> ProcessStartInfo -> Argument injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # CS-PATH-001: File operations
            SecurityCheck(
                id="CS-PATH-001",
                name="Path Traversal via File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user-controlled path allow directory traversal via ../",
                pattern=re.compile(r'(?i)(File\.(Open|ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Copy|Move|Delete|Exists)|FileStream|StreamReader|StreamWriter)\s*\([^)]*\+'),
                context_checks=[self._is_path_safe],
                suggestion="Use Path.GetFullPath and validate prefix against base directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="var safePath = Path.GetFullPath(Path.Combine(baseDir, userInput));\nif (!safePath.StartsWith(baseDir)) throw new SecurityException();",
                attack_vector="User input -> File path + ../ -> Arbitrary file access -> Data breach",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # CS-PATH-002: Directory operations
            SecurityCheck(
                id="CS-PATH-002",
                name="Path Traversal via Directory Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="Directory operations with user input allow traversal attacks",
                pattern=re.compile(r'(?i)(Directory\.(GetFiles|GetDirectories|CreateDirectory|Delete|Move|Exists)|DirectoryInfo)\s*\([^)]*\+'),
                context_checks=[self._is_path_safe],
                suggestion="Use Path.GetFullPath and validate prefix against base directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="var safePath = Path.GetFullPath(Path.Combine(baseDir, userInput));\nif (!safePath.StartsWith(baseDir)) throw new SecurityException();\nDirectory.GetFiles(safePath);",
                attack_vector="User input -> Directory path + ../ -> Directory traversal -> File listing",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # CS-SSRF-001: HttpClient
            SecurityCheck(
                id="CS-SSRF-001",
                name="Server-Side Request Forgery via HttpClient",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="HttpClient with user-controlled URL can target internal services",
                pattern=re.compile(r'(?i)(HttpClient|httpClient|client)\.(GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\([^)]*\+'),
                context_checks=[self._is_url_safe],
                suggestion="Validate URL hostname against an allowlist before making requests",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="var uri = new Uri(userInput);\nif (!allowedDomains.Contains(uri.Host)) throw new SecurityException();\nvar response = await client.GetAsync(uri);",
                attack_vector="User input -> HttpClient -> Internal network scan -> Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # CS-SSRF-002: WebRequest
            SecurityCheck(
                id="CS-SSRF-002",
                name="Server-Side Request Forgery via WebRequest",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="WebRequest.Create with user-controlled URL enables SSRF",
                pattern=re.compile(r'(?i)(WebRequest\.Create|HttpWebRequest|WebClient\.(DownloadString|DownloadData|UploadValues|UploadString))\s*\([^)]*\+'),
                context_checks=[self._is_url_safe],
                suggestion="Validate URL against an allowlist of trusted hosts",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="var uri = new Uri(userInput);\nif (!allowedDomains.Contains(uri.Host)) throw new SecurityException();\nvar request = WebRequest.Create(uri);",
                attack_vector="User input -> WebRequest -> Internal resource access -> Data theft",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # CS-DESER-001: BinaryFormatter
            SecurityCheck(
                id="CS-DESER-001",
                name="Insecure Deserialization via BinaryFormatter",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="BinaryFormatter deserializes untrusted data, enabling RCE via gadget chains",
                pattern=re.compile(r'(?i)BinaryFormatter\.(Deserialize|UnsafeDeserialize)|new\s+BinaryFormatter\s*\('),
                context_checks=[self._is_deser_safe],
                suggestion="Use JsonSerializer or avoid deserializing untrusted data. BinaryFormatter is deprecated",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="var result = JsonSerializer.Deserialize<MyType>(json);\n// BinaryFormatter is dangerous: https://aka.ms/BinaryFormatter",
                attack_vector="Serialized payload -> BinaryFormatter -> Gadget chain -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # CS-DESER-002: JavaScriptSerializer
            SecurityCheck(
                id="CS-DESER-002",
                name="Insecure Deserialization via JavaScriptSerializer",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="JavaScriptSerializer with SimpleTypeResolver enables RCE",
                pattern=re.compile(r'(?i)JavaScriptSerializer|SimpleTypeResolver|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)'),
                context_checks=[self._is_deser_safe],
                suggestion="Use JsonSerializer with strict type handling. Avoid TypeNameHandling",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\nvar obj = JsonConvert.DeserializeObject<MyType>(json, settings);",
                attack_vector="JSON with $type -> JavaScriptSerializer -> Arbitrary type instantiation -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # CS-DESER-003: LosFormatter/NetDataContract
            SecurityCheck(
                id="CS-DESER-003",
                name="Insecure Deserialization via LosFormatter/NetDataContract",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="LosFormatter and NetDataContractSerializer allow RCE from untrusted data",
                pattern=re.compile(r'(?i)(LosFormatter|NetDataContractSerializer|SoapFormatter|ObjectStateFormatter)\s*\('),
                context_checks=[self._is_deser_safe],
                suggestion="Use safe serializers like JsonSerializer or XmlSerializer with known types",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Use JsonSerializer or DataContractSerializer instead:\nvar json = JsonSerializer.Serialize(obj);",
                attack_vector="Malformed serialized data -> Unsafe formatter -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # CS-LDAP-001: LDAP injection
            SecurityCheck(
                id="CS-LDAP-001",
                name="LDAP Injection via DirectorySearcher",
                category="ldap-injection",
                severity=RiskLevel.CRITICAL,
                description="Unsanitized user input in LDAP filter allows injection attacks",
                pattern=re.compile(r'(?i)(DirectorySearcher|DirectoryEntry|PrincipalSearcher)\.(Filter|SearchFilter)\s*=|Filter\s*\+='),
                context_checks=[self._is_ldap_safe],
                suggestion="Sanitize LDAP filter input or use parameterized LDAP queries",
                cwe_id="CWE-90",
                owasp_category="A03:2021 - Injection",
                remediation_example="var sanitized = userInput.Replace(\"(\", \"\\\\28\").Replace(\")\", \"\\\\29\").Replace(\"*\", \"\\\\2a\");\nsearcher.Filter = $\"(uid={sanitized})\";",
                attack_vector="User input -> LDAP filter -> Injection -> Data extraction / Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-SECRET-001: Hardcoded credential
            SecurityCheck(
                id="CS-SECRET-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="API keys, passwords, or tokens hardcoded in source code",
                pattern=re.compile(r'(?i)(const|static\s+readonly|string)\s+\w*(?:api[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key|secret[_-]?key|connectionstring)\w*\s*=\s*"[^"]{8,}"'),
                context_checks=[self._is_secret_fp],
                suggestion="Use Azure Key Vault, environment variables, or user secrets",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="var apiKey = Environment.GetEnvironmentVariable(\"API_KEY\");\n// OR: var secret = await keyVaultClient.GetSecretAsync(secretUrl);",
                attack_vector="Source code leak -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # CS-SECRET-002: JWT hardcoded
            SecurityCheck(
                id="CS-SECRET-002",
                name="Hardcoded JWT Secret",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="JWT signing key hardcoded in source allows token forgery",
                pattern=re.compile(r'(?i)(SigningKey|IssuerSigningKey|SecurityKey)\s*=\s*"[^"]{4,}"|new\s+SymmetricSecurityKey\s*\(\s*Encoding.*GetBytes\s*\(\s*"[^"]{4,}"'),
                context_checks=[self._is_secret_fp],
                suggestion="Load JWT signing key from environment variables or Azure Key Vault",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="var key = Environment.GetEnvironmentVariable(\"JWT_SIGNING_KEY\");\nvar securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));",
                attack_vector="Hardcoded JWT secret -> Forge any JWT -> Auth bypass",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # CS-UNSAFE-001: unsafe code
            SecurityCheck(
                id="CS-UNSAFE-001",
                name="Unsafe Code Block",
                category="unsafe",
                severity=RiskLevel.CRITICAL,
                description="Unsafe code blocks bypass .NET memory safety and can cause corruption",
                pattern=re.compile(r'(?i)unsafe\s*\{|unsafe\s+\w+'),
                context_checks=[self._is_unsafe_fp],
                suggestion="Avoid unsafe code. Use Span<T> and Memory<T> for safe memory access",
                cwe_id="CWE-825",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example='// Use safe alternatives:\nSpan<byte> buffer = stackalloc byte[256];\n// Or use unsafe as a last resort with proper validation',
                attack_vector="Unsafe pointer -> Memory corruption -> Arbitrary code execution",
                mitre_technique="T1055 - Process Injection",
            ),
            # CS-ELI-001: Expression injection
            SecurityCheck(
                id="CS-ELI-001",
                name="Expression Tree Injection via Lambda",
                category="expression-language",
                severity=RiskLevel.CRITICAL,
                description="Dynamic LINQ or expression parsing with user input can lead to injection",
                pattern=re.compile(r'(?i)System\.Linq\.Dynamic|DynamicQueryable|\.Where\s*\(\s*"|\\.Parse\s*\(\s*\\$"'),
                context_checks=[self._is_expression_safe],
                suggestion="Avoid dynamic expression parsing. Use strongly-typed predicates",
                cwe_id="CWE-917",
                owasp_category="A03:2021 - Injection",
                remediation_example='// Avoid:\nquery.Where("Name == \\"" + userInput + "\\"");\n// Use:\nquery.Where(x => x.Name == userInput);',
                attack_vector="User input -> Dynamic LINQ -> Expression injection -> Data leakage",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-VIEWSTATE-001: ViewState MAC
            SecurityCheck(
                id="CS-VIEWSTATE-001",
                name="ViewState MAC Disabled",
                category="viewstate",
                severity=RiskLevel.CRITICAL,
                description="EnableViewStateMac=false allows tampering with ViewState data",
                pattern=re.compile(r'(?i)EnableViewStateMac\s*=\s*["\s]*false'),
                context_checks=[],
                suggestion="Always enable ViewState MAC to prevent tampering",
                cwe_id="CWE-642",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example='<%@ Page EnableViewStateMac="true" %>',
                attack_vector="Disabled ViewState MAC -> Tamper with ViewState -> Auth bypass / RCE",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # CS-CRYPTO-001: Weak hash
            SecurityCheck(
                id="CS-CRYPTO-001",
                name="Weak Cryptographic Hash (MD5/SHA-1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA-1 are broken and vulnerable to collision attacks",
                pattern=re.compile(r'(?i)(MD5CryptoServiceProvider|SHA1CryptoServiceProvider|MD5\.Create|SHA1\.Create|new\s+MD5Cng|new\s+SHA1Cng)'),
                context_checks=[self._is_crypto_fp],
                suggestion="Use SHA256, SHA384, SHA512, or bcrypt/scrypt for passwords",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="using var sha256 = SHA256.Create();\nvar hash = sha256.ComputeHash(data);\n// For passwords: use Rfc2898DeriveBytes (PBKDF2)",
                attack_vector="Collision attack on MD5/SHA-1 -> Signature forgery -> MITM",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # CS-CRYPTO-002: Weak cipher
            SecurityCheck(
                id="CS-CRYPTO-002",
                name="Weak Encryption Algorithm (DES/RC2/3DES)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="DES, RC2, and TripleDES are cryptographically weak",
                pattern=re.compile(r'(?i)(DESCryptoServiceProvider|RC2CryptoServiceProvider|TripleDESCryptoServiceProvider|DES\.Create|RC2\.Create|TripleDES\.Create)'),
                context_checks=[],
                suggestion="Use Aes.Create() with GCM mode or authenticated encryption",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="using var aes = Aes.Create();\naes.Mode = CipherMode.GCM;\naes.GenerateKey();\naes.GenerateIV();",
                attack_vector="Weak cipher -> Brute force / Cryptoanalysis -> Data decryption",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # CS-CRYPTO-003: Hardcoded crypto key
            SecurityCheck(
                id="CS-CRYPTO-003",
                name="Hardcoded Encryption Key",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Encryption keys hardcoded in source can be extracted from code leaks",
                pattern=re.compile(r'(?i)(Aes\.Create|Rijndael\.Create|SymmetricAlgorithm\.Create).*Key\s*=\s*Encoding|new\s+byte\s*\[\s*\]\s*\{[^}]{10,}\}'),
                context_checks=[self._is_secret_fp],
                suggestion="Store encryption keys in Azure Key Vault or environment variables",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="var key = Environment.GetEnvironmentVariable(\"ENCRYPTION_KEY\");\nusing var aes = Aes.Create();\naes.Key = Convert.FromBase64String(key);",
                attack_vector="Hardcoded encryption key -> Decrypt all protected data -> Data breach",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # CS-TLS-001: Certificate validation disabled
            SecurityCheck(
                id="CS-TLS-001",
                name="TLS Certificate Verification Disabled",
                category="tls",
                severity=RiskLevel.HIGH,
                description="Disabling TLS certificate validation enables MITM attacks",
                pattern=re.compile(r'(?i)ServerCertificateValidationCallback\s*=\s*.*\{(?!.*return)|ServerCertificateCustomValidationCallback\s*=.*delegate\s*\{'),
                context_checks=[self._is_tls_safe],
                suggestion="Validate certificates properly, checking SslPolicyErrors",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => {\n    return errors == System.Net.Security.SslPolicyErrors.None;\n};",
                attack_vector="No cert validation -> MITM -> Credential / Data interception",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # CS-TLS-002: ServicePointManager
            SecurityCheck(
                id="CS-TLS-002",
                name="Certificate Validation Disabled via ServicePointManager",
                category="tls",
                severity=RiskLevel.HIGH,
                description="ServicePointManager.ServerCertificateValidationCallback = {true} disables all validation",
                pattern=re.compile(r'(?i)ServicePointManager\.ServerCertificateValidationCallback\s*=.*\{?\s*true'),
                context_checks=[],
                suggestion="Remove or properly implement ServerCertificateValidationCallback",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Remove the callback entirely to use default validation\n// Or check errors: ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => e == SslPolicyErrors.None;",
                attack_vector="ServicePointManager all-true -> MITM -> Data interception",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # CS-XSS-001: Razor Html.Raw
            SecurityCheck(
                id="CS-XSS-001",
                name="XSS via Html.Raw Output",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Html.Raw() bypasses Razor HTML encoding, enabling XSS",
                pattern=re.compile(r'(?i)@Html\.Raw\s*\(|HtmlString|MvcHtmlString\.Create\s*\('),
                context_checks=[self._is_xss_safe],
                suggestion="Use @ syntax for automatic HTML encoding. Only use Html.Raw with trusted content",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="@Model.UserName // Auto-encoded\n// Never: @Html.Raw(Model.UserName)",
                attack_vector="User input -> Html.Raw -> XSS -> Session theft / Phishing",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # CS-XSS-002: Blazor MarkupString
            SecurityCheck(
                id="CS-XSS-002",
                name="XSS via Blazor MarkupString",
                category="xss",
                severity=RiskLevel.HIGH,
                description="MarkupString in Blazor renders raw HTML, enabling XSS from user input",
                pattern=re.compile(r'(?i)(MarkupString|new\s+MarkupString)\s*\('),
                context_checks=[self._is_xss_safe],
                suggestion="Use regular string interpolation in Blazor for auto-encoding",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="@userName // Auto-encoded\n// Never: new MarkupString(userName)",
                attack_vector="User input -> MarkupString -> XSS -> Blazor component hijack",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # CS-CSRF-001: Missing anti-forgery token
            SecurityCheck(
                id="CS-CSRF-001",
                name="Missing CSRF Protection on POST",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="State-changing action without [ValidateAntiForgeryToken] is CSRF-vulnerable",
                pattern=re.compile(r'(?i)\[(HttpPost|HttpPut|HttpDelete|HttpPatch)\]|AcceptVerbs|HttpMethod\.Post'),
                context_checks=[self._is_csrf_safe],
                suggestion="Add [ValidateAntiForgeryToken] attribute to all state-changing actions",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="[HttpPost]\n[ValidateAntiForgeryToken]\npublic IActionResult CreateUser(UserModel model) { ... }",
                attack_vector="Missing anti-forgery token -> Forged POST -> State-changing action",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # CS-SESSION-001: Session fixation
            SecurityCheck(
                id="CS-SESSION-001",
                name="Session Fixation Vulnerability",
                category="session",
                severity=RiskLevel.HIGH,
                description="Not clearing session after authentication allows session fixation",
                pattern=re.compile(r'(?i)HttpContext\.Session|Session\[|HttpContext\.Current\.Session'),
                context_checks=[self._is_session_fixed],
                suggestion="Clear session and regenerate session ID after authentication",
                cwe_id="CWE-384",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="HttpContext.Session.Clear();\nawait HttpContext.Session.CommitAsync();\n// Then sign in the user",
                attack_vector="Attacker-provided session ID -> User authenticates -> Session fixed -> Hijack",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # CS-RANDOM-001: System.Random
            SecurityCheck(
                id="CS-RANDOM-001",
                name="Weak Random Number Generator (System.Random)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="System.Random is predictable and not cryptographically secure",
                pattern=re.compile(r'(?i)new\s+System\.Random|new\s+Random\s*\(\s*\)'),
                context_checks=[self._is_random_fp],
                suggestion="Use System.Security.Cryptography.RandomNumberGenerator",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="var token = new byte[32];\nRandomNumberGenerator.Fill(token);\n// Or: var token = RandomNumberGenerator.GetBytes(32);",
                attack_vector="Predictable random -> Session token forgery -> Auth bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # CS-LOG-001: Log injection
            SecurityCheck(
                id="CS-LOG-001",
                name="Log Injection via Unsanitized Input",
                category="logging",
                severity=RiskLevel.HIGH,
                description="Logging unsanitized user input enables log injection and CRLF attacks",
                pattern=re.compile(r'(?i)(_logger|logger|Log\.|ILogger)\.(Log|LogInformation|LogWarning|LogError|LogDebug|LogTrace)\s*\([^)]*\+'),
                context_checks=[self._is_log_safe],
                suggestion="Use structured logging with parameterized templates",
                cwe_id="CWE-117",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="_logger.LogInformation(\"User login: {Username}\", username);\n// Never: _logger.LogInformation(\"User login: \" + username);",
                attack_vector="User input with \\r\\n -> Log injection -> SIEM injection / Log forgery",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # CS-REFLECT-001: Unsafe reflection
            SecurityCheck(
                id="CS-REFLECT-001",
                name="Unsafe Reflection with User Input",
                category="reflection",
                severity=RiskLevel.HIGH,
                description="Type.GetType, Assembly.Load, or Activator.CreateInstance with user input allows RCE",
                pattern=re.compile(r'(?i)(Type\.GetType|Assembly\.(Load|LoadFrom|LoadFile)|Activator\.CreateInstance|AppDomain\.CreateInstance)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Validate type/assembly names against an allowlist before using reflection",
                cwe_id="CWE-470",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="var allowedTypes = new HashSet<string> { \"MyApp.Models.User\" };\nif (!allowedTypes.Contains(typeName)) throw new SecurityException();\nvar type = Type.GetType(typeName);",
                attack_vector="User input -> Reflection -> Arbitrary type instantiation -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # CS-REDIR-001: Open redirect
            SecurityCheck(
                id="CS-REDIR-001",
                name="Open Redirect via Redirect Result",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="Redirect to user-controlled URLs without validation enables phishing",
                pattern=re.compile(r'(?i)(Redirect|LocalRedirect|RedirectResult)\s*\([^)]*(Request|request|query|param)'),
                context_checks=[self._is_redirect_safe],
                suggestion="Use LocalRedirect for relative URLs, or validate against an allowlist",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="if (Url.IsLocalUrl(returnUrl)) { return Redirect(returnUrl); }\nreturn RedirectToAction(\"Index\");",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # CS-CORS-001: Wildcard CORS
            SecurityCheck(
                id="CS-CORS-001",
                name="Overly Permissive CORS Policy",
                category="cors",
                severity=RiskLevel.HIGH,
                description="AllowAnyOrigin or WithOrigins(\"*\") exposes API to all domains",
                pattern=re.compile(r'(?i)AllowAnyOrigin|WithOrigins\s*\(\s*"\*"|SetIsOriginAllowed\s*\(\s*.*=>\s*true'),
                context_checks=[self._is_dev_fp],
                suggestion="Specify exact allowed origins instead of wildcard",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='builder.WithOrigins("https://app.example.com").AllowAnyMethod().AllowAnyHeader();',
                attack_vector="Wildcard CORS -> Any website reads API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # CS-COOKIE-001: Insecure cookie
            SecurityCheck(
                id="CS-COOKIE-001",
                name="Insecure Cookie Configuration",
                category="cookies",
                severity=RiskLevel.HIGH,
                description="Cookies without HttpOnly and Secure flags can be intercepted via XSS or HTTP",
                pattern=re.compile(r'(?i)CookieOptions\s*\{|new\s+CookieOptions|Response\.Cookies\.Append|HttpCookie|AppendResponseCookie'),
                context_checks=[self._is_cookie_safe],
                suggestion="Set HttpOnly=true, Secure=true, SameSite=Strict on cookies",
                cwe_id="CWE-614",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict }",
                attack_vector="Cookie without Secure/HttpOnly -> XSS reads cookie -> Session theft",
                mitre_technique="T1539 - Steal Web Session Cookie",
            ),
            # CS-NOSQL-001: MongoDB injection
            SecurityCheck(
                id="CS-NOSQL-001",
                name="NoSQL Injection via MongoDB BsonDocument",
                category="nosql-injection",
                severity=RiskLevel.HIGH,
                description="MongoDB queries using BsonDocument with user input allow injection",
                pattern=re.compile(r'(?i)BsonDocument\.Parse|MongoCollection\.Find|FilterDefinitionBuilder|Builders.*Filter\.(Eq|Gt|Lt|Regex|Where)'),
                context_checks=[self._is_nosql_safe],
                suggestion="Use typed filter builders and avoid parsing user strings as BsonDocument",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="var filter = Builders<User>.Filter.Eq(u => u.Username, username); // Safe\n// Never: BsonDocument.Parse(\"{username: '\" + userInput + \"'}\")",
                attack_vector="User input -> BsonDocument -> MongoDB injection -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # CS-VALID-001: Missing model validation
            SecurityCheck(
                id="CS-VALID-001",
                name="Missing Model Validation Attributes",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="Model properties without [Required], [StringLength] allow malformed data",
                pattern=re.compile(r'(?i)\[ApiController\]|\[Controller\]|ControllerBase|Controller\b'),
                context_checks=[self._is_validated],
                suggestion="Add data annotation validation attributes to all model properties",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="public class UserDto {\n    [Required]\n    [StringLength(100)]\n    public string Name { get; set; }\n}",
                attack_vector="Missing validation -> Malformed payload -> Logic bypass / Injection",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-DEPR-001: Deprecated APIs
            SecurityCheck(
                id="CS-DEPR-001",
                name="Deprecated API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="Using deprecated APIs may cause compatibility and security issues",
                pattern=re.compile(r'(?i)(BinaryFormatter|FormsAuthentication|RemotingConfiguration|AppDomain\.CreateDomain|Hashtable|ArrayList)'),
                context_checks=[],
                suggestion="Use modern alternatives: JsonSerializer, ASP.NET Core Identity, generics",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Instead of BinaryFormatter:\nvar json = JsonSerializer.Serialize(obj);\n// Instead of ArrayList:\nvar list = new List<string>();",
                attack_vector="Deprecated API may miss security fixes",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-ERROR-001: Stack trace disclosure
            SecurityCheck(
                id="CS-ERROR-001",
                name="Information Disclosure via Stack Traces",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Exposing exception details to users leaks internal application information",
                pattern=re.compile(r'(?i)(ex\.ToString\(\)|ex\.Message|Response\.Write.*Exception|ExceptionDetail|IncludeErrorDetail)'),
                context_checks=[self._is_error_safe],
                suggestion="Log detailed errors server-side, return generic messages to users",
                cwe_id="CWE-209",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="_logger.LogError(ex, \"Database error\");\nreturn StatusCode(500, \"An unexpected error occurred\");",
                attack_vector="Stack trace -> Internal paths/versions exposed -> Attack surface mapping",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # CS-ERROR-002: Developer exception page
            SecurityCheck(
                id="CS-ERROR-002",
                name="Developer Exception Page in Production",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="UseDeveloperExceptionPage in production exposes sensitive details",
                pattern=re.compile(r'(?i)UseDeveloperExceptionPage'),
                context_checks=[self._is_dev_fp],
                suggestion="Use app.UseExceptionHandler() for production error handling",
                cwe_id="CWE-209",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example='if (env.IsDevelopment()) app.UseDeveloperExceptionPage();\nelse app.UseExceptionHandler("/Home/Error");',
                attack_vector="Developer page exposed -> Stack trace / source -> Code/Config disclosure",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # CS-HEADER-001: Missing security headers
            SecurityCheck(
                id="CS-HEADER-001",
                name="Missing HTTP Security Headers",
                category="headers",
                severity=RiskLevel.MEDIUM,
                description="Web app without security headers is vulnerable to clickjacking, MIME sniffing",
                pattern=re.compile(r'(?i)(IApplicationBuilder|app\.Use|WebApplication|Startup)\.'),
                context_checks=[self._is_header_safe],
                suggestion="Add middleware for CSP, HSTS, X-Content-Type-Options, X-Frame-Options",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="app.UseHsts();\napp.UseXContentTypeOptions();\napp.UseXfo(options => options.Deny());\n// Add NWebsec or custom middleware",
                attack_vector="Missing headers -> Clickjacking / MIME sniffing -> XSS / Data theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # CS-HTTP-001: Insecure HTTP
            SecurityCheck(
                id="CS-HTTP-001",
                name="Insecure HTTP Client Configuration",
                category="http",
                severity=RiskLevel.MEDIUM,
                description="HttpClient without HTTPS or proper SSL configuration exposes data",
                pattern=re.compile(r'(?i)new\s+HttpClient\s*\(\s*\)|IHttpClientFactory'),
                context_checks=[self._is_http_safe],
                suggestion="Configure HttpClient with HTTPS and proper SSL validation",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="var handler = new HttpClientHandler { SslProtocols = SslProtocols.Tls13 };\nvar client = new HttpClient(handler) { BaseAddress = new Uri(\"https://api.example.com\") };",
                attack_vector="No HTTPS -> Traffic interception -> Data exposure",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # CS-DOS-001: Regex DoS
            SecurityCheck(
                id="CS-DOS-001",
                name="Regex Denial of Service (ReDoS)",
                category="dos",
                severity=RiskLevel.MEDIUM,
                description="Regex with nested quantifiers can cause catastrophic backtracking",
                pattern=re.compile(r'\(\s*.\s*\+\s*\)\s*\+|\(\s*.\s*\*\s*\)\s*\*|\(\s*.\s*\*\s*\)\s*\+|\+\s*\+\s*\+'),
                context_checks=[],
                suggestion="Use RegexOptions.Timeout or avoid nested quantifiers",
                cwe_id="CWE-1333",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));\n// Or use atomic groups: (?>...)",
                attack_vector="Crafted input -> Catastrophic backtracking -> CPU exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # CS-ERROR-003: Empty catch block
            SecurityCheck(
                id="CS-ERROR-003",
                name="Empty Catch Block",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Empty catch blocks silently swallow exceptions, hiding failures",
                pattern=re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}'),
                context_checks=[],
                suggestion="Log and handle exceptions. Never leave catch blocks empty",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="catch (Exception ex) {\n    _logger.LogError(ex, \"Operation failed\");\n    throw;\n}",
                attack_vector="Exception swallowed -> Security mechanism fails silently",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # CS-ASYNC-001: async void
            SecurityCheck(
                id="CS-ASYNC-001",
                name="Async Void Method (Fire-and-Forget)",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="async void methods crash the process on unhandled exceptions",
                pattern=re.compile(r'async\s+(void|partial\s+void)\s+\w+\s*\('),
                context_checks=[],
                suggestion="Use async Task instead of async void. Only async void for event handlers",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="public async Task ProcessDataAsync() { ... } // async Task\n// NOT: public async void ProcessDataAsync() { ... }",
                attack_vector="async void exception -> Process crash -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # CS-XPATH-001: XPath injection
            SecurityCheck(
                id="CS-XPATH-001",
                name="XPath Injection",
                category="xpath-injection",
                severity=RiskLevel.MEDIUM,
                description="XPath queries with user input allow injection and data extraction",
                pattern=re.compile(r'(?i)XPathDocument|XPathNavigator|XPathExpression|SelectNodes|SelectSingleNode|XPath\.Evaluate'),
                context_checks=[self._is_xpath_safe],
                suggestion="Use parameterized XPath queries or validate input against an allowlist",
                cwe_id="CWE-643",
                owasp_category="A03:2021 - Injection",
                remediation_example="var expr = XPathExpression.Compile($\"//user[name='{SanitizeForXPath(userName)}']\");\n// Or compile and use variables",
                attack_vector="User input in XPath -> Injection -> XML data extraction",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # CS-RACE-001: Race condition
            SecurityCheck(
                id="CS-RACE-001",
                name="Potential Race Condition (Unprotected State)",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Shared mutable state without synchronization can cause race conditions",
                pattern=re.compile(r'(?i)(lock\s*\(|Monitor\.Enter|Monitor\.Exit|SemaphoreSlim|ReaderWriterLockSlim|Interlocked\.|ConcurrentDictionary|ConcurrentQueue)'),
                context_checks=[self._is_race_fp],
                suggestion="Use lock, SemaphoreSlim, or ConcurrentDictionary for shared state",
                cwe_id="CWE-362",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="private readonly object _lock = new();\nlock (_lock) { sharedValue = newValue; }",
                attack_vector="Race condition -> Data corruption -> Auth bypass / Privilege escalation",
                mitre_technique="T1055 - Process Injection",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # CS-DOC-001: Missing XML doc
            SecurityCheck(
                id="CS-DOC-001",
                name="Missing XML Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Public classes and methods should have XML documentation comments",
                pattern=re.compile(r'(?i)(public|protected)\s+(class|interface|enum|void|\w+\s+\w+)\s+\w+'),
                context_checks=[self._is_xmldoc_present],
                suggestion="Add /// XML documentation comments to public APIs",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/// <summary>\n/// Validates user input and creates a new user.\n/// </summary>\npublic async Task<User> CreateUserAsync(UserDto dto) { ... }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # CS-MAGIC-001: Magic numbers
            SecurityCheck(
                id="CS-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(if|while|for|return|==|!=|>|<|>=|<=)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_magic_fp],
                suggestion="Define magic numbers as const or static readonly fields",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="private const int MaxRetries = 3;\nprivate const int TimeoutMs = 30000;\nif (retries >= MaxRetries) { throw new TimeoutException(); }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # CS-COMM-001: TODO
            SecurityCheck(
                id="CS-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security work",
                pattern=re.compile(r'(?i)\/\/\s*TODO|TODO:|/\*\s*TODO'),
                context_checks=[],
                suggestion="Address all TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Resolve all TODOs before production. Track in issue tracker.",
                attack_vector="Unresolved TODO may indicate missing security control",
                mitre_technique="N/A",
            ),
            # CS-COMM-002: FIXME/HACK
            SecurityCheck(
                id="CS-COMM-002",
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
            # CS-DEBUG-001: Console.WriteLine
            SecurityCheck(
                id="CS-DEBUG-001",
                name="Console.WriteLine Debug Statement",
                category="debug",
                severity=RiskLevel.LOW,
                description="Console.WriteLine should be removed from production code",
                pattern=re.compile(r'(?i)Console\.(WriteLine|Write|WriteAsync|Out\.Write|Error\.Write)'),
                context_checks=[self._is_dev_fp],
                suggestion="Use ILogger<T> with appropriate log levels instead",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="_logger.LogDebug(\"Processing user: {UserId}\", userId);\n// Never: Console.WriteLine($\"User: {userId}\");",
                attack_vector="Debug output in production -> Information disclosure",
                mitre_technique="N/A",
            ),
            # CS-USING-001: Unused usings
            SecurityCheck(
                id="CS-USING-001",
                name="Unused Using Directive",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Unused using directives clutter code and may indicate dead code",
                pattern=re.compile(r'^using\s+[\w.]+;'),
                context_checks=[self._is_using_used],
                suggestion="Remove unused using directives with IDE usings cleanup",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove unused using directives. Use IDE0161 for auto-cleanup.",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # CS-QUAL-001: Broad exception catch
            SecurityCheck(
                id="CS-QUAL-001",
                name="Catching Generic Exception",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Catching Exception hides specific error conditions and failures",
                pattern=re.compile(r'catch\s*\(\s*Exception\s+\w+catch\s*\(\s*\)'),
                context_checks=[],
                suggestion="Catch specific exception types (SqlException, IOException, etc.)",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="catch (SqlException ex) when (ex.Number == 2601) { // Duplicate key\ncatch (IOException ex) { // File error",
                attack_vector="Generic catch may hide security-relevant exceptions",
                mitre_technique="N/A",
            ),
            # CS-QUAL-002: Null check missing
            SecurityCheck(
                id="CS-QUAL-002",
                name="Potential NullReferenceException",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Method return used without null check (possible NullReferenceException)",
                pattern=re.compile(r'\.FirstOrDefault\s*\([^)]*\)\.|\.SingleOrDefault\s*\([^)]*\)\.'),
                context_checks=[],
                suggestion="Use the ?? operator, ?. null-conditional operator, or check for null",
                cwe_id="CWE-476",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="var user = users.FirstOrDefault(u => u.Id == id);\nif (user != null) { return user.Name; }\n// OR: return user?.Name;",
                attack_vector="NullReferenceException -> Application crash -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # CS-QUAL-003: Hardcoded localhost
            SecurityCheck(
                id="CS-QUAL-003",
                name="Hardcoded localhost Address",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost may indicate test/debug code in production",
                pattern=re.compile(r'["\x27]localhost["\x27]|["\x27]127\.0\.0\.1["\x27]|["\x27]\.\x27]'),
                context_checks=[self._is_dev_fp],
                suggestion="Use configuration values for host:port settings",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example='var host = configuration.GetValue<string>("Host") ?? "localhost";\nvar port = configuration.GetValue<int>("Port", 8080);',
                attack_vector="Hardcoded addresses may expose internal network information",
                mitre_technique="N/A",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect frameworks from imports and patterns."""
        frameworks = []
        if re.search(r'Microsoft\.AspNetCore\.|IApplicationBuilder|WebApplication|Program', content):
            frameworks.append('aspnet-core')
        if re.search(r'System\.Web\.Mvc|Controller\b|ActionResult|IActionResult', content):
            frameworks.append('aspnet-mvc')
        if re.search(r'System\.Web\.UI|Page\b|WebForm|ViewState', content):
            frameworks.append('webforms')
        if re.search(r'Microsoft\.EntityFrameworkCore|DbContext|DbSet|FromSqlRaw|ExecuteSqlRaw', content):
            frameworks.append('entity-framework')
        if re.search(r'Dapper|SqlMapper|connection\.Query|conn\.Execute', content):
            frameworks.append('dapper')
        if re.search(r'MongoDB\.Driver|MongoClient|IMongoDatabase|BsonDocument', content):
            frameworks.append('mongodb')
        if re.search(r'Microsoft\.Extensions\.DependencyInjection|IServiceCollection|AddScoped|AddTransient|AddSingleton', content):
            frameworks.append('dependency-injection')
        if re.search(r'Serilog|NLog|Microsoft\.Extensions\.Logging|ILogger', content):
            frameworks.append('logging')
        if re.search(r'IdentityServer|IdentityUser|SignInManager|UserManager', content):
            frameworks.append('identity')
        if re.search(r'SignalR|Hub\b|IHubContext', content):
            frameworks.append('signalr')
        if re.search(r'NUnit|xunit|Microsoft\.VisualStudio\.TestTools|TestClass|Fact|Theory|Test', content):
            frameworks.append('testing')
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
            'Request.QueryString': 'HTTP Query',
            'Request.Form': 'HTTP Form',
            'Request.Params': 'HTTP Params',
            'Request.Headers': 'HTTP Header',
            'Request.Cookies': 'HTTP Cookie',
            'Request.ServerVariables': 'HTTP Server Var',
            'Request.UserAgent': 'HTTP User-Agent',
            'Request.Url': 'HTTP URL',
            'Request.InputStream': 'HTTP Body',
            'Request.Files': 'HTTP Upload',
            'HttpContext.Request.Query': 'HTTP Query',
            'HttpContext.Request.Form': 'HTTP Form',
            'HttpContext.Request.Headers': 'HTTP Header',
            'HttpContext.Request.Cookies': 'HTTP Cookie',
            'HttpContext.Request.Body': 'HTTP Body',
            'Environment.GetEnvironmentVariable': 'Environment Var',
            'Configuration.GetValue': 'Config Value',
            'Configuration.GetConnectionString': 'Config Value',
            '@Request.Query': 'Razor Query',
            '@Request.Form': 'Razor Form',
        }
        sinks = {
            'new SqlCommand': 'SQL Query',
            'new SqlDataAdapter': 'SQL Query',
            'ExecuteReader': 'SQL Read',
            'ExecuteNonQuery': 'SQL Write',
            'ExecuteScalar': 'SQL Scalar',
            'FromSqlRaw': 'SQL Query',
            'ExecuteSqlRaw': 'SQL Exec',
            'Query': 'Dapper Query',
            'Execute': 'Dapper SQL',
            'Process.Start': 'Command Exec',
            'ProcessStartInfo': 'Command Exec',
            'new FileStream': 'File Access',
            'new StreamReader': 'File Read',
            'new StreamWriter': 'File Write',
            'File.Open': 'File Access',
            'File.ReadAllText': 'File Read',
            'File.WriteAllText': 'File Write',
            'GetAsync': 'HTTP Request',
            'PostAsync': 'HTTP Request',
            'SendAsync': 'HTTP Request',
            'DownloadString': 'HTTP Request',
            'Redirect': 'Redirect',
            'SearchFilter': 'LDAP Query',
        }
        tainted: Dict[str, str] = {}
        for i, line in enumerate(lines, 1):
            for src, stype in sources.items():
                if src in line:
                    m = re.search(r'(?:var|string|int)\s+(\w+)\s*=\s*(?:HttpContext\.Current)?\.?' + re.escape(src), line)
                    if not m:
                        m = re.search(r'(\w+)\s*=\s*(?:HttpContext\.Current\.)?Request\.', line)
                    if m:
                        tainted[m.group(1)] = stype
            for sink, sinktype in sinks.items():
                if sink in line:
                    for var_name, stype in tainted.items():
                        if var_name in line:
                            self._add_taint_finding(result, i, line, stype, sinktype)

    def _add_taint_finding(self, result: AnalysisResult, line_num: int, line: str, source_type: str, sink_type: str) -> None:
        """Add a taint analysis finding."""
        finding = Finding(
            file=str(result.file_path), line=line_num, column=0,
            issue_type="CS-TAINT-001",
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
        self._check_multiline_xss(content, lines, result, frameworks)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection across multiple lines."""
        for i, line in enumerate(lines):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+', line):
                for j in range(i, min(i + 5, len(lines))):
                    if '+' in lines[j] and re.search(r'(?i)(SqlCommand|ExecuteReader|ExecuteNonQuery|FromSqlRaw|Query\b)', lines[j]):
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="CS-SQL-007",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries with @param placeholders",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="using var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn);\ncmd.Parameters.AddWithValue(\"@id\", userId);",
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_multiline_xss(self, content: str, lines: List[str], result: AnalysisResult, frameworks: List[str]) -> None:
        """Check for XSS across multiple lines in Razor views."""
        for i, line in enumerate(lines):
            if '.Raw(' in line and '@' not in line:
                for j in range(max(0, i - 2), i + 1):
                    if 'var ' in lines[j] or 'string ' in lines[j]:
                        self._add_finding(result, i + 1, line, SecurityCheck(
                            id="CS-XSS-003",
                            name="Multi-line XSS via Raw Output",
                            category="xss",
                            severity=RiskLevel.HIGH,
                            description="Html.Raw with user input from variable defined earlier enables XSS",
                            pattern=re.compile(r''),
                            suggestion="Use @ syntax for automatic HTML encoding",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 - Injection",
                            remediation_example="@Model.UserName // Auto-encoded\n// Never: @Html.Raw(userNameVariable)",
                            attack_vector="Variable -> Html.Raw -> XSS -> Session theft",
                            mitre_technique="T1204.001 - User Execution: Malicious Link",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_xxe_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'DtdProcessing.Prohibit' in content or 'DtdProcessing.Ignore' in content:
            return True
        if 'XmlResolver = null' in content or 'XmlResolver = null' in line:
            return True
        if 'ProhibitDtd' in content:
            return True
        return False

    def _is_cmd_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'Process\.Start\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'ArgumentList.Add' in content:
            return True
        return False

    def _is_path_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'(File\.|Directory\.)\w+\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'Path.GetFullPath' in line or 'Path.Combine' in line:
            return True
        if 'baseDir' in line or 'safePath' in line:
            return True
        return False

    def _is_url_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'(GetAsync|PostAsync|Create|DownloadString)\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'allowedDomains' in line or 'allowedHosts' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_deser_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'JsonSerializer' in content and 'TypeNameHandling.None' in content:
            return True
        if 'DataContractSerializer' in content or 'KnownType' in content:
            return True
        return False

    def _is_ldap_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'escape' in line.lower() or 'Sanitize' in content:
            return True
        return False

    def _is_secret_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if 'Environment.GetEnvironmentVariable' in line or 'IConfiguration' in line:
            return True
        if 'test' in line.lower() or '[Test]' in content or '[Fact]' in content:
            return True
        return False

    def _is_unsafe_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Span<' in content or 'Memory<' in content:
            return True
        return False

    def _is_expression_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ParameterExpression' in line:
            return True
        return False

    def _is_crypto_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'SHA256' in line or 'SHA384' in line or 'SHA512' in line:
            return True
        if 'checksum' in line.lower() or 'hashcode' in line.lower() or 'GetHashCode' in line:
            return True
        return False

    def _is_tls_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'SslPolicyErrors.None' in content:
            return True
        if 'return errors ==' in content:
            return True
        return False

    def _is_xss_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Html.Encode' in line or 'AntiXssEncoder' in line or 'Sanitizer' in line:
            return True
        if 'HtmlEncoder.Default.Encode' in line:
            return True
        return False

    def _is_csrf_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ValidateAntiForgeryToken' in content or 'AutoValidateAntiforgeryToken' in content:
            return True
        return False

    def _is_session_fixed(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Session.Clear()' in content or 'Session.Clear' in content:
            return True
        if 'SignInAsync' in content:
            return True
        return False

    def _is_random_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'RandomNumberGenerator' in content:
            return True
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower():
            return True
        return False

    def _is_log_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        if '{' in line and '}' in line:
            return True
        return False

    def _is_redirect_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Url.IsLocalUrl' in line or 'IsLocalUrl' in content:
            return True
        if 'allowedRedirects' in line:
            return True
        return False

    def _is_dev_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'development' in line.lower() or 'Development' in line:
            return True
        if 'localhost' in line.lower():
            return True
        return False

    def _is_cookie_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'HttpOnly = true' in content and 'Secure = true' in content:
            return True
        if 'HttpOnly = true' in content or 'Secure = true' in content:
            return True
        return False

    def _is_nosql_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Builders<' in line:
            return True
        return False

    def _is_validated(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '[Required]' in content or '[StringLength' in content or '[RegularExpression' in content:
            return True
        if 'ModelState.IsValid' in content or 'TryValidateModel' in content:
            return True
        return False

    def _is_error_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '_logger' in line and 'Response.Write' not in line:
            return True
        if 'UseExceptionHandler' in content or 'app.UseExceptionHandler' in content:
            return True
        return False

    def _is_header_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'UseHsts' in content or 'UseXContentTypeOptions' in content:
            return True
        if 'UseXfo' in content or 'UseReferrerPolicy' in content:
            return True
        if 'Content-Security-Policy' in content or 'X-Content-Type-Options' in content:
            return True
        return False

    def _is_http_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'https://' in line:
            return True
        if 'SslProtocols' in line or 'ServerCertificateCustomValidationCallback' in line:
            return True
        return False

    def _is_xpath_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'SanitizeForXPath' in content or 'Sanitize' in content:
            return True
        return False

    def _is_race_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'lock (' in content or 'SemaphoreSlim' in content:
            return True
        return False

    def _is_xmldoc_present(self, line: str, content: str, frameworks: List[str]) -> bool:
        lines = content.split('\n')
        try:
            idx = lines.index(line)
            if idx > 0:
                for j in range(idx - 1, max(0, idx - 3), -1):
                    prev = lines[j].strip()
                    if prev.startswith('///') or prev.endswith('///'):
                        return True
        except ValueError:
            pass
        return False

    def _is_magic_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'\b(0|1|2|10|100|1000)\b', line):
            return True
        if 'const' in line or 'readonly' in line:
            return True
        return False

    def _is_using_used(self, line: str, content: str, frameworks: List[str]) -> bool:
        match = re.search(r'using\s+([\w.]+);', line)
        if match:
            namespace_path = match.group(1)
            parts = namespace_path.split('.')
            for part in reversed(parts):
                if part and part != '*' and part in content:
                    return True
        return False
