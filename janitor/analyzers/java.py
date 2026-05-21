"""Elite static analyzer for Java code with comprehensive security checks."""

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
    """A 'security unit test' for Java code."""
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


class JavaAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Java code - enterprise-grade security auditing."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._current_path: Path = Path("")

    def get_language(self) -> str:
        return "java"

    def get_supported_extensions(self) -> List[str]:
        return [".java"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Java file and return results."""
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
            # JV-SQL-001: Statement concat
            SecurityCheck(
                id="JV-SQL-001",
                name="SQL Injection via Statement Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in Statement.executeQuery() allows SQL injection",
                pattern=re.compile(r'(?i)Statement\.(executeQuery|executeUpdate|execute)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use PreparedStatement with ? placeholders instead of Statement",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);\nResultSet rs = stmt.executeQuery();",
                attack_vector="User input -> String concat in SQL query -> SQL injection -> Data exfiltration",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SQL-002: PreparedStatement concat
            SecurityCheck(
                id="JV-SQL-002",
                name="SQL Injection via PreparedStatement Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in PreparedStatement query disables parameterization",
                pattern=re.compile(r'(?i)PreparedStatement\s+\w+\s*=\s*conn\.prepareStatement\s*\(\s*"[^"]*"\s*\+'),
                context_checks=[],
                suggestion="Always use ? placeholders in prepareStatement, never concatenate",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);",
                attack_vector="User input -> PreparedStatement concat -> SQL injection -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SQL-003: JPA createQuery concat
            SecurityCheck(
                id="JV-SQL-003",
                name="SQL Injection via JPA createQuery Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in JPA createQuery() allows JPQL injection",
                pattern=re.compile(r'(?i)(entityManager|em)\.(createQuery|createNativeQuery)\s*\([^)]*\+'),
                context_checks=[self._is_jpa_parameterized],
                suggestion="Use parameterized JPQL queries with :param placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="TypedQuery<User> query = em.createQuery(\"SELECT u FROM User u WHERE u.id = :id\", User.class);\nquery.setParameter(\"id\", userId);",
                attack_vector="User input -> JPQL concat -> Injection -> Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SQL-004: Spring JdbcTemplate concat
            SecurityCheck(
                id="JV-SQL-004",
                name="SQL Injection via JdbcTemplate Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in JdbcTemplate query allows SQL injection",
                pattern=re.compile(r'(?i)jdbcTemplate\.(query|update|queryForObject|queryForList|execute)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use parameterized queries with ? or :named placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="jdbcTemplate.query(\"SELECT * FROM users WHERE id = ?\", new Object[]{userId}, rowMapper);",
                attack_vector="User input -> JdbcTemplate concat -> SQLi -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SQL-005: MyBatis ${} injection
            SecurityCheck(
                id="JV-SQL-005",
                name="SQL Injection via MyBatis ${} Substitution",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="MyBatis ${} directly interpolates user input into SQL, enabling injection",
                pattern=re.compile(r'\$\{\s*\w*\s*\}'),
                context_checks=[self._is_mybatis_safe],
                suggestion="Use #{} parameter placeholders instead of ${} string substitution",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="<select id=\"findUser\">SELECT * FROM users WHERE name = #{name}</select>",
                attack_vector="User input -> MyBatis ${} -> SQL injection -> Data theft",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SQL-006: Hibernate HQL concat
            SecurityCheck(
                id="JV-SQL-006",
                name="SQL Injection via Hibernate HQL Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in HQL queries allows injection via Hibernate",
                pattern=re.compile(r'(?i)(session|hibernateTemplate)\.(createQuery|find|findByNamedParam)\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use named parameters (:param) in HQL queries",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="Query query = session.createQuery(\"FROM User WHERE id = :id\");\nquery.setParameter(\"id\", userId);",
                attack_vector="User input -> HQL concat -> SQLi -> DB compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-JNDI-001: JNDI injection
            SecurityCheck(
                id="JV-JNDI-001",
                name="JNDI Injection via InitialContext.lookup",
                category="jndi-injection",
                severity=RiskLevel.CRITICAL,
                description="JNDI lookup with user-controlled name allows remote code execution via RMI/LDAP",
                pattern=re.compile(r'(?i)InitialContext\.lookup|Context\.lookup|new\s+InitialContext\s*\(\s*\)\s*\.lookup'),
                context_checks=[self._is_jndi_safe],
                suggestion="Validate and restrict JNDI names. Use an allowlist for lookup strings",
                cwe_id="CWE-917",
                owasp_category="A03:2021 - Injection",
                remediation_example="String safeName = allowedJndiNames.get(userInput);\nif (safeName == null) throw new SecurityException(\"Invalid JNDI name\");\nContext ctx = new InitialContext();\nObject obj = ctx.lookup(safeName);",
                attack_vector="User input -> JNDI lookup -> LDAP/RMI server -> RCE via deserialization",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-CMD-001: Runtime.exec
            SecurityCheck(
                id="JV-CMD-001",
                name="Command Injection via Runtime.exec()",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Runtime.exec() with user input concatenated into command string enables injection",
                pattern=re.compile(r'(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\([^)]*\+'),
                context_checks=[self._is_cmd_safe],
                suggestion="Use ProcessBuilder tokenizing arguments separately, not shell strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="ProcessBuilder pb = new ProcessBuilder(\"ls\", \"-la\", sanitizedDir);\npb.redirectErrorStream(true);\nProcess p = pb.start();",
                attack_vector="User input -> Runtime.exec concat -> Shell injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # JV-CMD-002: ProcessBuilder concat
            SecurityCheck(
                id="JV-CMD-002",
                name="Command Injection via ProcessBuilder Concatenation",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="ProcessBuilder with concatenated arguments allows command injection",
                pattern=re.compile(r'(?i)ProcessBuilder\s*\([^)]*\+'),
                context_checks=[self._is_cmd_safe],
                suggestion="Pass arguments as separate strings in the ProcessBuilder constructor or command() list",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="new ProcessBuilder(\"ls\", \"-la\", sanitizedDir).start();",
                attack_vector="User input -> ProcessBuilder concat -> Arg injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # JV-CMD-003: ProcessBuilder.command add with concat
            SecurityCheck(
                id="JV-CMD-003",
                name="Command Injection via ProcessBuilder.command()",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="ProcessBuilder.command().add() with user input allows injection",
                pattern=re.compile(r'(?i)\.command\s*\(\s*\)\s*\.add\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Use separate argument list items, never concatenate within a single argument",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="ProcessBuilder pb = new ProcessBuilder();\npb.command(\"ls\", \"-la\", sanitizedDir);",
                attack_vector="User input -> command().add() concat -> Argument injection -> RCE",
                mitre_technique="T1059.004 - Command and Scripting Interpreter: Unix Shell",
            ),
            # JV-PATH-001: File path traversal
            SecurityCheck(
                id="JV-PATH-001",
                name="Path Traversal via File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user-controlled path allow directory traversal via ../",
                pattern=re.compile(r'(?i)new\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|RandomAccessFile)\s*\([^)]*\+'),
                context_checks=[self._is_path_safe],
                suggestion="Use getCanonicalFile() and verify path prefix against allowed base directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="File safeFile = new File(baseDir, userInput).getCanonicalFile();\nif (!safeFile.getPath().startsWith(baseDir.getPath())) throw new SecurityException();",
                attack_vector="User input -> File path + ../ -> Arbitrary file read/write -> Data breach",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # JV-PATH-002: Paths/Files traversal
            SecurityCheck(
                id="JV-PATH-002",
                name="Path Traversal via java.nio.file.Paths/Files",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="java.nio.file operations with user-controlled path allow directory traversal",
                pattern=re.compile(r'(?i)(Paths\.get|Files\.(readAllBytes|write|newInputStream|newOutputStream|copy|move|delete|readAllLines|lines|walk|find))\s*\([^)]*\+'),
                context_checks=[self._is_path_safe],
                suggestion="Use Path.toRealPath() and verify path prefix against allowed directory",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="Path resolved = baseDir.resolve(userInput).normalize().toRealPath();\nif (!resolved.startsWith(baseDir)) throw new SecurityException();",
                attack_vector="User input -> Paths.get + ../ -> File system access -> Data theft",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            # JV-XXE-001: XXE via DocumentBuilderFactory
            SecurityCheck(
                id="JV-XXE-001",
                name="XML External Entity (XXE) via DocumentBuilderFactory",
                category="xxe",
                severity=RiskLevel.CRITICAL,
                description="DocumentBuilderFactory without FEATURE_SECURE_PROCESSING allows XXE attacks",
                pattern=re.compile(r'(?i)DocumentBuilderFactory\.newInstance\s*\('),
                context_checks=[self._is_xxe_safe],
                suggestion="Disable DTD processing and external entity resolution explicitly",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
                attack_vector="XML with external entity -> XXE -> File read / SSRF -> Data breach",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-XXE-002: XXE via SAXParser
            SecurityCheck(
                id="JV-XXE-002",
                name="XML External Entity (XXE) via SAXParser",
                category="xxe",
                severity=RiskLevel.CRITICAL,
                description="SAXParser without configuration allows XXE attacks",
                pattern=re.compile(r'(?i)(SAXParser|SAXBuilder|SAXReader)\.(newInstance|newSAXParser|build|parse)\s*\('),
                context_checks=[self._is_xxe_safe],
                suggestion="Configure SAXParser with XXE protection features",
                cwe_id="CWE-611",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="SAXParserFactory spf = SAXParserFactory.newInstance();\nspf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nSAXParser parser = spf.newSAXParser();",
                attack_vector="XML with external entity -> SAXParser XXE -> SSRF / File disclosure",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-DESER-001: ObjectInputStream
            SecurityCheck(
                id="JV-DESER-001",
                name="Insecure Deserialization via ObjectInputStream",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="Deserializing untrusted data via ObjectInputStream can execute arbitrary code",
                pattern=re.compile(r'(?i)new\s+ObjectInputStream\s*\(|\.readObject\s*\('),
                context_checks=[self._is_deser_safe],
                suggestion="Use ObjectInputFilter to restrict deserialized classes. Prefer JSON/structured data",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"java.base/java.lang.String;!*\");\nois.setObjectInputFilter(filter);",
                attack_vector="Serialized payload -> readObject() -> Gadget chain -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # JV-DESER-002: XMLDecoder
            SecurityCheck(
                id="JV-DESER-002",
                name="Insecure Deserialization via XMLDecoder",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="XMLDecoder deserializes arbitrary objects from XML, enabling RCE",
                pattern=re.compile(r'(?i)new\s+XMLDecoder\s*\('),
                context_checks=[],
                suggestion="Avoid XMLDecoder for untrusted data. Use JAXB or JSON processing",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Instead of XMLDecoder, use:\nUnmarshaller unmarshaller = JAXBContext.newInstance(SafeClass.class).createUnmarshaller();\nSafeClass obj = (SafeClass) unmarshaller.unmarshal(input);",
                attack_vector="XML payload -> XMLDecoder -> Arbitrary object creation -> RCE",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # JV-LDAP-001: LDAP injection
            SecurityCheck(
                id="JV-LDAP-001",
                name="LDAP Injection via DirContext",
                category="ldap-injection",
                severity=RiskLevel.CRITICAL,
                description="Unsanitized user input in LDAP queries allows injection attacks",
                pattern=re.compile(r'(?i)(InitialDirContext|DirContext|LdapTemplate|ldapTemplate)\.(search|lookup)\s*\([^)]*\+'),
                context_checks=[self._is_ldap_safe],
                suggestion="Sanitize LDAP filter input and use parameterized searches when available",
                cwe_id="CWE-90",
                owasp_category="A03:2021 - Injection",
                remediation_example="String sanitized = input.replace(\"(\", \"\\\\28\").replace(\")\", \"\\\\29\");\nctx.search(baseDn, \"(uid=\" + sanitized + \")\", searchCtls);",
                attack_vector="User input -> LDAP search filter -> Injection -> Data extraction / Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SSRF-001: URL.openConnection
            SecurityCheck(
                id="JV-SSRF-001",
                name="Server-Side Request Forgery via URL.openConnection",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="URL.openConnection() with user-controlled URL can target internal services",
                pattern=re.compile(r'(?i)new\s+URL\s*\([^)]*\+|\.openConnection\s*\(\s*\)|HttpURLConnection'),
                context_checks=[self._is_url_safe],
                suggestion="Parse URL and validate hostname against an allowlist of external domains",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="URL url = new URL(inputUrl);\nif (!allowedDomains.contains(url.getHost())) throw new SecurityException();\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();",
                attack_vector="User input -> new URL() -> Internal network request -> Cloud metadata exfil",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # JV-SSRF-002: RestTemplate SSRF
            SecurityCheck(
                id="JV-SSRF-002",
                name="Server-Side Request Forgery via RestTemplate",
                category="ssrf",
                severity=RiskLevel.CRITICAL,
                description="RestTemplate with user-controlled URL enables SSRF",
                pattern=re.compile(r'(?i)restTemplate\.(getForObject|postForObject|exchange|execute|getForEntity|postForEntity)\s*\([^)]*\+'),
                context_checks=[self._is_url_safe],
                suggestion="Validate URL hostname against an allowlist before using RestTemplate",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="URI uri = UriComponentsBuilder.fromUriString(inputUrl).build().toUri();\nif (!allowedHosts.contains(uri.getHost())) throw new SecurityException();\nrestTemplate.getForObject(uri, String.class);",
                attack_vector="User input -> RestTemplate -> Internal API call -> Data exfiltration",
                mitre_technique="T1526 - Cloud Service Discovery",
            ),
            # JV-ELI-001: Expression Language Injection
            SecurityCheck(
                id="JV-ELI-001",
                name="Expression Language Injection via SpEL",
                category="expression-language",
                severity=RiskLevel.CRITICAL,
                description="Spring Expression Language (SpEL) with user input allows RCE",
                pattern=re.compile(r'(?i)ExpressionParser|SpelExpressionParser|ParseExpression|SpelParserConfiguration|new\s+SpelExpressionParser'),
                context_checks=[self._is_spel_safe],
                suggestion="Validate SpEL expressions against an allowlist. Avoid evaluating user input",
                cwe_id="CWE-917",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Avoid evaluating user expressions:\nif (!allowedExpressions.contains(userExpression)) throw new SecurityException();\nExpressionParser parser = new SpelExpressionParser();",
                attack_vector="User input -> SpEL parser -> Expression evaluation -> RCE",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SECRET-001: Hardcoded credential
            SecurityCheck(
                id="JV-SECRET-001",
                name="Hardcoded Secret / Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="API keys, passwords, or tokens hardcoded in source code",
                pattern=re.compile(r'(?i)(String\s+\w*(api[_-]?key|secret[_-]?key|password|passwd|pwd|token|auth[_-]?token|access[_-]?key)\w*\s*=\s*"[^"]{8,}")'),
                context_checks=[self._is_secret_fp],
                suggestion="Use environment variables, a secrets manager (Vault), or config files",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="String apiKey = System.getenv(\"API_KEY\");\nif (apiKey == null) throw new IllegalStateException(\"API_KEY not set\");",
                attack_vector="Source code leak -> Hardcoded credential -> Account compromise",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # JV-SECRET-002: JWT hardcoded secret
            SecurityCheck(
                id="JV-SECRET-002",
                name="Hardcoded JWT Secret",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="JWT signing key hardcoded in source allows token forgery and auth bypass",
                pattern=re.compile(r'(?i)(jwt|JWT).*(secret|key|signing)\s*[:=]\s*"[^"]{4,}"|\.signWith\s*\(\s*"[^"]{4,}"'),
                context_checks=[self._is_secret_fp],
                suggestion="Load JWT secret from environment variables using System.getenv()",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="String jwtSecret = System.getenv(\"JWT_SECRET\");\n// Never hardcode JWT secrets",
                attack_vector="Hardcoded JWT secret -> Forge any JWT token -> Auth bypass",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # JV-TMPL-001: Template injection via FreeMarker
            SecurityCheck(
                id="JV-TMPL-001",
                name="Server-Side Template Injection via FreeMarker",
                category="template-injection",
                severity=RiskLevel.CRITICAL,
                description="FreeMarker template processing with user-controlled template content enables SSTI",
                pattern=re.compile(r'(?i)Template\s*\(|freemarker\.template\.Configuration|newTemplate\s*\('),
                context_checks=[self._is_template_safe],
                suggestion="Avoid processing user input as templates. Use static template files",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="Template template = freemarkerConfig.getTemplate(\"welcome.ftl\"); // Load from file\n// Never create templates from user strings",
                attack_vector="User input -> FreeMarker template -> SSTI -> RCE",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-TMPL-002: Template injection via Velocity
            SecurityCheck(
                id="JV-TMPL-002",
                name="Server-Side Template Injection via Velocity",
                category="template-injection",
                severity=RiskLevel.CRITICAL,
                description="Velocity template engine with user input allows SSTI and RCE",
                pattern=re.compile(r'(?i)Velocity\.evaluate|VelocityEngine\.evaluate|new\s+VelocityEngine'),
                context_checks=[self._is_template_safe],
                suggestion="Use static Velocity templates, never evaluate user input as template",
                cwe_id="CWE-94",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Use static templates:\nTemplate template = Velocity.getTemplate(\"welcome.vm\");\n// Never: Velocity.evaluate(context, writer, \"user\", userInput)",
                attack_vector="User input -> Velocity.evaluate -> SSTI -> Arbitrary code execution",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SECRET-003: Hardcoded AWS/GCP key
            SecurityCheck(
                id="JV-SECRET-003",
                name="Hardcoded Cloud Credential",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded cloud provider credentials (AWS, GCP, Azure) enable account takeover",
                pattern=re.compile(r'(?i)(AKIA[0-9A-Z]{16}|wJalrXUtnFEMI/K7MDENG/bPxRfiCY|-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY)'),
                context_checks=[],
                suggestion="Use cloud IAM roles, instance profiles, or environment variables",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="// AWS: Use DefaultCredentialsProviderChain\ns3Client = AmazonS3ClientBuilder.defaultClient();",
                attack_vector="Hardcoded cloud key -> Cloud console access -> Data breach / Resource hijack",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # JV-LOG4J-001: Log4j JNDI
            SecurityCheck(
                id="JV-LOG4J-001",
                name="Log4j JNDI Lookup (CVE-2021-44228)",
                category="jndi-injection",
                severity=RiskLevel.CRITICAL,
                description="Log4j JndiLookup pattern enables RCE via crafted log messages",
                pattern=re.compile(r'(?i)JndiLookup|log4j.*JNDI|org\.apache\.logging\.log4j'),
                context_checks=[self._is_log4j_patched],
                suggestion="Upgrade Log4j to 2.17.0+ or set log4j2.enableJndiLookup=false",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Set JVM property:\n// -Dlog4j2.enableJndiLookup=false\n// Or upgrade to Log4j >= 2.17.0",
                attack_vector="Crafted log message ${jndi:ldap://...} -> Log4j JNDI -> RCE",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # HIGH CHECKS
        # ====================================================================

        checks.extend([
            # JV-CRYPTO-001: Weak hash
            SecurityCheck(
                id="JV-CRYPTO-001",
                name="Weak Cryptographic Hash (MD5/SHA-1)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA-1 are broken and vulnerable to collision attacks",
                pattern=re.compile(r'(?i)MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1|SHA)"'),
                context_checks=[self._is_crypto_fp],
                suggestion="Use SHA-256, SHA-3, or bcrypt for security-sensitive hashing",
                cwe_id="CWE-328",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n// Prefer bcrypt/scrypt for passwords:\n// BCrypt.checkpw(password, hash);",
                attack_vector="Collision on MD5/SHA-1 -> Certificate forgery -> MITM",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JV-CRYPTO-002: Weak cipher
            SecurityCheck(
                id="JV-CRYPTO-002",
                name="Weak Encryption Algorithm (DES/RC4/Blowfish)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="DES, RC4, and Blowfish are cryptographically broken and should not be used",
                pattern=re.compile(r'(?i)Cipher\.getInstance\s*\(\s*"(DES|DESede|RC4|Blowfish|PBEWithMD5AndDES)'),
                context_checks=[],
                suggestion="Use AES-256 in GCM mode for encryption",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\nSecretKeySpec keySpec = new SecretKeySpec(keyBytes, \"AES\");",
                attack_vector="Weak cipher -> Brute force / Cryptoanalysis -> Data decryption",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JV-CRYPTO-003: ECB mode
            SecurityCheck(
                id="JV-CRYPTO-003",
                name="ECB Encryption Mode (Insecure)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="ECB mode encrypts blocks identically, leaking patterns in plaintext",
                pattern=re.compile(r'(?i)Cipher\.getInstance\s*\(\s*".*/ECB/'),
                context_checks=[],
                suggestion="Use AES/GCM/NoPadding with a random IV for authenticated encryption",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\nGCMParameterSpec spec = new GCMParameterSpec(128, iv);",
                attack_vector="ECB mode -> Pattern leakage in encrypted data -> Information disclosure",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JV-CRYPTO-004: Hardcoded encryption key
            SecurityCheck(
                id="JV-CRYPTO-004",
                name="Hardcoded Encryption Key",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="Encryption keys hardcoded in source can be extracted from code leaks",
                pattern=re.compile(r'(?i)(SecretKeySpec|DESKeySpec|PBEKeySpec)\s*\([^)]*"([^"]{8,})"'),
                context_checks=[self._is_secret_fp],
                suggestion="Store encryption keys in a KMS, environment variables, or secure config",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="String encryptionKey = System.getenv(\"ENCRYPTION_KEY\");\nbyte[] keyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);\nSecretKeySpec keySpec = new SecretKeySpec(keyBytes, \"AES\");",
                attack_vector="Hardcoded key -> Decrypt all protected data -> Full data breach",
                mitre_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
            ),
            # JV-RANDOM-001: Weak random
            SecurityCheck(
                id="JV-RANDOM-001",
                name="Weak Random Number Generator (java.util.Random)",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="java.util.Random is predictable and should not be used for security tokens",
                pattern=re.compile(r'(?i)new\s+java\.util\.Random|new\s+Random\s*\(\s*\)|Math\.random'),
                context_checks=[self._is_random_fp],
                suggestion="Use java.security.SecureRandom for session tokens, passwords, or nonces",
                cwe_id="CWE-330",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="SecureRandom secureRandom = SecureRandom.getInstanceStrong();\nbyte[] token = new byte[32]; secureRandom.nextBytes(token);",
                attack_vector="Predictable random -> Session token forgery -> Auth bypass",
                mitre_technique="T1600 - Weaken Encryption",
            ),
            # JV-TLS-001: Missing certificate validation
            SecurityCheck(
                id="JV-TLS-001",
                name="TLS Certificate Verification Disabled",
                category="tls",
                severity=RiskLevel.HIGH,
                description="Custom TrustManager that accepts all certificates enables MITM attacks",
                pattern=re.compile(r'(?i)TrustManager|X509TrustManager|checkServerTrusted|checkClientTrusted|HostnameVerifier'),
                context_checks=[self._is_tls_safe],
                suggestion="Use the default TrustManager or implement proper certificate verification",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());\ntmf.init((KeyStore) null);\nSSLContext ctx = SSLContext.getInstance(\"TLS\");\nctx.init(tmf.getTrustManagers(), null, null);",
                attack_vector="No cert validation -> MITM -> Credential / Data interception",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # JV-TLS-002: InsecureSkipVerify equivalent
            SecurityCheck(
                id="JV-TLS-002",
                name="SSLContext with TrustAll Certificates",
                category="tls",
                severity=RiskLevel.HIGH,
                description="SSLContext initialized with a trust-all TrustManager disables validation",
                pattern=re.compile(r'(?i)SSLContext\.getInstance\s*\(\s*"TLS"\s*\)\.init\s*\([^)]*null'),
                context_checks=[],
                suggestion="Always provide initialized TrustManager[], never null for trust managers",
                cwe_id="CWE-295",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());\ntmf.init((KeyStore) null);\nctx.init(null, tmf.getTrustManagers(), null);",
                attack_vector="Trust-all SSL -> MITM -> Credential theft",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            # JV-XSS-001: Servlet response XSS
            SecurityCheck(
                id="JV-XSS-001",
                name="Reflected XSS via Servlet Response",
                category="xss",
                severity=RiskLevel.HIGH,
                description="Writing user input directly to HTTP response without escaping enables XSS",
                pattern=re.compile(r'(?i)(response\.getWriter|response\.getOutputStream)\s*\(\s*\)\.(write|print|println)\s*\([^)]*(request\.get|req\.get|req\.param)'),
                context_checks=[self._is_xss_safe],
                suggestion="HTML-encode all user data before writing to response. Use OWASP Java Encoder",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="response.getWriter().write(Encode.forHtml(userInput));\n// Use org.owasp.encoder.Encode",
                attack_vector="User input -> response.write -> XSS -> Session theft / Phishing",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JV-XSS-002: Spring ModelAndView XSS
            SecurityCheck(
                id="JV-XSS-002",
                name="Reflected XSS via Spring ModelAndView",
                category="xss",
                severity=RiskLevel.HIGH,
                description="User input added to Model without escaping can trigger XSS in JSP/Thymeleaf",
                pattern=re.compile(r'(?i)model\.addAttribute\s*\([^)]*(request\.|req\.|user|input|param)'),
                context_checks=[self._is_xss_safe],
                suggestion="Sanitize data before adding to model, or use template auto-escaping",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="model.addAttribute(\"username\", Encode.forHtml(userInput));\n// Ensure Thymeleaf/JSP auto-escaping is enabled",
                attack_vector="User input in Model -> Template renders raw -> XSS -> Session hijack",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JV-CSRF-001: CSRF disabled
            SecurityCheck(
                id="JV-CSRF-001",
                name="CSRF Protection Disabled",
                category="csrf",
                severity=RiskLevel.HIGH,
                description="Disabling CSRF in Spring Security allows cross-site request forgery",
                pattern=re.compile(r'(?i)csrf\(\)\.disable\(\)|\.csrf\(\)\.ignoringAntMatchers|\.and\(\).*csrf\(\)\.disable'),
                context_checks=[self._is_csrf_safe],
                suggestion="Keep CSRF protection enabled. Use csrf().requireCsrfProtectionMatcher() for exemptions",
                cwe_id="CWE-352",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());\n// Never: http.csrf().disable();",
                attack_vector="CSRF disabled -> Attacker forges authenticated POST -> State-changing action",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JV-SESSION-001: Session fixation
            SecurityCheck(
                id="JV-SESSION-001",
                name="Session Fixation Vulnerability",
                category="session",
                severity=RiskLevel.HIGH,
                description="Not invalidating session after authentication allows session fixation",
                pattern=re.compile(r'(?i)request\.getSession\s*\(\s*(true)?\s*\)'),
                context_checks=[self._is_session_fixed],
                suggestion="Call session.invalidate() and create a new session after login",
                cwe_id="CWE-384",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="HttpSession oldSession = request.getSession(false);\nif (oldSession != null) oldSession.invalidate();\nHttpSession newSession = request.getSession(true);",
                attack_vector="Attacker-provided session ID -> User authenticates -> Session remains -> Hijack",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # JV-LOG-001: Log injection
            SecurityCheck(
                id="JV-LOG-001",
                name="Log Injection via Unsanitized Input",
                category="logging",
                severity=RiskLevel.HIGH,
                description="Logging unsanitized user input enables log injection attacks and CRLF injection",
                pattern=re.compile(r'(?i)(logger|log|LOG)\.(info|debug|warn|error|trace|fatal)\s*\([^)]*\+'),
                context_checks=[self._is_log_safe],
                suggestion="Use parameterized logging with {} placeholders instead of concatenation",
                cwe_id="CWE-117",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="logger.info(\"User login attempt from {}\", InetAddress.getByName(clientIp).getHostAddress());\n// Never: logger.info(\"User login from \" + userInput);",
                attack_vector="User input with \\r\\n -> Log injection -> SIEM injection / Log forgery",
                mitre_technique="T1564 - Hide Artifacts",
            ),
            # JV-REFLECT-001: Unsafe reflection
            SecurityCheck(
                id="JV-REFLECT-001",
                name="Unsafe Reflection with User Input",
                category="reflection",
                severity=RiskLevel.HIGH,
                description="Class.forName or Method.invoke with user input can bypass security controls",
                pattern=re.compile(r'(?i)Class\.forName\s*\([^)]*\+|\.getMethod\s*\([^)]*\+|\.invoke\s*\([^)]*\+'),
                context_checks=[],
                suggestion="Validate class/method names against an allowlist before using reflection",
                cwe_id="CWE-470",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="Set<String> allowedClasses = Set.of(\"com.example.SafeClass\");\nif (!allowedClasses.contains(className)) throw new SecurityException();\nClass<?> clazz = Class.forName(className);",
                attack_vector="User input -> Reflection -> Instantiate arbitrary class -> RCE / Bypass",
                mitre_technique="T1059.006 - Command and Scripting Interpreter: Python",
            ),
            # JV-REDIR-001: Open redirect
            SecurityCheck(
                id="JV-REDIR-001",
                name="Open Redirect via sendRedirect",
                category="redirect",
                severity=RiskLevel.HIGH,
                description="Redirecting to user-controlled URLs without validation enables phishing",
                pattern=re.compile(r'(?i)response\.sendRedirect\s*\([^)]*\+|\.sendRedirect\s*\([^)]*(request|req)'),
                context_checks=[self._is_redirect_safe],
                suggestion="Validate redirect URLs against an allowlist of trusted domains",
                cwe_id="CWE-601",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="String url = request.getParameter(\"redirect\");\nif (!allowedRedirects.contains(url)) { response.sendError(400); return; }\nresponse.sendRedirect(url);",
                attack_vector="User-controlled redirect -> Phishing -> Credential theft",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # JV-CORS-001: Wildcard CORS
            SecurityCheck(
                id="JV-CORS-001",
                name="Overly Permissive CORS Policy",
                category="cors",
                severity=RiskLevel.HIGH,
                description="@CrossOrigin or allowedOrigins with wildcard exposes API to any domain",
                pattern=re.compile(r'(?i)@CrossOrigin\s*\(\s*\)|allowedOrigins\s*\(\s*"\*"|\.allowedOrigins\s*\(\s*"\*"'),
                context_checks=[self._is_dev_fp],
                suggestion="Specify exact allowed origins instead of wildcard",
                cwe_id="CWE-942",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="@CrossOrigin(origins = {\"https://app.example.com\"})\n// Never: @CrossOrigin() or origins = \"*\"",
                attack_vector="Wildcard CORS -> Any website reads API response -> Data theft",
                mitre_technique="T1530 - Data from Cloud Storage Object",
            ),
            # JV-COOKIE-001: Insecure cookie
            SecurityCheck(
                id="JV-COOKIE-001",
                name="Insecure Cookie Configuration",
                category="cookies",
                severity=RiskLevel.HIGH,
                description="Cookies without Secure and HttpOnly flags can be intercepted via XSS or HTTP",
                pattern=re.compile(r'(?i)new\s+Cookie\s*\(|response\.addCookie|\.setSecure\s*\(\s*false|\.setHttpOnly\s*\(\s*false'),
                context_checks=[self._is_cookie_safe],
                suggestion="Set Secure=true, HttpOnly=true, and SameSite=Lax on all cookies",
                cwe_id="CWE-614",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="Cookie cookie = new Cookie(\"session\", sessionId);\ncookie.setSecure(true);\ncookie.setHttpOnly(true);\ncookie.setAttribute(\"SameSite\", \"Lax\");\nresponse.addCookie(cookie);",
                attack_vector="Cookie without Secure/HttpOnly -> XSS reads cookie -> Session theft",
                mitre_technique="T1539 - Steal Web Session Cookie",
            ),
            # JV-NOSQL-001: MongoDB injection
            SecurityCheck(
                id="JV-NOSQL-001",
                name="NoSQL Injection via MongoDB $where",
                category="nosql-injection",
                severity=RiskLevel.HIGH,
                description="MongoDB $where operator with user input allows JavaScript injection",
                pattern=re.compile(r'(?i)\$where|BasicDBObject.*\$where|Document.*\$where'),
                context_checks=[self._is_nosql_safe],
                suggestion="Avoid $where operator. Use structured queries with field-based filters",
                cwe_id="CWE-943",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Instead of $where, use:\nDocument filter = new Document(\"username\", userInput);\nFindIterable<Document> docs = collection.find(filter);",
                attack_vector="User input with $where -> MongoDB JS injection -> Auth bypass",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # MEDIUM CHECKS
        # ====================================================================

        checks.extend([
            # JV-VALID-001: Missing @Valid
            SecurityCheck(
                id="JV-VALID-001",
                name="Missing Input Validation on Request Body",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="@RequestBody without @Valid annotation allows malformed data",
                pattern=re.compile(r'(?i)@RequestBody'),
                context_checks=[self._is_validated],
                suggestion="Add @Valid or @Validated annotation before @RequestBody parameter",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="@PostMapping\ntypedResponse<?> createUser(@Valid @RequestBody UserDto userDto) {\n    // userDto is now validated\n}",
                attack_vector="Missing validation -> Malformed payload -> Logic bypass / Injection",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-VALID-002: Missing method validation
            SecurityCheck(
                id="JV-VALID-002",
                name="Controller Without Method-Level Validation",
                category="validation",
                severity=RiskLevel.MEDIUM,
                description="Controller class without @Validated on methods may miss parameter validation",
                pattern=re.compile(r'(?i)@(RestController|Controller)\b'),
                context_checks=[self._is_method_validated],
                suggestion="Add @Validated to controller class or use @Valid on method parameters",
                cwe_id="CWE-20",
                owasp_category="A03:2021 - Injection",
                remediation_example="@RestController\n@Validated\npublic class UserController { ... }",
                attack_vector="Missing validation -> Injection via malformed params -> Data corruption",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-DEPR-001: Deprecated Date API
            SecurityCheck(
                id="JV-DEPR-001",
                name="Deprecated Date/Calendar API Usage",
                category="deprecated",
                severity=RiskLevel.MEDIUM,
                description="java.util.Date, Calendar, SimpleDateFormat are deprecated and error-prone",
                pattern=re.compile(r'(?i)(java\.util\.Date|java\.util\.Calendar|SimpleDateFormat|new\s+Date\s*\(\s*\)|\.getYear\s*\(|\.getMonth\s*\()'),
                context_checks=[self._is_date_fp],
                suggestion="Use java.time API (LocalDate, LocalDateTime, DateTimeFormatter)",
                cwe_id="CWE-477",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="LocalDate now = LocalDate.now();\nDateTimeFormatter formatter = DateTimeFormatter.ofPattern(\"yyyy-MM-dd\");",
                attack_vector="Deprecated API may have unfixed security issues",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-ERROR-001: Stack trace disclosure
            SecurityCheck(
                id="JV-ERROR-001",
                name="Information Disclosure via Stack Trace",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="printStackTrace or getMessage exposed to users leaks internal details",
                pattern=re.compile(r'(?i)(printStackTrace|e\.getMessage\s*\(\s*\)|e\.toString\s*\(\s*\))'),
                context_checks=[self._is_error_safe],
                suggestion="Log stack traces server-side, return generic error messages to clients",
                cwe_id="CWE-209",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="logger.error(\"Database error\", e);\nreturn ResponseEntity.internalServerError().body(\"An unexpected error occurred\");",
                attack_vector="Stack trace -> Internal paths/versions exposed -> Attack surface mapping",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # JV-HEADER-001: Missing security headers
            SecurityCheck(
                id="JV-HEADER-001",
                name="Missing HTTP Security Headers",
                category="headers",
                severity=RiskLevel.MEDIUM,
                description="Spring Security config without security headers increases attack surface",
                pattern=re.compile(r'(?i)(HttpSecurity|WebSecurityConfigurerAdapter|SecurityFilterChain|http\.headers)'),
                context_checks=[self._is_header_safe],
                suggestion="Configure CSP, HSTS, X-Content-Type-Options, X-Frame-Options",
                cwe_id="CWE-693",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="http.headers()\n    .contentTypeOptions()\n    .frameOptions().deny()\n    .httpStrictTransportSecurity().includeSubDomains(true).maxAgeInSeconds(31536000)\n    .contentSecurityPolicy(\"default-src 'self'\");",
                attack_vector="Missing headers -> Clickjacking / MIME sniffing -> XSS / Data theft",
                mitre_technique="T1204.001 - User Execution: Malicious Link",
            ),
            # JV-HTTP-001: HTTP client without SSL
            SecurityCheck(
                id="JV-HTTP-001",
                name="HTTP Client Without Proper SSL",
                category="http",
                severity=RiskLevel.MEDIUM,
                description="RestTemplate, WebClient, or HttpClient without SSL context enables MITM",
                pattern=re.compile(r'(?i)(RestTemplate\s*\(\s*\)|HttpClient\.newHttpClient|WebClient\.create|CloseableHttpClient|HttpClients\.createDefault)'),
                context_checks=[self._is_http_safe],
                suggestion="Configure SSL context and only use HTTPS for external requests",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="SSLContext sslContext = SSLContext.getInstance(\"TLS\");\nsslContext.init(null, trustManagers, null);\nHttpClient client = HttpClient.newBuilder().sslContext(sslContext).build();",
                attack_vector="No SSL -> HTTP traffic interception -> Data exposure",
                mitre_technique="T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            ),
            # JV-ACTUATOR-001: Exposed actuators
            SecurityCheck(
                id="JV-ACTUATOR-001",
                name="Spring Actuator Endpoints Exposed Without Security",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="Actuator endpoints like /actuator/env or /actuator/heapdump leak sensitive data",
                pattern=re.compile(r'(?i)spring-boot-starter-actuator|endpoints\.web\.exposure|Actuator|management\.endpoints'),
                context_checks=[self._is_actuator_secure],
                suggestion="Secure actuator endpoints with Spring Security and restrict exposure",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="management.endpoints.web.exposure.include=health,info\nmanagement.endpoints.web.exposure.exclude=env,heapdump,shutdown",
                attack_vector="Exposed /actuator/env -> Configuration leak -> Credential extraction",
                mitre_technique="T1592 - Gather Victim Host Information",
            ),
            # JV-DOS-001: Regex DoS
            SecurityCheck(
                id="JV-DOS-001",
                name="Regex Denial of Service (ReDoS)",
                category="dos",
                severity=RiskLevel.MEDIUM,
                description="Pattern with nested quantifiers can cause catastrophic backtracking",
                pattern=re.compile(r'\(\s*.\s*\+\s*\)\s*\+|\(\s*.\s*\*\s*\)\s*\*|\(\s*.\s*\*\s*\)\s*\+|\+\s*\+\s*\+'),
                context_checks=[],
                suggestion="Avoid nested quantifiers in regex. Use possessive quantifiers or atomic groups",
                cwe_id="CWE-1333",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of (.*)+, use:\n// Possessive: .*+\n// Or limit input size before matching",
                attack_vector="Crafted input -> Catastrophic backtracking -> CPU exhaustion -> DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            # JV-XPATH-001: XPath injection
            SecurityCheck(
                id="JV-XPATH-001",
                name="XPath Injection",
                category="xpath-injection",
                severity=RiskLevel.MEDIUM,
                description="XPath queries with user input allow injection and data extraction",
                pattern=re.compile(r'(?i)XPath\.newInstance|XPathFactory\.newInstance|\.evaluate\s*\([^)]*\+'),
                context_checks=[self._is_xpath_safe],
                suggestion="Use parameterized XPath queries with variables (xpath.setVariable)",
                cwe_id="CWE-643",
                owasp_category="A03:2021 - Injection",
                remediation_example="xpath.setXPathVariableResolver(v -> {\n    if (\"user\".equals(v.getLocalPart())) return userInput;\n    return null;\n});\n// Use $user in XPath instead of concatenation",
                attack_vector="User input in XPath -> Injection -> XML data extraction",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            # JV-SMTP-001: SMTP header injection
            SecurityCheck(
                id="JV-SMTP-001",
                name="SMTP Header Injection via Email",
                category="smtp",
                severity=RiskLevel.MEDIUM,
                description="User input in email headers can inject additional recipients or content",
                pattern=re.compile(r'(?i)(MimeMessage|SimpleMailMessage|JavaMailSender|spring-boot-starter-mail).*(setSubject|setText|setFrom)\s*\('),
                context_checks=[self._is_smtp_safe],
                suggestion="Sanitize user input used in email headers, remove \\r\\n characters",
                cwe_id="CWE-93",
                owasp_category="A03:2021 - Injection",
                remediation_example="String safeSubject = userInput.replaceAll(\"\\\\r\\\\n\", \" \");\nmessage.setSubject(safeSubject);\n// Never: message.setSubject(userInput);",
                attack_vector="User input with \\r\\n -> SMTP injection -> Spam relay / Phishing",
                mitre_technique="T1566.002 - Phishing: Spearphishing Link",
            ),
            # JV-PATH-003: allowLoadLocalInfile
            SecurityCheck(
                id="JV-PATH-003",
                name="MySQL JDBC allowLoadLocalInfile Enabled",
                category="configuration",
                severity=RiskLevel.MEDIUM,
                description="MySQL JDBC with allowLoadLocalInfile=true allows reading server-side files",
                pattern=re.compile(r'(?i)allowLoadLocalInfile\s*=\s*true|allowUrlInLocalInfile\s*=\s*true'),
                context_checks=[],
                suggestion="Remove allowLoadLocalInfile=true or set to false in JDBC URL",
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="jdbc:mysql://localhost:3306/db?allowLoadLocalInfile=false\n// Or remove the parameter entirely",
                attack_vector="LOAD DATA LOCAL INFILE -> Server-side file read -> Data exfiltration",
                mitre_technique="T1005 - Data from Local System",
            ),
            # JV-RACE-001: Unsynchronized servlet field
            SecurityCheck(
                id="JV-RACE-001",
                name="Potential Race Condition in Servlet",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Servlet instance variables without synchronization can cause race conditions",
                pattern=re.compile(r'(?i)(class\s+\w+\s+extends\s+HttpServlet|@WebServlet)'),
                context_checks=[self._is_servlet_threadsafe],
                suggestion="Avoid mutable instance variables in servlets. Use local variables or synchronization",
                cwe_id="CWE-362",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="// Servlet should not have mutable instance variables:\n// Use @Scope(\"request\") for Spring beans instead",
                attack_vector="Race condition -> Data corruption -> Auth bypass / Privilege escalation",
                mitre_technique="T1055 - Process Injection",
            ),
            # JV-ERROR-002: Empty catch block
            SecurityCheck(
                id="JV-ERROR-002",
                name="Empty Catch Block",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Empty catch blocks swallow exceptions, hiding security-critical failures",
                pattern=re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}'),
                context_checks=[],
                suggestion="Log or handle exceptions properly. Never leave catch blocks empty",
                cwe_id="CWE-391",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example="catch (Exception e) {\n    logger.error(\"Operation failed\", e);\n    throw new ServiceException(\"Operation failed\");\n}",
                attack_vector="Exception swallowed -> Security mechanism fails silently -> Undetected attack",
                mitre_technique="T1564 - Hide Artifacts",
            ),
        ])

        # ====================================================================
        # LOW CHECKS
        # ====================================================================

        checks.extend([
            # JV-DOC-001: Missing JavaDoc
            SecurityCheck(
                id="JV-DOC-001",
                name="Missing JavaDoc Documentation",
                category="documentation",
                severity=RiskLevel.LOW,
                description="Public classes and methods should have JavaDoc comments",
                pattern=re.compile(r'(?i)public\s+(class|interface|enum|void|\w+\s+\w+)\s+\w+'),
                context_checks=[self._is_javadoc_present],
                suggestion="Add JavaDoc with @param and @return tags for public APIs",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="/**\n * Validates and processes user registration.\n * @param userDto The user data transfer object\n * @return The created user entity\n */\npublic User createUser(UserDto userDto) { ... }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JV-MAGIC-001: Magic numbers
            SecurityCheck(
                id="JV-MAGIC-001",
                name="Magic Number Used",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded numeric literals should be named constants",
                pattern=re.compile(r'(?i)(if|while|for|return|==|!=|>|<|>=|<=)\s*[^;]*\b[3-9]\d{1,2}\b'),
                context_checks=[self._is_magic_fp],
                suggestion="Define magic numbers as static final constants",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="private static final int MAX_RETRIES = 3;\nprivate static final int TIMEOUT_SECONDS = 30;\nif (retries >= MAX_RETRIES) { throw new TimeoutException(); }",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JV-COMM-001: TODO
            SecurityCheck(
                id="JV-COMM-001",
                name="TODO Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="TODO comments may indicate incomplete security work or missing features",
                pattern=re.compile(r'(?i)\/\/\s*TODO|TODO:|@TODO|\/\*\s*TODO'),
                context_checks=[],
                suggestion="Address all TODO items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Resolve all TODOs before production. Track in issue tracker.",
                attack_vector="Unresolved TODO may indicate missing security control",
                mitre_technique="N/A",
            ),
            # JV-COMM-002: FIXME/HACK
            SecurityCheck(
                id="JV-COMM-002",
                name="FIXME/HACK Comment in Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="FIXME/HACK comments indicate known issues or workarounds that need addressing",
                pattern=re.compile(r'(?i)(FIXME|HACK|XXX|BUG|TEMP|WORKAROUND)\s*[:!]?'),
                context_checks=[],
                suggestion="Address FIXME/HACK items before production deployment",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove HACK workarounds and implement proper solutions before release",
                attack_vector="Known bug left unaddressed may become exploitable vulnerability",
                mitre_technique="N/A",
            ),
            # JV-DEBUG-001: System.out.println
            SecurityCheck(
                id="JV-DEBUG-001",
                name="System.out.println Debug Statement",
                category="debug",
                severity=RiskLevel.LOW,
                description="System.out.println should be removed from production code",
                pattern=re.compile(r'(?i)System\.(out|err)\.(print|println|printf)'),
                context_checks=[self._is_dev_fp],
                suggestion="Use a logging framework (SLF4J, Logback) with appropriate log levels",
                cwe_id="CWE-489",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation_example="logger.debug(\"Processing user: {}\", userId);\n// Never: System.out.println(\"User: \" + userId);",
                attack_vector="Debug output in production -> Information disclosure",
                mitre_technique="N/A",
            ),
            # JV-IMPORT-001: Unused imports
            SecurityCheck(
                id="JV-IMPORT-001",
                name="Unused Import Statement",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Unused imports clutter code and may indicate dead code paths",
                pattern=re.compile(r'^import\s+[\w.*]+;'),
                context_checks=[self._is_import_used],
                suggestion="Remove unused imports to keep code clean and maintainable",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Remove unused import:\n// import com.example.UnusedClass;",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JV-QUAL-001: Broad exception catch
            SecurityCheck(
                id="JV-QUAL-001",
                name="Catching Broad Exception Type",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Catching Exception or Throwable hides specific error conditions",
                pattern=re.compile(r'catch\s*\(\s*Exception\s+\w+|catch\s*\(\s*Throwable\s+\w+'),
                context_checks=[],
                suggestion="Catch specific exception types instead of generic Exception",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="catch (IOException e) {\n    logger.error(\"File operation failed\", e);\n} catch (SQLException e) {\n    logger.error(\"Database error\", e);\n}",
                attack_vector="Generic catch may hide security-relevant exceptions",
                mitre_technique="N/A",
            ),
            # JV-QUAL-002: String == comparison
            SecurityCheck(
                id="JV-QUAL-002",
                name="String Comparison Using == Instead of .equals()",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Using == for String comparison compares references, not content",
                pattern=re.compile(r'(?i)String\s+\w+.*\n?.*\b==\s*["\x27]|["\x27]\s*==\s*\w+'),
                context_checks=[],
                suggestion="Use .equals() or .equalsIgnoreCase() for String content comparison",
                cwe_id="CWE-597",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="if (userInput.equals(expected)) { // correct\n// NOT: if (userInput == expected) { // wrong",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
            # JV-QUAL-003: Hardcoded localhost
            SecurityCheck(
                id="JV-QUAL-003",
                name="Hardcoded localhost Address",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost may indicate test/debug code left in production",
                pattern=re.compile(r'["\x27]localhost["\x27]|["\x27]127\.0\.0\.1["\x27]|["\x27]0\.0\.0\.0["\x27]'),
                context_checks=[self._is_dev_fp],
                suggestion="Use configuration variables for host:port values",
                cwe_id="CWE-200",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="String host = config.getProperty(\"server.host\");\nint port = config.getInt(\"server.port\", 8080);",
                attack_vector="Hardcoded addresses may expose internal network information",
                mitre_technique="N/A",
            ),
            # JV-QUAL-004: Nested loops
            SecurityCheck(
                id="JV-QUAL-004",
                name="Deeply Nested Loop",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Deeply nested loops (3+ levels) indicate complex code susceptible to bugs",
                pattern=re.compile(r'(?i)(for|while)\s*\([^)]*\)\s*\{[^}]*\b(for|while)\s*\([^)]*\)\s*\{[^}]*\b(for|while)\s*\('),
                context_checks=[],
                suggestion="Refactor deeply nested loops into separate methods",
                cwe_id="CWE-1060",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Extract inner loops to helper methods:\nprivate void processItems(List<Item> items) {\n    for (Item item : items) processItem(item);\n}",
                attack_vector="N/A (Code quality)",
                mitre_technique="N/A",
            ),
        ])

        return checks

    def _detect_frameworks(self, content: str, file_path: Path) -> List[str]:
        """Detect frameworks from imports and annotations."""
        frameworks = []
        if re.search(r'import\s+org\.springframework\.|@SpringBootApplication|@RestController|@RequestMapping', content):
            frameworks.append('spring')
        if re.search(r'import\s+jakarta\.|import\s+javax\.servlet|@WebServlet', content):
            frameworks.append('jakarta-ee')
        if re.search(r'import\s+org\.hibernate\.|@Entity|@Table|@Column', content):
            frameworks.append('hibernate')
        if re.search(r'import\s+javax\.persistence\.|import\s+jakarta\.persistence\.', content):
            frameworks.append('jpa')
        if re.search(r'import\s+io\.quarkus\.|@QuarkusApplication', content):
            frameworks.append('quarkus')
        if re.search(r'import\s+io\.micronaut\.', content):
            frameworks.append('micronaut')
        if re.search(r'import\s+org\.apache\.struts', content):
            frameworks.append('struts')
        if re.search(r'import\s+com\.fasterxml\.jackson\.|@JsonProperty|ObjectMapper', content):
            frameworks.append('jackson')
        if re.search(r'import\s+org\.mybatis\.', content):
            frameworks.append('mybatis')
        if re.search(r'import\s+org\.apache\.logging\.|import\s+org\.slf4j\.|import\s+ch\.qos\.logback', content):
            frameworks.append('logging')
        if re.search(r'import\s+org\.thymeleaf\.', content):
            frameworks.append('thymeleaf')
        if re.search(r'import\s+freemarker\.', content):
            frameworks.append('freemarker')
        if re.search(r'import\s+org\.apache\.velocity', content):
            frameworks.append('velocity')
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
            'request.getParameter': 'HTTP Param',
            'request.getQueryString': 'HTTP Query',
            'request.getHeader': 'HTTP Header',
            'request.getCookies': 'HTTP Cookie',
            'request.getRequestURI': 'HTTP URI',
            'request.getServerName': 'HTTP Host',
            'request.getInputStream': 'HTTP Body',
            'request.getReader': 'HTTP Body',
            'request.getPart': 'HTTP Upload',
            'req.getParameter': 'HTTP Param',
            'req.getHeader': 'HTTP Header',
            'req.getCookies': 'HTTP Cookie',
            '@PathVariable': 'Path Variable',
            '@RequestParam': 'Request Param',
            '@RequestHeader': 'Request Header',
            '@RequestBody': 'Request Body',
            '@ModelAttribute': 'Model Attr',
            '@CookieValue': 'Cookie Value',
            '@Value': 'Config Value',
            'System.getenv': 'Environment Var',
            'System.getProperty': 'System Prop',
        }
        sinks = {
            'executeQuery': 'SQL Query',
            'executeUpdate': 'SQL Update',
            'execute': 'SQL Execute',
            'createQuery': 'JPA Query',
            'createNativeQuery': 'SQL Native',
            'query': 'SQL Query',
            'update': 'SQL Update',
            'queryForObject': 'SQL Query',
            'queryForList': 'SQL Query',
            'jdbcTemplate': 'SQL Access',
            'Runtime.exec': 'Command Exec',
            'ProcessBuilder': 'Command Exec',
            'new File': 'File Access',
            'new FileInputStream': 'File Read',
            'new FileOutputStream': 'File Write',
            'getCanonicalFile': 'File Access',
            'Paths.get': 'File Path',
            'Files.readAllBytes': 'File Read',
            'Files.write': 'File Write',
            'openConnection': 'HTTP Request',
            'openStream': 'HTTP Request',
            'URL': 'HTTP Request',
            'sendRedirect': 'Redirect',
            'lookup': 'JNDI Lookup',
        }
        tainted: Dict[str, str] = {}
        for i, line in enumerate(lines, 1):
            for src, stype in sources.items():
                if src in line:
                    m = re.search(r'(?:String|int|long|boolean|Object)\s+(\w+)\s*=\s*.*' + re.escape(src), line)
                    if not m:
                        m = re.search(r'(\w+)\s*=\s*(request|req)\..+', line)
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
            issue_type="JV-TAINT-001",
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
        self._check_multiline_spel(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SQL injection across multiple lines."""
        for i, line in enumerate(lines):
            if re.search(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+', line):
                for j in range(i, min(i + 5, len(lines))):
                    if '+' in lines[j] and re.search(r'(?i)(executeQuery|executeUpdate|createQuery|query|update)', lines[j]):
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="JV-SQL-007",
                            name="Multi-line SQL Injection via Concatenation",
                            category="sql-injection",
                            severity=RiskLevel.CRITICAL,
                            description="SQL query built across multiple lines with string concatenation",
                            pattern=re.compile(r''),
                            suggestion="Use parameterized queries with ? placeholders",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                            remediation_example='PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);',
                            attack_vector="Multi-line SQL concat -> SQLi -> Database compromise",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    def _check_multiline_spel(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Check for SpEL injection across multiple lines."""
        for i, line in enumerate(lines):
            if 'ExpressionParser' in line or 'SpelExpressionParser' in line:
                for j in range(i, min(i + 3, len(lines))):
                    if '.parseExpression' in lines[j] and '+' in lines[j]:
                        self._add_finding(result, j + 1, lines[j], SecurityCheck(
                            id="JV-ELI-002",
                            name="Multi-line SpEL Injection",
                            category="expression-language",
                            severity=RiskLevel.CRITICAL,
                            description="SpEL expression built with concatenation across multiple lines",
                            pattern=re.compile(r''),
                            suggestion="Validate SpEL expressions against an allowlist",
                            cwe_id="CWE-917",
                            owasp_category="A03:2021 - Injection",
                            remediation_example='ExpressionParser parser = new SpelExpressionParser();\nif (!allowedExpressions.contains(userExpr)) throw new SecurityException();',
                            attack_vector="Multi-line SpEL concat -> Expression injection -> RCE",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                        ))
                        break

    # ====================================================================
    # FALSE POSITIVE FILTERS
    # ====================================================================

    def _is_jpa_parameterized(self, line: str, content: str, frameworks: List[str]) -> bool:
        if ':param' in line or ':name' in line or ':id' in line:
            return True
        if 'setParameter' in content:
            return True
        return False

    def _is_mybatis_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '#{' in line and '${' not in line:
            return True
        if 'mybatis' not in str(self._current_path).lower() and 'mybatis' not in content.lower():
            return True
        return False

    def _is_jndi_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowedJndiNames' in line or 'whitelist' in line.lower():
            return True
        if 'System.getenv' in line:
            return True
        return False

    def _is_cmd_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'(Runtime\.exec|ProcessBuilder)\s*\(\s*"[^"]*"\s*[,\)]', line):
            return True
        if 'sanitize' in line.lower() or 'Sanitizer' in content:
            return True
        return False

    def _is_path_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'new\s+File\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'getCanonicalFile' in content or 'toRealPath' in content or 'normalize' in content:
            return True
        if 'baseDir' in line or 'allowedPath' in line:
            return True
        return False

    def _is_xxe_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'FEATURE_SECURE_PROCESSING' in content or 'disallow-doctype-decl' in content:
            return True
        if 'setFeature' in content and 'external' in content:
            return True
        if 'XMLConstants' in content and 'ACCESS_EXTERNAL' in content:
            return True
        return False

    def _is_deser_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'ObjectInputFilter' in content or 'setObjectInputFilter' in content:
            return True
        if 'readResolve' in content:
            return True
        return False

    def _is_ldap_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        return False

    def _is_url_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if re.search(r'new\s+URL\s*\(\s*"[^"]*"\s*\)', line):
            return True
        if 'allowedDomains' in line or 'allowedHosts' in line or 'whitelist' in line.lower():
            return True
        return False

    def _is_spel_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowedExpressions' in line or 'allowed' in line.lower():
            return True
        if 'T(java' in line:
            return False
        return False

    def _is_secret_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'example' in line.lower() or 'placeholder' in line.lower():
            return True
        if 'System.getenv' in line or 'os.Getenv' in line:
            return True
        if 'test' in line.lower() or '@Test' in content:
            return True
        return False

    def _is_template_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'getTemplate' in line and '"' in line:
            return True
        if 'freeMarkerConfig' in line or 'freemarkerConfig' in line:
            return True
        return False

    def _is_log4j_patched(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'log4j2.enableJndiLookup' in content:
            return True
        if 'FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS' in content:
            return True
        return False

    def _is_crypto_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sha256' in line.lower() or 'sha-256' in line.lower():
            return True
        if 'checksum' in line.lower() or 'hashCode' in line:
            return True
        return False

    def _is_random_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'SecureRandom' in content:
            return True
        if 'animation' in line.lower() or 'game' in line.lower() or 'ui' in line.lower():
            return True
        return False

    def _is_tls_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'TrustManagerFactory' in line or 'CertificatePinner' in line:
            return True
        if 'setDefaultTrustManager' in line:
            return True
        if 'throw CertificateException' in content:
            return True
        return False

    def _is_xss_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'Encode.forHtml' in line or 'Encode.forJavaScript' in line:
            return True
        if 'StringEscapeUtils' in line or 'HtmlUtils' in line:
            return True
        if 'sanitize' in line.lower():
            return True
        if 'thymeleaf' in frameworks and 'th:utext' not in line:
            return True
        return False

    def _is_csrf_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '.and()' in line and 'csrf()' not in line:
            return True
        return False

    def _is_session_fixed(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'invalidate()' in content or 'changeSessionId()' in content:
            return True
        return False

    def _is_log_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'escape' in line.lower():
            return True
        if '{}' in line or '{}' in content:
            return True
        return False

    def _is_redirect_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'allowedRedirects' in line or 'allowed' in line.lower():
            return True
        return False

    def _is_dev_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'development' in line.lower() or 'dev' in line.lower() or 'localhost' in line.lower():
            return True
        return False

    def _is_cookie_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'setSecure(true)' in content and 'setHttpOnly(true)' in content:
            return True
        return False

    def _is_nosql_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'filter' in line.lower() or 'query' in line.lower():
            return True
        return False

    def _is_validated(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '@Valid' in content or '@Validated' in content:
            return True
        if 'Validator' in content or 'Errors' in content:
            return True
        return False

    def _is_method_validated(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '@Validated' in content:
            return True
        return False

    def _is_date_fp(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'LocalDate' in content or 'LocalDateTime' in content:
            return True
        return False

    def _is_error_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'logger' in line.lower() and 'printStackTrace' not in line:
            return True
        if 'sendError' in content or 'ResponseEntity' in content:
            return True
        return False

    def _is_header_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'contentTypeOptions' in content or 'frameOptions' in content:
            return True
        if 'Content-Security-Policy' in content or 'Strict-Transport-Security' in content:
            return True
        if 'X-Content-Type-Options' in content or 'X-Frame-Options' in content:
            return True
        return False

    def _is_http_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sslContext' in line.lower() or 'SSLContext' in line:
            return True
        if 'https://' in line:
            return True
        return False

    def _is_actuator_secure(self, line: str, content: str, frameworks: List[str]) -> bool:
        if '.exclude' in line or '.exposure' in line:
            return True
        if 'security' in line.lower():
            return True
        return False

    def _is_xpath_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'setXPathVariableResolver' in content or 'setVariable' in content:
            return True
        return False

    def _is_smtp_safe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'sanitize' in line.lower() or 'replace' in line:
            return True
        return False

    def _is_servlet_threadsafe(self, line: str, content: str, frameworks: List[str]) -> bool:
        if 'synchronized' in content or 'Atomic' in content:
            return True
        if '@Scope' in content or '@RequestScope' in content:
            return True
        return False

    def _is_javadoc_present(self, line: str, content: str, frameworks: List[str]) -> bool:
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
        if 'private static final' in line or 'public static final' in line:
            return True
        if 'const' in line:
            return True
        return False

    def _is_import_used(self, line: str, content: str, frameworks: List[str]) -> bool:
        match = re.search(r'import\s+([\w.*]+);', line)
        if match:
            import_path = match.group(1)
            class_name = import_path.rstrip('.*').split('.')[-1]
            if class_name and class_name != '*':
                if class_name in content:
                    return True
            if import_path.endswith('.*') and import_path.count('.') >= 1:
                pkg = import_path[:-2]
                if pkg in content:
                    return True
        return False
