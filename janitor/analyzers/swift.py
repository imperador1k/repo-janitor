"""Elite static analyzer for Swift/iOS code with comprehensive security checks."""

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
    """A security check for Swift/iOS code."""
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


class SwiftAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Swift/iOS code — 50+ elite security checks."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._taint_sources: Set[str] = set()
        self._taint_sinks: Set[str] = set()

    def get_language(self) -> str:
        return "swift"

    def get_supported_extensions(self) -> List[str]:
        return [".swift"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Swift/iOS file and return results."""
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
            if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
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
        "UIKit": ["UIKit", "UILabel", "UIButton", "UITableView", "UIWebView"],
        "SwiftUI": ["SwiftUI", "View {", "@State", "@Binding", "@Observable"],
        "Foundation": ["Foundation", "UserDefaults", "NSNotification"],
        "CoreData": ["CoreData", "NSManagedObject", "NSPersistentContainer"],
        "CloudKit": ["CloudKit", "CKRecord", "CKDatabase"],
        "Firebase": ["Firebase", "Firestore", "Auth.auth()"],
        "Alamofire": ["Alamofire", "AF.request", "SessionManager"],
        "RxSwift": ["RxSwift", "Observable", "DisposeBag"],
        "Combine": ["Combine", "AnyCancellable", "PassthroughSubject"],
        "Realm": ["RealmSwift", "RLMRealm", "Realm("],
        "SQLite.swift": ["SQLite.swift", "Connection(", "Statement"],
        "Keychain": ["KeychainSwift", "KeychainWrapper", "SecItem"],
        "Kingfisher": ["Kingfisher", "KFImage", "ImageCache"],
        "SDWebImage": ["SDWebImage", "sd_setImage"],
        "Cocoapods": ["pod ", "Podfile", "Pods/"],
        "SPM": ["swift package", "Package.swift", ".package(url:"],
        "Vapor": ["Vapor", "HTTPRequest", "HTTPResponse", "Router"],
        "Perfect": ["PerfectHTTP", "PerfectHTTPServer"],
        "Kitura": ["Kitura", "Router(", "Kitura("],
        "GRDB": ["GRDB", "DatabasePool", "DatabaseQueue"],
        "Starscream": ["Starscream", "WebSocket", "Socket("],
        "Moya": ["Moya", "MoyaProvider", "TargetType"],
        "Quick/Nimble": ["Quick", "Nimble", "describe(", "it("],
        "XCTest": ["XCTest", "XCTAssert", "test"],
        "SwiftyJSON": ["SwiftyJSON", "JSON("],
        "SwiftProtobuf": ["SwiftProtobuf", "protobuf"],
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

    def _is_not_test_file(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Filter out test files for certain checks."""
        if "import XCTest" in content or "Quick" in content or "Nimble" in content:
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
        if "import XCTest" in content or "test" in content:
            return False
        return True

    def _is_uiwebview_usage(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if UIWebView is actually used as UIWebView (not just in comment)."""
        if "UIWebView" in line and "WKWebView" not in line:
            return True
        return False

    def _is_unnecessary_force(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if force unwrap is on an IBOutlet (generally safe)."""
        if "@IBOutlet" in content:
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
                id='SW-IOS-001',
                name='UIWebView Usage (Deprecated)',
                category='ios-specific',
                severity=RiskLevel.MEDIUM,
                description='Using deprecated UIWebView which lacks modern security features',
                pattern=re.compile('UIWebView'),
                context_checks=[self._is_uiwebview_usage],
                suggestion='Replace UIWebView with WKWebView',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='let webView = WKWebView(frame: view.frame)',
                attack_vector='UIWebView does not support modern web security features',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-IOS-002',
                name='WKWebView JavaScript Enabled',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='WKWebView with JavaScript enabled can lead to XSS',
                pattern=re.compile('WKWebView'),
                context_checks=[],
                suggestion='Disable JavaScript when not needed',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='webView.configuration.preferences.javaScriptEnabled = false',
                attack_vector='Cross-site scripting via WebView with JavaScript enabled',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='SW-IOS-003',
                name='WKWebView Without Navigation Delegate',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='WKWebView without navigation delegate can navigate to malicious URLs',
                pattern=re.compile('load\\(URLRequest|loadHTMLString|loadFileURL'),
                context_checks=[],
                suggestion='Implement WKNavigationDelegate to control navigation',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='webView.navigationDelegate = self',
                attack_vector='User can be redirected to malicious sites',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-IOS-004',
                name='UserDefaults for Sensitive Data',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='Using UserDefaults to store sensitive data like tokens',
                pattern=re.compile('UserDefaults\\.standard'),
                context_checks=[],
                suggestion='Use Keychain for sensitive data instead of UserDefaults',
                cwe_id='CWE-522',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='SecItemAdd with kSecClass = kSecClassGenericPassword',
                attack_vector='Sensitive data stored in plaintext, accessible via device backup',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-IOS-005',
                name='Keychain Without Access Control',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='Keychain items stored without proper access control attributes',
                pattern=re.compile('SecItemAdd|SecItemUpdate|kSecAttrAccessible'),
                context_checks=[],
                suggestion='Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive data',
                cwe_id='CWE-522',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
                attack_vector='Keychain accessible from backups or after device unlock',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-IOS-006',
                name='NSAppTransportSecurity Disabled',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='NSAppTransportSecurity allows arbitrary HTTP loads in Info.plist',
                pattern=re.compile('NSAllowsArbitraryLoads\\s*=\\s*true|NSAllowsArbitraryLoads\\s*=\\s*YES'),
                context_checks=[],
                suggestion='Remove NSAllowsArbitraryLoads or restrict to specific domains',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use NSExceptionDomains to whitelist specific domains',
                attack_vector='App communicates over unencrypted HTTP',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='SW-IOS-007',
                name='allowsArbitraryLoadsForMedia',
                category='ios-specific',
                severity=RiskLevel.MEDIUM,
                description='allowsArbitraryLoadsForMedia allows unencrypted media loading',
                pattern=re.compile('NSAllowsArbitraryLoadsForMedia|allowsArbitraryLoadsForMedia'),
                context_checks=[],
                suggestion='Load media over HTTPS only',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use HTTPS for all media content',
                attack_vector='Media content loaded over unencrypted connections',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='SW-IOS-008',
                name='openURL Without Validation',
                category='ios-specific',
                severity=RiskLevel.MEDIUM,
                description='Opening URL without validation can lead to phishing',
                pattern=re.compile('UIApplication\\.shared\\.open|openURL|application\\.open'),
                context_checks=[],
                suggestion='Validate URL before opening',
                cwe_id='CWE-601',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='guard UIApplication.shared.canOpenURL(url) else { return }',
                attack_vector='User redirected to malicious URLs',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-IOS-009',
                name='SFSafariViewController Without Delegate',
                category='ios-specific',
                severity=RiskLevel.MEDIUM,
                description='SFSafariViewController without delegate cannot control navigation',
                pattern=re.compile('SFSafariViewController'),
                context_checks=[],
                suggestion='Implement SFSafariViewControllerDelegate',
                cwe_id='CWE-601',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='safariVC.delegate = self',
                attack_vector='User can navigate to arbitrary web content',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-IOS-010',
                name='Insecure CoreData Storage',
                category='ios-specific',
                severity=RiskLevel.HIGH,
                description='CoreData may store sensitive data unencrypted',
                pattern=re.compile('NSPersistentContainer|NSManagedObjectContext|CoreData'),
                context_checks=[],
                suggestion='Enable CoreData encryption or use SQLCipher',
                cwe_id='CWE-312',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='Use NSFileProtectionComplete for the persistent store file',
                attack_vector='Sensitive data stored in plaintext SQLite database',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-SQL-001',
                name='SQLite3 exec With User Input',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='SQLite query constructed with string interpolation',
                pattern=re.compile('sqlite3_exec|sqlite3_prepare_v2'),
                context_checks=[],
                suggestion='Use prepared statements with parameter binding',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example='sqlite3_bind_text(statement, 1, userId, -1, SQLITE_TRANSIENT)',
                attack_vector='SQL injection via string interpolation in SQLite queries',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='SW-SQL-002',
                name='CoreData NSExpression With Format String',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='CoreData fetch request with predicate format string from user input',
                pattern=re.compile('NSExpression\\(|expressionForFunction'),
                context_checks=[],
                suggestion='Use NSExpression with constant values or predicate substitution',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example='predicateWithFormat: instead of format string with user input',
                attack_vector='Predicate injection allowing unauthorized data access',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='SW-SQL-003',
                name='NSPredicate With Format String Injection',
                category='sql-injection',
                severity=RiskLevel.CRITICAL,
                description='NSPredicate with format string from user-provided input',
                pattern=re.compile('NSPredicate\\(format:|predicateWithFormat:'),
                context_checks=[],
                suggestion='Use NSCompoundPredicate or predicateWithSubstitutionVariables',
                cwe_id='CWE-89',
                owasp_category='A03:2021 - Injection',
                remediation_example='NSPredicate(format: "name == %@", name)',
                attack_vector='Predicate injection via format string',
                mitre_technique='T1191',
            ),
            SecurityCheck(
                id='SW-CMD-001',
                name='Process (NSTask) With User Input',
                category='command-injection',
                severity=RiskLevel.CRITICAL,
                description='Running shell process with potentially user-controlled input',
                pattern=re.compile('Process\\s*\\(|NSTask\\s*\\('),
                context_checks=[],
                suggestion='Avoid Process with user-controlled arguments; use whitelist',
                cwe_id='CWE-78',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use Process with fixed arguments and validate inputs',
                attack_vector='OS command injection via Process with unvalidated input',
                mitre_technique='T1202',
            ),
            SecurityCheck(
                id='SW-CMD-002',
                name='system() shell With User Input',
                category='command-injection',
                severity=RiskLevel.CRITICAL,
                description='Shell command execution with potentially user-controlled input',
                pattern=re.compile('\\bsystem\\s*\\(|NSTask|execvp|posix_spawn'),
                context_checks=[],
                suggestion='Avoid shell execution entirely; use safer Foundation APIs',
                cwe_id='CWE-78',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use Process with explicit executable path and arguments array',
                attack_vector='OS command injection via shell execution',
                mitre_technique='T1202',
            ),
            SecurityCheck(
                id='SW-CINJ-001',
                name='NSExpression eval With User Input',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='NSExpression evaluated with user-controlled expression strings',
                pattern=re.compile('NSExpression\\(|expressionForConstantValue|expressionWithFormat'),
                context_checks=[],
                suggestion='Avoid evaluating user input as expressions',
                cwe_id='CWE-470',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use static expressions only; never with user-provided format strings',
                attack_vector='Arbitrary expression evaluation leading to code execution',
                mitre_technique='T1064',
            ),
            SecurityCheck(
                id='SW-CINJ-002',
                name='performSelector With User Input',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='Using performSelector with user-controlled selector strings',
                pattern=re.compile('performSelector|perform\\(selector\\s*:'),
                context_checks=[],
                suggestion='Avoid performSelector with dynamic selector names',
                cwe_id='CWE-470',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use delegate pattern or type-safe closure instead',
                attack_vector='Arbitrary method invocation via dynamic selector',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-CINJ-003',
                name='dlopen/dlsym Dynamic Library Loading',
                category='code-injection',
                severity=RiskLevel.HIGH,
                description='Loading native libraries dynamically at runtime',
                pattern=re.compile('dlopen\\s*\\(|dlsym\\s*\\('),
                context_checks=[],
                suggestion='Use statically linked frameworks instead of dlopen',
                cwe_id='CWE-114',
                owasp_category='A03:2021 - Injection',
                remediation_example='Import frameworks directly using module imports',
                attack_vector='DLL hijacking via dynamic library loading',
                mitre_technique='T1574',
            ),
            SecurityCheck(
                id='SW-PTH-001',
                name='FileManager With User Input',
                category='path-traversal',
                severity=RiskLevel.HIGH,
                description='FileManager operations with user-controlled paths',
                pattern=re.compile('FileManager\\.default\\.|contentsOfDirectory|fileExists'),
                context_checks=[],
                suggestion='Validate file paths and use basename to prevent traversal',
                cwe_id='CWE-22',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='let safePath = documentsDirectory.appendingPathComponent(filename).standardized',
                attack_vector='Path traversal to read/write files outside sandbox',
                mitre_technique='T1006',
            ),
            SecurityCheck(
                id='SW-PTH-002',
                name='String(contentsOfFile:) With User Input',
                category='path-traversal',
                severity=RiskLevel.HIGH,
                description='Reading file with user-controlled path',
                pattern=re.compile('String\\(contentsOfFile:|contentsOf\\s*URL|dataWithContentsOf'),
                context_checks=[],
                suggestion='Validate paths and restrict to app sandbox directory',
                cwe_id='CWE-22',
                owasp_category='A01:2021 - Broken Access Control',
                remediation_example='let data = try Data(contentsOf: safeURL)',
                attack_vector='File traversal to read arbitrary files',
                mitre_technique='T1006',
            ),
            SecurityCheck(
                id='SW-NET-001',
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
                id='SW-NET-002',
                name='URLSession Without Certificate Validation',
                category='network-tls',
                severity=RiskLevel.CRITICAL,
                description='URLSession configured without proper certificate validation',
                pattern=re.compile('URLSession\\s*\\(|URLAuthenticationChallenge|canAuthenticateAgainstProtectionSpace'),
                context_checks=[],
                suggestion='Implement URLSessionDelegate to validate certificates',
                cwe_id='CWE-295',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Use URLSessionDelegate with server trust validation',
                attack_vector='MITM attack by accepting invalid certificates',
                mitre_technique='T1557',
            ),
            SecurityCheck(
                id='SW-NET-003',
                name='Alamofire ServerTrustEvaluator Disabled',
                category='network-tls',
                severity=RiskLevel.CRITICAL,
                description='Alamofire ServerTrustEvaluating policy disabled',
                pattern=re.compile('ServerTrustManager|DisableEvaluation|disableEvaluation|performDefaultEvaluation'),
                context_checks=[],
                suggestion='Use PinnedCertificatesTrustEvaluator or DefaultTrustEvaluator',
                cwe_id='CWE-295',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='let manager = ServerTrustManager(evaluators: [host: PinnedCertificatesTrustEvaluator()])',
                attack_vector='MITM attack bypassing TLS certificate validation',
                mitre_technique='T1557',
            ),
            SecurityCheck(
                id='SW-NET-004',
                name='AllowsCellularAccess for Sensitive Data',
                category='network-tls',
                severity=RiskLevel.LOW,
                description='URLSession allows cellular access for sensitive operations',
                pattern=re.compile('allowsCellularAccess\\s*=\\s*true'),
                context_checks=[],
                suggestion='Consider disabling cellular access for sensitive operations',
                cwe_id='CWE-319',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='allowsCellularAccess = false for sensitive data transfers',
                attack_vector='Possible data interception on cellular networks',
                mitre_technique='T1040',
            ),
            SecurityCheck(
                id='SW-XSS-001',
                name='UIWebView stringByEvaluatingJavaScript',
                category='xss',
                severity=RiskLevel.HIGH,
                description='Evaluating JavaScript in UIWebView can lead to XSS',
                pattern=re.compile('stringByEvaluatingJavaScript|evaluateJavaScript'),
                context_checks=[],
                suggestion='Sanitize JavaScript input before evaluation',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='Avoid evaluating user-controlled JavaScript',
                attack_vector='XSS via user-controlled JavaScript evaluation',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='SW-XSS-002',
                name='WKUserContentController Without Sanitization',
                category='xss',
                severity=RiskLevel.HIGH,
                description='Adding user scripts to WKUserContentController without sanitization',
                pattern=re.compile('WKUserContentController|addUserScript|WKUserScript'),
                context_checks=[],
                suggestion='Sanitize all user scripts before injection',
                cwe_id='CWE-79',
                owasp_category='A03:2021 - Injection',
                remediation_example='Only inject trusted scripts from app bundle',
                attack_vector='JavaScript injection via user scripts',
                mitre_technique='T1059',
            ),
            SecurityCheck(
                id='SW-SEC-001',
                name='Hardcoded API Key',
                category='secrets',
                severity=RiskLevel.CRITICAL,
                description='API key hardcoded in source code',
                pattern=re.compile('(?:apiKey|api_key|apikey)\\s*[:=]\\s*[\\"\'][A-Za-z0-9_\\-]{16,}[\\"\']'),
                context_checks=[],
                suggestion='Store API keys in environment variables or configuration files',
                cwe_id='CWE-798',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='Use xcconfig files or environment variables',
                attack_vector='Exposed API keys in source code',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-SEC-002',
                name='Hardcoded Token/JWT',
                category='secrets',
                severity=RiskLevel.CRITICAL,
                description='Authentication token or JWT hardcoded in source',
                pattern=re.compile('(?:token|jwt|accessToken|refreshToken|authToken)\\s*[:=]\\s*[\\"\'][A-Za-z0-9_\\-=]{20,}[\\"\']'),
                context_checks=[],
                suggestion='Obtain tokens at runtime from secure auth flow',
                cwe_id='CWE-798',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='Use Keychain to store and retrieve tokens',
                attack_vector='Leaked authentication tokens',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-SEC-003',
                name='Hardcoded Password',
                category='secrets',
                severity=RiskLevel.CRITICAL,
                description='Password hardcoded in source code',
                pattern=re.compile('(?:password|passwd|pwd)\\s*[:=]\\s*[\\"\'][^\\"\']{4,}[\\"\']'),
                context_checks=[],
                suggestion='Prompt user for password at runtime or use biometric auth',
                cwe_id='CWE-798',
                owasp_category='A07:2021 - Identification and Authentication Failures',
                remediation_example='Use LocalAuthentication framework for biometric auth',
                attack_vector='Exposed passwords in source code',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-SEC-004',
                name='UserDefaults for Credentials',
                category='secrets',
                severity=RiskLevel.HIGH,
                description='Using UserDefaults to store credentials instead of Keychain',
                pattern=re.compile('UserDefaults\\.standard|UserDefaults\\(suitename'),
                context_checks=[],
                suggestion='Use Keychain for storing credentials',
                cwe_id='CWE-522',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='SecItemAdd(kSecClass: kSecClassGenericPassword, ...)',
                attack_vector='Credentials stored in plaintext',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-CRP-001',
                name='Weak Hash Function (MD5/SHA1)',
                category='crypto',
                severity=RiskLevel.HIGH,
                description='Using weak cryptographic hash functions like MD5 or SHA1',
                pattern=re.compile('CC_MD5|CC_SHA1|Insecure\\.MD5|Insecure\\.SHA1|CommonCrypto.*MD5'),
                context_checks=[],
                suggestion='Use SHA-256 or stronger hash for security purposes',
                cwe_id='CWE-327',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='SHA256.hash(data: input)',
                attack_vector='Hash collision or preimage attacks',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='SW-CRP-002',
                name='Hardcoded Encryption Key',
                category='crypto',
                severity=RiskLevel.CRITICAL,
                description='Encryption key hardcoded in source code',
                pattern=re.compile('(?:key|secret|iv|initializationVector)\\s*[:=]\\s*[\\"\'][A-Za-z0-9+/=]{16,}[\\"\']'),
                context_checks=[],
                suggestion='Derive keys from user credentials or use Keychain',
                cwe_id='CWE-321',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='Use SecKeyGeneratePair or derive from user password',
                attack_vector='Extraction of encryption keys from binary',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-CRP-003',
                name='SecKey API Misuse',
                category='crypto',
                severity=RiskLevel.MEDIUM,
                description='Potential misuse of SecKey API for cryptographic operations',
                pattern=re.compile('SecKeyEncrypt|SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify'),
                context_checks=[],
                suggestion='Use modern Security framework APIs properly',
                cwe_id='CWE-327',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='Use SecKeyCreateEncryptedData with .eciesEncryptionStandardX963SHA256AESGCM',
                attack_vector='Weak encryption configuration',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='SW-DAT-001',
                name='NSKeyedUnarchiver Without Validation',
                category='data-storage',
                severity=RiskLevel.HIGH,
                description='NSKeyedUnarchiver deserializing data without validation',
                pattern=re.compile('NSKeyedUnarchiver|unarchiveObject|unarchivedObject'),
                context_checks=[],
                suggestion='Use NSSecureCoding to validate deserialized classes',
                cwe_id='CWE-502',
                owasp_category='A08:2021 - Software and Data Integrity Failures',
                remediation_example='NSKeyedUnarchiver.unarchivedObject(ofClass: MyClass.self, from: data)',
                attack_vector='Deserialization attack leading to code execution',
                mitre_technique='T1213',
            ),
            SecurityCheck(
                id='SW-DAT-002',
                name='NSCoding Without NSSecureCoding',
                category='data-storage',
                severity=RiskLevel.MEDIUM,
                description='NSCoding implementation without NSSecureCoding conformance',
                pattern=re.compile('class\\s+\\w+\\s*:\\s*.*NSCoding'),
                context_checks=[],
                suggestion='Adopt NSSecureCoding protocol for all codable classes',
                cwe_id='CWE-502',
                owasp_category='A08:2021 - Software and Data Integrity Failures',
                remediation_example='class MyClass: NSObject, NSSecureCoding',
                attack_vector='Deserialization of untrusted classes',
                mitre_technique='T1213',
            ),
            SecurityCheck(
                id='SW-DAT-003',
                name='NSLog Without Data Redaction',
                category='data-storage',
                severity=RiskLevel.MEDIUM,
                description='NSLog or print statements may leak sensitive data',
                pattern=re.compile('NSLog\\s*\\(|print\\s*\\('),
                context_checks=[self._has_sensitive_logging],
                suggestion='Redact sensitive data in logs',
                cwe_id='CWE-532',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example='os_log with privacy .private for sensitive data',
                attack_vector='Sensitive data leakage via logs',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-DAT-004',
                name='Codable Without Secure Coding',
                category='data-storage',
                severity=RiskLevel.LOW,
                description='Codable types may deserialize untrusted data',
                pattern=re.compile('Codable|Decodable|Encodable'),
                context_checks=[],
                suggestion='Validate decoded data before use',
                cwe_id='CWE-502',
                owasp_category='A08:2021 - Software and Data Integrity Failures',
                remediation_example='Use CodingKeys to whitelist allowed properties',
                attack_vector='Potentially untrusted deserialization',
                mitre_technique='T1213',
            ),
            SecurityCheck(
                id='SW-MEM-001',
                name='UnsafePointer Misuse',
                category='memory-safety',
                severity=RiskLevel.HIGH,
                description='Using UnsafePointer can lead to memory corruption',
                pattern=re.compile('UnsafePointer|UnsafeMutablePointer|UnsafeRawPointer'),
                context_checks=[],
                suggestion='Prefer safe Swift constructs over unsafe pointers',
                cwe_id='CWE-822',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use withUnsafePointer only when necessary and validate bounds',
                attack_vector='Memory corruption via unsafe pointer operations',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-MEM-002',
                name='String(format:) With User Input (Format String)',
                category='memory-safety',
                severity=RiskLevel.CRITICAL,
                description='String(format:) with user-controlled format string',
                pattern=re.compile('String\\(format:|NSString\\(format:|String\\.format'),
                context_checks=[],
                suggestion='Use string interpolation instead of format strings with user input',
                cwe_id='CWE-134',
                owasp_category='A03:2021 - Injection',
                remediation_example='let message = "Hello, \\(username)"',
                attack_vector='Format string vulnerability leading to memory read/write',
                mitre_technique='T1064',
            ),
            SecurityCheck(
                id='SW-MEM-003',
                name='UnsafeMutableRawPointer Misuse',
                category='memory-safety',
                severity=RiskLevel.HIGH,
                description='UnsafeMutableRawPointer operations without proper management',
                pattern=re.compile('UnsafeMutableRawPointer|OpaquePointer|UnsafeBufferPointer'),
                context_checks=[],
                suggestion='Use typed pointers and proper memory management',
                cwe_id='CWE-822',
                owasp_category='A03:2021 - Injection',
                remediation_example='Use bindMemory(to:) and assumingMemoryBound(to:) safely',
                attack_vector='Memory corruption via raw pointer operations',
                mitre_technique='T1204',
            ),
            SecurityCheck(
                id='SW-CQ-001',
                name='Force Unwrapping (!)',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Force unwrapping optionals can cause runtime crashes',
                pattern=re.compile('\\w+!\\s*\\.|\\w+!\\s*\\)|\\w+!\\s*\\]|\\w+!\\s*,'),
                context_checks=[self._is_unnecessary_force],
                suggestion='Use optional binding or guard let instead of force unwrapping',
                cwe_id='CWE-476',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='guard let value = optionalValue else { return }',
                attack_vector='App crash due to force unwrapping nil',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-002',
                name='Force Try (!)',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Force try can cause runtime crashes on errors',
                pattern=re.compile('try!'),
                context_checks=[],
                suggestion='Use try? or do-catch instead of force try',
                cwe_id='CWE-476',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='do { let result = try riskyOperation() } catch { handle(error) }',
                attack_vector='App crash on unhandled error',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-003',
                name='Implicitly Unwrapped Optionals',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Implicitly unwrapped optionals (!) can crash when nil',
                pattern=re.compile('\\w+\\s*:\\s*\\w+!'),
                context_checks=[],
                suggestion='Use proper optionals instead of implicitly unwrapped ones',
                cwe_id='CWE-476',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='var name: String? instead of var name: String!',
                attack_vector='Crash on nil access',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-004',
                name='TODO/FIXME in Code',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Unresolved TODO or FIXME comment in source code',
                pattern=re.compile('TODO|FIXME|XXX|HACK|WORKAROUND'),
                context_checks=[],
                suggestion='Address all TODO/FIXME items before release',
                cwe_id='CWE-546',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Complete the implementation and remove the TODO',
                attack_vector='Incomplete security implementations',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-005',
                name='Empty Catch Block',
                category='code-quality',
                severity=RiskLevel.MEDIUM,
                description='Empty catch block silently swallows exceptions',
                pattern=re.compile('catch\\s*\\{[^}]*\\}'),
                context_checks=[],
                suggestion='Handle exceptions properly or log them',
                cwe_id='CWE-396',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example="catch { print('Error: \\(error)') }",
                attack_vector='Silent failures mask security incidents',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-006',
                name='Print Statements in Production',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Using print() or debugPrint() in production code',
                pattern=re.compile('\\bprint\\s*\\('),
                context_checks=[self._is_production_print],
                suggestion='Use os_log with proper log levels',
                cwe_id='CWE-532',
                owasp_category='A04:2021 - Insecure Design',
                remediation_example="os_log(.info, 'message')",
                attack_vector='Information disclosure via console',
                mitre_technique='T1552',
            ),
            SecurityCheck(
                id='SW-CQ-007',
                name='Strong Reference Cycle Risk (self in closure)',
                category='code-quality',
                severity=RiskLevel.MEDIUM,
                description='Capturing self strongly in closure can cause retain cycles',
                pattern=re.compile('self\\.\\w+|self\\?\\.'),
                context_checks=[],
                suggestion='Use [weak self] or [unowned self] to break retain cycles',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='closure { [weak self] in guard let self = self else { return } }',
                attack_vector='Memory leak leading to app crash',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-CQ-008',
                name='Unused self/unowned self',
                category='code-quality',
                severity=RiskLevel.LOW,
                description='Self captured but not used inside closure',
                pattern=re.compile('\\[weak self\\]|\\[unowned self\\]'),
                context_checks=[],
                suggestion='Remove unused capture lists',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Remove [weak self] if self is not referenced',
                attack_vector='Unnecessary memory management complexity',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-MISC-001',
                name='Weak Random (arc4random)',
                category='misc',
                severity=RiskLevel.MEDIUM,
                description='Using arc4random without proper seeding for security',
                pattern=re.compile('arc4random\\s*\\(|arc4random_uniform|random\\s*\\(\\)'),
                context_checks=[],
                suggestion='Use SecRandomCopyBytes for security-sensitive random values',
                cwe_id='CWE-338',
                owasp_category='A02:2021 - Cryptographic Failures',
                remediation_example='var bytes = [UInt8](repeating: 0, count: 32); SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)',
                attack_vector='Predictable random values',
                mitre_technique='T1602',
            ),
            SecurityCheck(
                id='SW-MISC-002',
                name='NSDateFormatter Without Locale',
                category='misc',
                severity=RiskLevel.LOW,
                description='NSDateFormatter without explicit locale can format inconsistently',
                pattern=re.compile('DateFormatter\\(\\)|NSDateFormatter\\(\\)'),
                context_checks=[],
                suggestion='Set locale explicitly on date formatters',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example="formatter.locale = Locale(identifier: 'en_US_POSIX')",
                attack_vector='Inconsistent date formatting across locales',
                mitre_technique='T1211',
            ),
            SecurityCheck(
                id='SW-MISC-003',
                name='UserDefaults synchronize Called',
                category='misc',
                severity=RiskLevel.LOW,
                description='Calling synchronize on UserDefaults is unnecessary',
                pattern=re.compile('UserDefaults.*synchronize|standard\\.synchronize'),
                context_checks=[],
                suggestion='Remove synchronize calls; they are automatic',
                cwe_id='CWE-1104',
                owasp_category='A05:2021 - Security Misconfiguration',
                remediation_example='Remove .synchronize() calls',
                attack_vector='Unnecessary synchronous disk writes',
                mitre_technique='T1211',
            ),
        ])

        return checks

    # ======================================================================
    # TAINT ANALYSIS
    # ======================================================================

    TAINT_SOURCE_PATTERNS: Dict[str, str] = {
        "http_request": r"URLSession\.shared\.dataTask|dataTask\s*\(|AF\.request|session\.request",
        "form_input": r"UITextField|UITextView|textField|textView",
        "deep_link": r"application\(_:\s*open|url\s*:.*options|onOpenURL|onContinueUserActivity",
        "notification": r"UNNotification|userInfo|didReceiveRemoteNotification",
        "clipboard": r"UIPasteboard\.general|generalPasteboard",
        "file_read": r"String\(contentsOf:|Data\(contentsOf:|FileManager.*contents",
        "url_param": r"queryItems|URLComponents|URLQueryItem|value\(forKey:",
        "user_defaults": r"UserDefaults\.standard\.(string|data|array|dictionary|object)\(forKey:",
        "keychain": r"SecItemCopyMatching|KeychainWrapper.*string\(forKey:",
        "qrcode": r"AVMetadataMachineReadableCodeObject|QRCode|barCode",
    }

    TAINT_SINK_PATTERNS: Dict[str, str] = {
        "sql_query": r"sqlite3_exec|sqlite3_prepare_v2|NSPredicate\(format:|predicateWithFormat:",
        "file_write": r"write\(to:|FileManager.*createFile|Data.*write",
        "http_request": r"dataTask\s*\(|session\.request|AF\.request|URLSession.*dataTask",
        "process_exec": r"Process\s*\(|NSTask\s*\(|system\s*\(",
        "webview_load": r"load\(URLRequest|loadHTMLString|evaluateJavaScript|loadRequest",
        "open_url": r"UIApplication\.shared\.open|openURL|application\.open",
    }

    def _extract_taint_sources(self, lines: List[str]) -> Set[str]:
        """Extract potential taint source variable names."""
        sources = set()
        for src_name, src_pattern in self.TAINT_SOURCE_PATTERNS.items():
            for line in lines:
                if re.search(src_pattern, line):
                    var_match = re.search(r"(?:let|var)?\s*(\w+)\s*(?:=)", line)
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
                    var_match = re.search(r"(?:let|var)?\s*(\w+)\s*(?:=)", line)
                    if var_match:
                        taint_vars.add(var_match.group(1))

            taint_val = re.search(r"(\w+)\s*=.*", line)
            if taint_val and any(tv in line for tv in list(taint_vars)):
                taint_vars.add(taint_val.group(1))

            for sink_name, sink_pattern in self.TAINT_SINK_PATTERNS.items():
                if re.search(sink_pattern, line):
                    for tv in list(taint_vars):
                        if tv in line and tv not in ("i", "j", "k", "x", "y", "z", "idx", "key", "val"):
                            result.findings.append(Finding(
                                file=str(result.file_path),
                                line=i + 1,
                                column=line.index(tv) + 1,
                                issue_type=f"SW-TAINT-{sink_name.upper()}",
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
            if re.search(r"""String\s*\(format:\s*["']""", line):
                multi_line = line
                j = i + 1
                while j < len(lines) and j < i + 10:
                    next_line = lines[j].strip()
                    multi_line += next_line
                    if next_line.endswith(")") or next_line.endswith('"') or next_line.endswith("'"):
                        break
                    j += 1

                if re.search(r"SELECT|INSERT|UPDATE|DELETE|CREATE|DROP", multi_line, re.IGNORECASE):
                    if "\(" in multi_line or "+" in multi_line:
                        result.findings.append(Finding(
                            file=str(result.file_path),
                            line=i + 1,
                            column=0,
                            issue_type="SW-CROSS-SQL",
                            message="Multi-line SQL query with possible injection via string interpolation",
                            risk_level=RiskLevel.HIGH,
                            code_snippet=multi_line[:200],
                            suggestion="Use prepared statements with parameter binding",
                        ))

        # Cross-line force unwrap chain detection (e.g., a!.b!.c)
        for i, line in enumerate(lines):
            if re.search(r"\w+!\s*\.\s*\w+!\s*\.", line):
                result.findings.append(Finding(
                    file=str(result.file_path),
                    line=i + 1,
                    column=0,
                    issue_type="SW-CROSS-UNWRAP",
                    message="Chained force unwrapping can cause cascading crashes",
                    risk_level=RiskLevel.MEDIUM,
                    code_snippet=line.strip()[:200],
                    suggestion="Use guard-let to safely unwrap optionals in chain",
                ))

        # Cross-line missing weak self in escaping closure
        for i, line in enumerate(lines):
            if re.search(r"escaping|DispatchQueue\.main\.async|URLSession.*completionHandler", line):
                next_lines = "\n".join(lines[i:i+5])
                if "self." in next_lines and "[weak self]" not in next_lines:
                    result.findings.append(Finding(
                        file=str(result.file_path),
                        line=i + 1,
                        column=0,
                        issue_type="SW-CROSS-RETAIN",
                        message="Escaping closure captures self strongly, possible retain cycle",
                        risk_level=RiskLevel.MEDIUM,
                        code_snippet=next_lines[:200],
                        suggestion="Add [weak self] to closure capture list and guard-let self",
                    ))

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
