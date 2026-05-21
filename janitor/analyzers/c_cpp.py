"""C/C++ analyzer with 52+ elite security checks."""

import re
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from janitor.analyzers.base import BaseAnalyzer, AnalysisResult
from janitor.types import Finding, RiskLevel


class CCheck:
    """Security check definition for C/C++."""

    def __init__(
        self,
        check_id: str,
        name: str,
        description: str,
        risk: RiskLevel,
        cwe: str,
        owasp: str,
        mitre: str,
        pattern: Optional[str] = None,
        remediation: str = "",
        example: str = "",
        context_check: Optional[str] = None,
        taint_source: bool = False,
        taint_sink: bool = False,
    ):
        self.id = check_id
        self.name = name
        self.description = description
        self.risk = risk
        self.cwe = cwe
        self.owasp = owasp
        self.mitre = mitre
        if pattern:
            self.pattern = re.compile(pattern, re.MULTILINE)
        else:
            self.pattern = None
        self.remediation = remediation
        self.example = example
        self.context_check = context_check
        self.taint_source = taint_source
        self.taint_sink = taint_sink

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "risk": self.risk.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "mitre": self.mitre,
        }


class CppAnalyzer(BaseAnalyzer):
    """C/C++ analyzer with 52+ elite security checks."""

    @property
    def default_max_file_size(self) -> int:
        return 1024 * 1024  # 1MB

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self._checks = self._build_checks()
        self._all_checks = self._checks
        self.framework_patterns = self._build_framework_patterns()

    def get_language(self) -> str:
        return "c_cpp"

    def get_supported_extensions(self) -> List[str]:
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".hh"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a C/C++ file and return results."""
        return self._analyze(str(file_path))

    def _build_framework_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Detect C/C++ frameworks and libraries."""
        return {
            "Qt": [re.compile(r"#include\s*<Q[A-Z]")],
            "Boost": [re.compile(r"#include\s*<boost/")],
            "STL": [re.compile(r"#include\s*<(vector|string|map|algorithm|iostream)")],
            "OpenSSL": [re.compile(r"#include\s*<openssl/")],
            "libcurl": [re.compile(r"#include\s*<curl/")],
            "SQLite": [re.compile(r"#include\s*<sqlite3\.h>")],
            "libpq": [re.compile(r"#include\s*<libpq-fe\.h>")],
            "MySQL": [re.compile(r"#include\s*<mysql/mysql\.h>")],
            "OpenMP": [re.compile(r"#pragma\s+omp\s")],
            "CUDA": [re.compile(r"#include\s*<cuda")],
            "WinAPI": [re.compile(r"#include\s*<windows\.h>")],
            "POSIX": [re.compile(r"#include\s*<(unistd|pthread|dlfcn)\.h>")],
            "GTK": [re.compile(r"#include\s*<gtk/")],
            "libevent": [re.compile(r"#include\s*<event\.h>")],
            "protobuf": [re.compile(r"#include\s*<google/protobuf/")],
            "gRPC": [re.compile(r"#include\s*<grpc/")],
            "cURL": [re.compile(r"#include\s*<curl/")],
            "nss": [re.compile(r"#include\s*<nss/")],
            "libsodium": [re.compile(r"#include\s*<sodium")],
            "capstone": [re.compile(r"#include\s*<capstone/")],
        }

    def _build_checks(self) -> List[CCheck]:
        """Build all security checks."""
        return [
            CCheck(
                check_id="C001",
                name='strcpy without bounds check',
                description='strcpy without bounds check',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-121",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='strcpy\\s*\\(',
                remediation='Use strncpy_s or snprintf instead of strcpy',
                example='strcpy(dest, src);',
                context_check=None,
                taint_source=False,
                taint_sink=True,
            ),
            CCheck(
                check_id="C002",
                name='strcat without bounds check',
                description='strcat without bounds check',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-121",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='strcat\\s*\\(',
                remediation='Use strncat_s or strlcat instead',
                example='strcat(dest, src);',
                context_check=None,
                taint_source=False,
                taint_sink=True,
            ),
            CCheck(
                check_id="C003",
                name='sprintf without bounds check',
                description='sprintf without bounds check',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-121",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='sprintf\\s*\\(',
                remediation='Use snprintf or sprintf_s with buffer size',
                example='sprintf(buf, "%s", data);',
                context_check=None,
                taint_source=False,
                taint_sink=True,
            ),
            CCheck(
                check_id="C004",
                name='gets() usage',
                description='gets() usage',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-121",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='\\bgets\\s*\\(',
                remediation='Use fgets() with size limit or getline()',
                example='gets(buf);',
                context_check=None,
                taint_source=False,
                taint_sink=True,
            ),
            CCheck(
                check_id="C005",
                name='scanf %s without width',
                description='scanf %s without width',
                risk=RiskLevel.HIGH,
                cwe="CWE-120",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='scanf\\s*\\(\\s*"[^"]*%s[^"]*"',
                remediation='Always specify width: %255s instead of %s',
                example='scanf("%s", buf);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C006",
                name='memcpy with unchecked size',
                description='memcpy with unchecked size',
                risk=RiskLevel.HIGH,
                cwe="CWE-122",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='memcpy\\s*\\(',
                remediation="Validate size argument doesn't exceed destination buffer",
                example='memcpy(dest, src, size);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C007",
                name='unsafe array index',
                description='unsafe array index',
                risk=RiskLevel.HIGH,
                cwe="CWE-129",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='[a-zA-Z_]\\w*\\[\\s*[a-zA-Z_]\\w*\\s*\\]\\s*(?:=|;)',
                remediation='Validate array index before access',
                example='arr[idx] = val;',
                context_check="'idx' in line and 'for' not in line and 'size' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C008",
                name='variable-length array (VLA)',
                description='variable-length array (VLA)',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-758",
                owasp="A3: Injection",
                mitre="T1499",
                pattern='[a-zA-Z_]\\w*\\s*\\[\\s*[a-zA-Z_]\\w*\\s*\\]\\s*;',
                remediation='Ensure VLA size is bounded',
                example='int arr[n];',
                context_check="'for' in line or 'while' in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C009",
                name='printf with user input string',
                description='printf with user input string',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-134",
                owasp="A1: Injection",
                mitre="T1064",
                pattern='printf\\s*\\(\\s*[a-zA-Z_]\\w*\\s*\\)',
                remediation='Use printf("%s", user_input) instead of printf(user_input)',
                example='printf(user_input);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C010",
                name='fprintf with user input string',
                description='fprintf with user input string',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-134",
                owasp="A1: Injection",
                mitre="T1064",
                pattern='fprintf\\s*\\([^,]+,\\s*[a-zA-Z_]\\w*\\s*\\)',
                remediation='Use fprintf(stderr, "%s", user_input) instead',
                example='fprintf(stderr, user_input);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C011",
                name='sprintf/ vsnprintf unchecked format',
                description='sprintf/ vsnprintf unchecked format',
                risk=RiskLevel.HIGH,
                cwe="CWE-134",
                owasp="A1: Injection",
                mitre="T1064",
                pattern='(sprintf|vsnprintf|snprintf)\\s*\\([^,]+,\\s*[^,]+,\\s*[a-zA-Z_]\\w*\\s*\\)',
                remediation='Always use constant format strings',
                example='sprintf(buf, user_fmt, val);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C012",
                name='potential use-after-free',
                description='potential use-after-free',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-416",
                owasp="A1: Injection",
                mitre="T1213",
                pattern='\\b(?:free|delete)\\s*\\(\\s*(\\w+)\\s*\\)',
                remediation='Set pointer to NULL after freeing to prevent use-after-free',
                example='free(ptr); ptr->field = 1;',
                context_check="'free(' in prev_line and 'NULL' not in line and 'nullptr' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C013",
                name='potential double free',
                description='potential double free',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-415",
                owasp="A1: Injection",
                mitre="T1213",
                pattern='\\bfree\\s*\\(\\s*(\\w+)\\s*\\)',
                remediation='Set pointer to NULL after first free to prevent double free',
                example='free(ptr); free(ptr);',
                context_check="'free(' in prev_line and 'NULL' not in prev_line and 'nullptr' not in prev_line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C014",
                name='malloc without free',
                description='malloc without free',
                risk=RiskLevel.HIGH,
                cwe="CWE-401",
                owasp="A1: Injection",
                mitre="T1145",
                pattern='\\bmalloc\\s*\\(',
                remediation='Track all malloc allocations and ensure corresponding free calls',
                example='char* buf = malloc(1024);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C015",
                name='calloc without free',
                description='calloc without free',
                risk=RiskLevel.HIGH,
                cwe="CWE-401",
                owasp="A1: Injection",
                mitre="T1145",
                pattern='\\bcalloc\\s*\\(',
                remediation='Track all calloc allocations and ensure corresponding free calls',
                example='int* arr = calloc(10, sizeof(int));',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C016",
                name='strdup without free',
                description='strdup without free',
                risk=RiskLevel.HIGH,
                cwe="CWE-401",
                owasp="A1: Injection",
                mitre="T1145",
                pattern='\\bstrdup\\s*\\(',
                remediation='strdup allocates memory that must be freed',
                example='char* dup = strdup(orig);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C017",
                name='realloc without NULL check',
                description='realloc without NULL check',
                risk=RiskLevel.HIGH,
                cwe="CWE-476",
                owasp="A1: Injection",
                mitre="T1145",
                pattern='\\brealloc\\s*\\(',
                remediation='Always assign realloc to a temp pointer and check for NULL',
                example='ptr = realloc(ptr, newsize);',
                context_check="'realloc' in line and 'if' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C018",
                name='system() with user input',
                description='system() with user input',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-78",
                owasp="A1: Injection",
                mitre="T1202",
                pattern='\\bsystem\\s*\\(\\s*[^\\"\\s]',
                remediation='Use execve() with explicit arguments instead of system()',
                example='system(user_cmd);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C019",
                name='popen() with user input',
                description='popen() with user input',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-78",
                owasp="A1: Injection",
                mitre="T1202",
                pattern='\\bpopen\\s*\\(\\s*[^\\"\\s&]',
                remediation='Avoid popen with user-controlled input',
                example='FILE* f = popen(user_input, "r");',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C020",
                name='exec* family with user input',
                description='exec* family with user input',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-78",
                owasp="A1: Injection",
                mitre="T1202",
                pattern='(?:exec[lvpe]{1,4}|system|popen)\\s*\\([^)]*[a-zA-Z_]\\w*\\]?\\s*[,&)]',
                remediation='Use execve with strict argument validation and whitelist',
                example='execlp("/bin/sh", "sh", "-c", user_input, NULL);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C021",
                name='open() with user-controlled path',
                description='open() with user-controlled path',
                risk=RiskLevel.HIGH,
                cwe="CWE-22",
                owasp="A1: Injection",
                mitre="T1006",
                pattern='\\bopen\\s*\\(\\s*[a-zA-Z_]\\w*\\s*[,\\)]',
                remediation='Validate and sanitize file paths, use basename() and realpath()',
                example='int fd = open(user_path, O_RDONLY);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C022",
                name='fopen() with user-controlled path',
                description='fopen() with user-controlled path',
                risk=RiskLevel.HIGH,
                cwe="CWE-22",
                owasp="A1: Injection",
                mitre="T1006",
                pattern='\\bfopen\\s*\\(\\s*[a-zA-Z_]\\w*\\s*,',
                remediation='Validate and sanitize file paths',
                example='FILE* f = fopen(user_filename, "r");',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C023",
                name='SQLite3 exec with user input',
                description='SQLite3 exec with user input',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-89",
                owasp="A1: Injection",
                mitre="T1191",
                pattern='(?:sqlite3_exec|sqlite3_prepare_v2)\\s*\\([^)]*[a-zA-Z_]\\w*\\s*\\)',
                remediation='Use prepared statements with parameterized queries',
                example='sqlite3_exec(db, user_sql, 0, 0, &err);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C024",
                name='MySQL/libpq query with user input',
                description='MySQL/libpq query with user input',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-89",
                owasp="A1: Injection",
                mitre="T1191",
                pattern='(?:mysql_query|PQexec|PQexecParams)\\s*\\([^)]*[a-zA-Z_]\\w*\\s*\\)',
                remediation='Use parameterized queries or prepared statements',
                example='mysql_query(conn, user_sql);',
                context_check=None,
                taint_source=True,
                taint_sink=True,
            ),
            CCheck(
                check_id="C025",
                name='potential integer overflow',
                description='potential integer overflow',
                risk=RiskLevel.HIGH,
                cwe="CWE-190",
                owasp="A3: Injection",
                mitre="T1499",
                pattern='\\w+\\s*\\+\\s*\\w+',
                remediation='Use safe integer arithmetic with bounds checking',
                example='int sum = a + b;',
                context_check="'int' in line and '+' in line and 'sizeof' not in line and 'for' not in line and 'printf' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C026",
                name='potential division by zero',
                description='potential division by zero',
                risk=RiskLevel.HIGH,
                cwe="CWE-369",
                owasp="A3: Injection",
                mitre="T1499",
                pattern='\\w+\\s*/\\s*\\w+',
                remediation='Check divisor is not zero before division',
                example='int result = a / b;',
                context_check="'/' in line and 'printf' not in line and '//' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C027",
                name='signed/unsigned comparison mismatch',
                description='signed/unsigned comparison mismatch',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-192",
                owasp="A3: Injection",
                mitre="T1499",
                pattern='for\\s*\\(\\s*(?:int|long)\\s+\\w+\\s*=\\s*\\d+\\s*;\\s*\\w+\\s*[<>]=\\s*\\w+\\.size\\(\\)',
                remediation='Use size_t for loop indices comparing with .size()',
                example='for (int i = 0; i < vec.size(); i++)',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C028",
                name='potential shift overflow',
                description='potential shift overflow',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-128",
                owasp="A3: Injection",
                mitre="T1499",
                pattern='\\w+\\s*<<\\s*\\d{2,}',
                remediation='Validate shift amount is less than bit width of type',
                example='int result = value << 32;',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C029",
                name='TOCTOU race condition',
                description='TOCTOU race condition',
                risk=RiskLevel.HIGH,
                cwe="CWE-367",
                owasp="A8: Software and Data Integrity Failures",
                mitre="T1600",
                pattern='\\b(?:access|stat)\\s*\\([^)]+\\)',
                remediation='Use open() with O_EXCL or handle errors atomically',
                example='if (access(path, F_OK) == 0) { int fd = open(path, O_RDONLY); }',
                context_check="'access(' in line or 'stat(' in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C030",
                name='signal handler (async-signal-safety)',
                description='signal handler (async-signal-safety)',
                risk=RiskLevel.HIGH,
                cwe="CWE-479",
                owasp="A8: Software and Data Integrity Failures",
                mitre="T1600",
                pattern='\\bsignal\\s*\\(\\s*SIG\\w+\\s*,\\s*\\w+',
                remediation='Only use async-signal-safe functions in signal handlers',
                example='signal(SIGINT, handler);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C031",
                name='pthread_create without mutex on shared data',
                description='pthread_create without mutex on shared data',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-362",
                owasp="A8: Software and Data Integrity Failures",
                mitre="T1600",
                pattern='\\bpthread_create\\s*\\(',
                remediation='Ensure shared data is protected by mutexes',
                example='pthread_create(&th, NULL, func, &shared);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C032",
                name='MD5/SHA1 usage',
                description='MD5/SHA1 usage',
                risk=RiskLevel.HIGH,
                cwe="CWE-327",
                owasp="A2: Cryptographic Failures",
                mitre="T1602",
                pattern='\\b(?:MD5|SHA1|SHA_1|md5)\\s*\\(',
                remediation='Use SHA-256 or stronger hashing algorithm',
                example='unsigned char* hash = MD5(input, len, result);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C033",
                name='hardcoded cryptographic key',
                description='hardcoded cryptographic key',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-321",
                owasp="A2: Cryptographic Failures",
                mitre="T1602",
                pattern='(?:unsigned\\s+char\\s+\\w+\\s*\\[\\s*\\]\\s*=\\s*\\{[^}]{10,}|#define\\s+\\w+_KEY\\s+\\"[A-Za-z0-9+/=]{16,})',
                remediation='Store keys in secure key management system, not in source',
                example='unsigned char key[] = {0x01, 0x02, 0x03, ...};',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C034",
                name='weak random number generator (rand)',
                description='weak random number generator (rand)',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-338",
                owasp="A2: Cryptographic Failures",
                mitre="T1602",
                pattern='\\brand\\s*\\(\\s*\\)',
                remediation='Use cryptographically secure RNG (arc4random, getrandom, BCryptGenRandom)',
                example='int key = rand();',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C035",
                name='HTTP instead of HTTPS',
                description='HTTP instead of HTTPS',
                risk=RiskLevel.HIGH,
                cwe="CWE-319",
                owasp="A5: Security Misconfiguration",
                mitre="T1040",
                pattern='http://',
                remediation='Always use HTTPS instead of HTTP for network communication',
                example='curl_easy_setopt(curl, CURLOPT_URL, "http://api.example.com");',
                context_check="'https://' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C036",
                name='SSL certificate verification disabled',
                description='SSL certificate verification disabled',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-295",
                owasp="A5: Security Misconfiguration",
                mitre="T1040",
                pattern='(?:SSL_CTX_set_verify\\s*\\(\\s*\\w+\\s*,\\s*SSL_VERIFY_NONE|curl_easy_setopt\\s*\\(\\s*\\w+\\s*,\\s*CURLOPT_SSL_VERIFYPEER\\s*,\\s*0)',
                remediation='Always verify SSL certificates',
                example='SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C037",
                name='telnet usage (unencrypted)',
                description='telnet usage (unencrypted)',
                risk=RiskLevel.HIGH,
                cwe="CWE-319",
                owasp="A2: Cryptographic Failures",
                mitre="T1040",
                pattern='\\btelnet\\b',
                remediation='Use SSH instead of telnet for remote communication',
                example='system("telnet remote-host");',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C038",
                name='FTP usage (unencrypted)',
                description='FTP usage (unencrypted)',
                risk=RiskLevel.HIGH,
                cwe="CWE-319",
                owasp="A2: Cryptographic Failures",
                mitre="T1040",
                pattern='(?:ftp://|FTP://)',
                remediation='Use SFTP or FTPS instead of plain FTP',
                example='curl_easy_setopt(curl, CURLOPT_URL, "ftp://files.example.com");',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C039",
                name='goto statement',
                description='goto statement',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-489",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='\\bgoto\\s+\\w+',
                remediation='Prefer structured programming; limit goto to error cleanup patterns only',
                example='goto end;',
                context_check="'cleanup' not in line and 'err' not in line and 'exit' not in line and 'error' not in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C040",
                name='setjmp/longjmp usage',
                description='setjmp/longjmp usage',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-754",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='(?:setjmp|longjmp)\\s*\\(',
                remediation='Use exceptions or error return values instead of setjmp/longjmp',
                example='if (setjmp(env)) { }',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C041",
                name='recursive function (check base case)',
                description='recursive function (check base case)',
                risk=RiskLevel.LOW,
                cwe="CWE-674",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='([a-zA-Z_]\\w*)\\s*\\([^)]*\\)\\s*\\{[^}]*\\1\\s*\\(',
                remediation='Ensure recursive functions have proper termination conditions',
                example='int fact(int n) { return fact(n-1); }',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C042",
                name='magic numbers',
                description='magic numbers',
                risk=RiskLevel.LOW,
                cwe="CWE-1104",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='\\b\\d{3,}\\b(?!\\s*\\))',
                remediation='Replace magic numbers with named constants',
                example='int size = 4096;',
                context_check="'sizeof' in line or 'const' in line or '#define' in line",
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C043",
                name='long function (over 100 lines)',
                description='long function (over 100 lines)',
                risk=RiskLevel.LOW,
                cwe="CWE-1104",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern=None,
                remediation='Refactor long functions into smaller cohesive functions',
                example='void big_func() { ... }',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C044",
                name='TODO/FIXME in comment',
                description='TODO/FIXME in comment',
                risk=RiskLevel.LOW,
                cwe="CWE-546",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='(?:TODO|FIXME|XXX|HACK|BUG|WORKAROUND)\\s*[:]?',
                remediation='Address TODO and FIXME comments before release',
                example='// TODO: implement authentication',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C045",
                name='empty or silent catch block',
                description='empty or silent catch block',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-396",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='catch\\s*(?:\\.\\.\\.|\\([^)]*\\))\\s*\\{\\s*\\}',
                remediation='Never silently swallow exceptions; log or handle specifically',
                example='catch (...) { }',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C046",
                name='hardcoded password',
                description='hardcoded password',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-798",
                owasp="A7: Identification and Authentication Failures",
                mitre="T1552",
                pattern='(?:password|passwd|pwd|secret)\\s*=\\s*["\\\'][^"\\\']+["\\\']',
                remediation='Store passwords in environment variables or secure vault',
                example='const char* pass = "super_secret_123";',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C047",
                name='hardcoded API key/secret',
                description='hardcoded API key/secret',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-798",
                owasp="A7: Identification and Authentication Failures",
                mitre="T1552",
                pattern='(?:api_key|apikey|api_secret|access_key|secret_key|token)\\s*=\\s*["\\\'][A-Za-z0-9_\\-]{16,}["\\\']',
                remediation='Store API keys in environment variables or secret manager',
                example='const char* api_key = "sk-abc123def456ghi789";',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C048",
                name='hardcoded SSH private key',
                description='hardcoded SSH private key',
                risk=RiskLevel.CRITICAL,
                cwe="CWE-798",
                owasp="A7: Identification and Authentication Failures",
                mitre="T1552",
                pattern='-----BEGIN\\s+(?:RSA|DSA|EC|OPENSSH)\\s+PRIVATE\\s+KEY-----',
                remediation='Never commit private keys; use SSH agent or vault',
                example='-----BEGIN RSA PRIVATE KEY-----',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C049",
                name='inline assembly',
                description='inline assembly',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-1108",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='__asm__\\s*\\(|_asm\\s*\\{|\\basm\\s+(?:volatile)?\\s*\\{',
                remediation='Prefer compiler intrinsics or standard library over inline asm',
                example='__asm__("movl %eax, %ebx");',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C050",
                name='alloca usage (stack overflow risk)',
                description='alloca usage (stack overflow risk)',
                risk=RiskLevel.HIGH,
                cwe="CWE-770",
                owasp="A5: Security Misconfiguration",
                mitre="T1499",
                pattern='\\balloca\\s*\\(',
                remediation='Use heap allocation (malloc) instead of alloca to avoid stack overflow',
                example='char* buf = alloca(size);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C051",
                name='volatile without atomic',
                description='volatile without atomic',
                risk=RiskLevel.MEDIUM,
                cwe="CWE-1108",
                owasp="A5: Security Misconfiguration",
                mitre="T1211",
                pattern='\\bvolatile\\s+(?:int|long|char|unsigned|short|bool|float|double)\\s+\\w+',
                remediation='Use atomic types (std::atomic) instead of volatile for shared state',
                example='volatile int flag;',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
            CCheck(
                check_id="C052",
                name='gets_s misuse (hardcoded size)',
                description='gets_s misuse (hardcoded size)',
                risk=RiskLevel.HIGH,
                cwe="CWE-119",
                owasp="A1: Injection",
                mitre="T1190",
                pattern='gets_s\\s*\\(\\s*\\w+\\s*,\\s*(?!sizeof)',
                remediation='Use sizeof or provide correct buffer size to gets_s',
                example='gets_s(buf, 100);',
                context_check=None,
                taint_source=False,
                taint_sink=False,
            ),
        ]

    def detect_frameworks(self, lines: List[str]) -> Dict[str, bool]:
        """Detect which frameworks/libs are used in the codebase."""
        frameworks = {}
        for fw_name, patterns in self.framework_patterns.items():
            for pat in patterns:
                if any(pat.search(l) for l in lines):
                    frameworks[fw_name] = True
                    break
            else:
                frameworks[fw_name] = False
        return frameworks

    def _analyze(self, file_path: str) -> AnalysisResult:
        """Analyze a C/C++ file for security vulnerabilities."""
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            result = AnalysisResult(file_path=Path(file_path))
            result.has_errors = True
            result.error_message = str(e)
            return result

        if len(content) > self.default_max_file_size:
            result = AnalysisResult(file_path=Path(file_path))
            result.has_errors = True
            result.error_message = "File exceeds maximum size"
            return result

        lines = content.split("\n")
        result = AnalysisResult(file_path=Path(file_path))

        for check in self._all_checks:
            if check.pattern is None:
                continue
            for match in check.pattern.finditer(content):
                line_number = content[:match.start()].count("\n") + 1
                matched_text = match.group().strip()
                line = lines[line_number - 1] if line_number <= len(lines) else ""
                prev_line = lines[line_number - 2] if line_number > 1 else ""

                if check.context_check:
                    ctx = {"line": line, "prev_line": prev_line, "lines": lines}
                    try:
                        parts = check.context_check.split(" and ")
                        skip = False
                        for part in parts:
                            part = part.strip()
                            if "not in" in part:
                                var, _, val = part.partition("not in")
                                var = var.strip()
                                val = val.strip().strip("\"'")
                                if ctx.get(var) and val in ctx[var]:
                                    skip = True
                                    break
                            elif "in" in part:
                                var, _, val = part.partition("in")
                                var = var.strip()
                                val = val.strip().strip("\"'")
                                if ctx.get(var) and val not in ctx[var]:
                                    skip = True
                                    break
                        if skip:
                            continue
                    except Exception:
                        pass

                if self._is_false_positive(check, line):
                    continue

                result.findings.append(Finding(
                    file=str(file_path),
                    line=line_number,
                    column=matched_text.index(check.pattern.search(matched_text).group()) + 1 if check.pattern.search(matched_text) else 0,
                    issue_type=check.id,
                    message=f"[{check.id}] {check.description} | CWE: {check.cwe}, OWASP: {check.owasp}, MITRE: {check.mitre}",
                    risk_level=check.risk,
                    code_snippet=matched_text[:200],
                    suggestion=check.remediation,
                ))

        return result

    def _is_false_positive(self, check: CCheck, line: str) -> bool:
        """Determine if a finding is likely a false positive based on context."""
        if "test_" in line.lower() or "_test" in line.lower():
            if check.risk == RiskLevel.LOW:
                return True
        if check.id == "C025" and "for" in line:
            return True
        if check.id == "C035" and ("//" in line or "/*" in line):
            return True
        return False

    def get_supported_checks(self) -> List[dict]:
        """Return metadata for all supported checks."""
        return [c.to_dict() for c in self._all_checks]

    @property
    def version(self) -> str:
        return "1.0.0"
