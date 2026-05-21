"""Elite static analyzer for Rust code with comprehensive security checks."""

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
    """A security unit test for Rust code."""
    id: str
    name: str
    category: str
    severity: RiskLevel
    description: str
    pattern: re.Pattern
    context_checks: List[Callable[[str, str, List[str], Dict], bool]] = field(default_factory=list)
    suggestion: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    remediation_example: str = ""
    attack_vector: str = ""
    mitre_technique: str = ""


class RustAnalyzer(BaseAnalyzer):
    """Elite static analyzer for Rust code — 50+ elite security checks."""

    def __init__(self):
        self.checks: List[SecurityCheck] = self._build_checks()
        self._framework_cache: Dict[str, List[str]] = {}
        self._taint_sources: Set[str] = set()
        self._taint_sinks: Set[str] = set()

    def get_language(self) -> str:
        return "rust"

    def get_supported_extensions(self) -> List[str]:
        return [".rs"]

    def analyze_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a Rust file and return results."""
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
        "actix-web": ["actix_web", "HttpRequest", "HttpResponse", "web::"],
        "rocket": ["rocket::", "#[get]", "#[post]", "#[put]", "#[delete]", "State<"],
        "axum": ["axum::", "Router::", "Extension<", "Json<", "Query<"],
        "warp": ["warp::", "Filter", "path!"],
        "tokio": ["tokio::", "#[tokio::main]", "tokio::spawn", "async fn"],
        "diesel": ["diesel::", "Queryable", "Insertable", "diesel::prelude::"],
        "sqlx": ["sqlx::", "query!", "query_as!", "PgPool", "MySqlPool"],
        "rusqlite": ["rusqlite::", "Connection::open", "rusqlite::Connection"],
        "serde": ["serde::", "#[derive(Serialize", "#[derive(Deserialize"],
        "reqwest": ["reqwest::", "reqwest::Client"],
        "hyper": ["hyper::", "hyper::server"],
        "tonic": ["tonic::", "grpc"],
        "clap": ["clap::", "#[derive(Parser]"],
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

    def _is_safe_command(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if a command execution uses a safe pattern (no user input)."""
        if re.search(r'"(ping|echo|ls|whoami|date|id|uname)"', line):
            return False
        if content.count(".") > 3 and "args" not in content:
            return False
        if "let _ = " in line or line.strip().startswith("//"):
            return False
        return True

    def _is_parameterized_query(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if a SQL-like pattern is actually parameterized."""
        if "?" in line or ":1" in line or "$1" in line:
            return False
        if "sqlx::query!" in line or "diesel::sql_query" in line:
            return False
        return True

    def _is_safe_file_path(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if a file path operation uses a safe pattern."""
        if "canonicalize" in content or "canonical" in content:
            return False
        if '"/tmp/' in line or '"/var/' in line or '"./"' in line:
            return False
        if "concat!" in line and "env!" in line:
            return False
        return True

    def _has_unsafe_annotation(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if unsafe block has proper justification."""
        lines = content.split("\n")
        line_idx = next(i for i, l in enumerate(lines) if l == line)
        context = "\n".join(lines[max(0, line_idx-5):line_idx+2])
        if "SAFETY:" in context or "// Safety:" in context or "// safety:" in context:
            return False
        return True

    def _is_unwrap_with_message(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if unwrap has a proper error message."""
        if '.expect("' in content or ".expect('" in content:
            return False
        match = re.search(r'\.unwrap\(\)', line)
        if match:
            line_before = content[:content.index(line)+match.start()]
            last_assign = line_before.rfind("let ")
            if last_assign >= 0:
                context_block = line_before[last_assign:]
                if "Result" in context_block or "Option" in context_block:
                    return True
        return True

    def _is_dangerous_crypto(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if crypto usage is actually for security purposes."""
        if "test" in content.lower() or "#[cfg(test)]" in content:
            return False
        if "hash" in line.lower() and "password" not in content.lower():
            return False
        return True

    def _has_valid_bounds_check(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if indexing has bounds checking."""
        if ".get(" in content or ".get_mut(" in content:
            if "[" in line and "]" in line:
                return False
        return True

    def _is_public_function(self, line: str, content: str, frameworks: List[str]) -> bool:
        """Check if a function is public (needs documentation)."""
        idx = content.find(line)
        prefix = content[max(0, idx-50):idx]
        return "pub " in prefix or "pub(crate)" in prefix

    # ======================================================================
    # BUILD CHECKS
    # ======================================================================

    def _build_checks(self) -> List[SecurityCheck]:
        """Build all security checks organized by category and severity."""
        checks = []

        # ====================================================================
        # CATEGORY: MEMORY SAFETY (Critical)
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-MEM-001",
                name="Unsafe Block Without Safety Justification",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="Unsafe block without documented safety invariants",
                pattern=re.compile(r'unsafe\s*\{'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Document SAFETY invariants above each unsafe block",
                cwe_id="CWE-676",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// SAFETY: `ptr` is valid, aligned, and non-null\nunsafe { *ptr = 42 }",
                attack_vector="Unsafe block → Undefined behavior → Memory corruption → RCE",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-002",
                name="Raw Pointer Dereference",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="Dereferencing a raw pointer without safety guarantees",
                pattern=re.compile(r'\*\s*(const|mut)\s+\S+\s*=\s*&?\s*\S+\s+as\s+\*'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use safe abstractions instead of raw pointers whenever possible",
                cwe_id="CWE-822",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of raw pointer dereference, use safe references\nlet value = &*ptr;  // still unsafe, prefer &mut T",
                attack_vector="Raw pointer → Arbitrary memory read/write → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-003",
                name="Use of std::mem::transmute",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="transmute can create arbitrary type representations with no compile-time checking",
                pattern=re.compile(r'(?i)(std::mem::)?transmute\s*[<(]'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use safe conversions like From/Into or try_from instead of transmute",
                cwe_id="CWE-704",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of transmute:\nlet value = u32::from_ne_bytes(bytes);",
                attack_vector="transmute → Type confusion → Memory safety violation",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-004",
                name="Use of std::mem::transmute_copy",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="transmute_copy performs a bitwise copy without compile-time validation",
                pattern=re.compile(r'(?i)(std::mem::)?transmute_copy\s*[<(]'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use safe Clone or copy operations instead of transmute_copy",
                cwe_id="CWE-704",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of transmute_copy:\nlet value = *bytes.as_ptr().cast::<u32>();",
                attack_vector="transmute_copy → Bitwise reinterpretation → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-005",
                name="Use of core::mem::zeroed / uninitialized",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="Creating uninitialized or zeroed memory can cause undefined behavior for non-POD types",
                pattern=re.compile(r'(?i)(core::mem::)?(zeroed|uninitialized)\s*[<(]'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use Default trait or constructors instead of zeroed/uninitialized memory",
                cwe_id="CWE-457",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of MaybeUninit::zeroed():\nlet value = MyStruct::default();",
                attack_vector="Uninitialized memory → Undefined behavior → Information disclosure",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-006",
                name="Use of std::mem::forget / ManuallyDrop",
                category="memory-safety",
                severity=RiskLevel.HIGH,
                description="forget/ManuallyDrop can skip destructors causing resource leaks",
                pattern=re.compile(r'(?i)(std::mem::)?forget\s*\(|ManuallyDrop::'),
                context_checks=[],
                suggestion="Avoid forgetting values with destructors. Use RAII patterns instead",
                cwe_id="CWE-459",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of mem::forget:\n// Use a scope guard or explicit close() method",
                attack_vector="Resource leak → Denial of service via resource exhaustion",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-MEM-007",
                name="MaybeUninit Without Proper Initialization Check",
                category="memory-safety",
                severity=RiskLevel.HIGH,
                description="MaybeUninit requires explicit initialization before reading — missing it causes UB",
                pattern=re.compile(r'MaybeUninit::'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Ensure MaybeUninit is properly initialized with .write() before .assume_init()",
                cwe_id="CWE-457",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let mut uninit = MaybeUninit::uninit();\nuninit.write(value);\nlet initialized = unsafe { uninit.assume_init() };",
                attack_vector="Uninitialized MaybeUninit read → Undefined behavior → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-MEM-008",
                name="Pointer Arithmetic Without Bounds Checks",
                category="memory-safety",
                severity=RiskLevel.CRITICAL,
                description="Manual pointer arithmetic can overflow or access out-of-bounds memory",
                pattern=re.compile(r'(ptr|as_ptr|as_mut_ptr)\s*\.\s*(add|offset|sub)\s*\('),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use safe slice indexing or iterators instead of manual pointer arithmetic",
                cwe_id="CWE-823",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of ptr.add(n):\nif let Some(element) = slice.get(n) { ... }",
                attack_vector="Pointer arithmetic overflow → Out-of-bounds access → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
        ])

        # ====================================================================
        # CATEGORY: CONCURRENCY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-CONC-001",
                name="Use of std::thread::spawn Without JoinHandle",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Spawned thread without JoinHandle makes error handling impossible",
                pattern=re.compile(r'(?i)thread::spawn\s*\('),
                context_checks=[],
                suggestion="Capture JoinHandle and join() threads properly, or use tokio tasks",
                cwe_id="CWE-366",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let handle = thread::spawn(move || { ... });\nhandle.join().unwrap();",
                attack_vector="Leaked thread → Resource leak → Potential DoS",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-CONC-002",
                name="Use of Arc::get_mut_unchecked",
                category="concurrency",
                severity=RiskLevel.CRITICAL,
                description="get_mut_unchecked allows mutable access to Arc contents without proper synchronization",
                pattern=re.compile(r'(?i)get_mut_unchecked\s*\('),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use proper synchronization with Mutex<RwLock> instead of unsafe Arc access",
                cwe_id="CWE-362",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of unsafe Arc access:\nlet shared = Arc::new(Mutex::new(value));\nlet mut data = shared.lock().unwrap();",
                attack_vector="Race condition → Data race → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-CONC-003",
                name="Use of static mut",
                category="concurrency",
                severity=RiskLevel.CRITICAL,
                description="static mut is inherently unsafe and causes data races",
                pattern=re.compile(r'static\s+mut\s+\w+\s*:'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Use atomic types, Mutex, or thread_local! instead of static mut",
                cwe_id="CWE-362",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="use std::sync::atomic::{AtomicBool, Ordering};\nstatic FLAG: AtomicBool = AtomicBool::new(false);",
                attack_vector="Static mut → Data race → Undefined behavior → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-CONC-004",
                name="Mutex Poisoning Risk",
                category="concurrency",
                severity=RiskLevel.MEDIUM,
                description="Mutex can be poisoned if a holding thread panics — ignoring poison can cause issues",
                pattern=re.compile(r'\.lock\(\)\.unwrap\(\)|\.lock\(\)\.expect\('),
                context_checks=[],
                suggestion="Handle mutex poisoning: use .lock().unwrap_or_else(|e| e.into_inner())",
                cwe_id="CWE-667",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let guard = match mutex.lock() {\n    Ok(guard) => guard,\n    Err(poisoned) => poisoned.into_inner(),\n};",
                attack_vector="Mutex poison → Panic cascade → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-CONC-005",
                name="Unsafe Send/Sync Implementation",
                category="concurrency",
                severity=RiskLevel.CRITICAL,
                description="Manual unsafe impl of Send/Sync can create data races",
                pattern=re.compile(r'unsafe\s+impl\s+(Send|Sync)\s+for'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Ensure safety invariants are documented when implementing Send/Sync manually",
                cwe_id="CWE-362",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// SAFETY: `MyType` contains only `Send` fields\nunsafe impl Send for MyType {}",
                attack_vector="Wrong Send/Sync → Data race → Memory corruption",
                mitre_technique="T1204 - User Execution",
            ),
        ])

        # ====================================================================
        # CATEGORY: COMMAND INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-CMD-001",
                name="Command Injection via std::process::Command with Shell",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="Using shell=true with user input allows arbitrary command execution",
                pattern=re.compile(r'(?i)std::process::Command::new\(|Command::new\('),
                context_checks=[self._is_safe_command],
                suggestion="Use Command with explicit argument array, never shell strings",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="Command::new(\"ls\")\n    .arg(\"-la\")\n    .arg(user_dir)\n    .output()?",
                attack_vector="User input → Command execution → Arbitrary shell command → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RS-CMD-002",
                name="Command Injection via format! in Shell Args",
                category="command-injection",
                severity=RiskLevel.CRITICAL,
                description="format! macro in shell command arguments allows injection",
                pattern=re.compile(r'format!\s*\([^)]*"(?:sh|bash|cmd|powershell|/bin/sh|/bin/bash)"'),
                context_checks=[],
                suggestion="Avoid shell invocation. Use Command::new() with direct arguments",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Instead: Command::new(\"ls\").arg(safe_path).output()",
                attack_vector="User input → format! → Shell execution → Arbitrary command",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RS-CMD-003",
                name="Command Injection via OpenOptions",
                category="command-injection",
                severity=RiskLevel.HIGH,
                description="Using std::process::Command with .arg() containing user input with shell metacharacters",
                pattern=re.compile(r'\.arg\(\s*(format!|input|user|name|path|file|cmd)'),
                context_checks=[self._is_safe_command],
                suggestion="Validate and sanitize all arguments passed to Command::arg()",
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                remediation_example="let safe_arg = user_input.replace(\";\", \"\").replace(\"&\", \"\");\nCommand::new(\"ls\").arg(safe_arg).output()",
                attack_vector="User input → Command arg → Shell interpretation → RCE",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: SQL INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-SQL-001",
                name="SQL Injection via diesel::sql_query with Format",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String formatting in diesel::sql_query allows SQL injection",
                pattern=re.compile(r'(?i)sql_query\s*\(\s*format!\s*\('),
                context_checks=[self._is_parameterized_query],
                suggestion="Use diesel's query builder or bind parameters instead of format!",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='sql_query("SELECT * FROM users WHERE id = $1").bind::<Integer, _>(user_id)',
                attack_vector="User input → diesel sql_query → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RS-SQL-002",
                name="SQL Injection via sqlx::query! Macro Concatenation",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="Using format! or concat! in sqlx::query! allows SQL injection",
                pattern=re.compile(r'(?i)(sqlx::)?(query|query_as)!\(\s*(format!|concat!)'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use SQLx's bind parameters ($1, $2) instead of string formatting",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example="sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id)",
                attack_vector="User input → sqlx query! format → SQL execution → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
            SecurityCheck(
                id="RS-SQL-003",
                name="SQL Injection via rusqlite::execute with Concat",
                category="sql-injection",
                severity=RiskLevel.CRITICAL,
                description="String concatenation in rusqlite execute allows SQL injection",
                pattern=re.compile(r'(?i)(execute|query|prepare)\s*\(\s*"[^"]*"\s*\.to_string\(\)|(execute|query|prepare)\s*\(\s*(&|format!)'),
                context_checks=[self._is_parameterized_query],
                suggestion="Use rusqlite's parameterized queries with ? or :param placeholders",
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection",
                remediation_example='conn.execute("INSERT INTO users (name) VALUES (?1)", params![&user_name])?',
                attack_vector="User input → rusqlite execution → SQL injection → Database compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: PATH TRAVERSAL
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-PATH-001",
                name="Path Traversal via std::fs::File Operations",
                category="path-traversal",
                severity=RiskLevel.CRITICAL,
                description="File operations with user-controlled paths can access arbitrary files",
                pattern=re.compile(r'(?i)(File::open|File::create|fs::read|fs::write|fs::read_to_string)\s*\(\s*(format!|input|user|name|path|file)'),
                context_checks=[self._is_safe_file_path],
                suggestion="Canonicalize and validate paths before file operations",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="let canonical = path.canonicalize()?;\nif !canonical.starts_with(ALLOWED_DIR) { bail!(\"Invalid path\") }",
                attack_vector="User input → Path traversal → /etc/passwd read → Information disclosure",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
            SecurityCheck(
                id="RS-PATH-002",
                name="Path Traversal via std::path::Path::new",
                category="path-traversal",
                severity=RiskLevel.HIGH,
                description="Creating Path from user input without validation allows traversal",
                pattern=re.compile(r'Path::new\s*\('),
                context_checks=[self._is_safe_file_path],
                suggestion="Use canonicalize() and verify the resolved path is within allowed directories",
                cwe_id="CWE-22",
                owasp_category="A01:2021 - Broken Access Control",
                remediation_example="let base = Path::new(\"/safe/dir\");\nlet full = base.join(user_input).canonicalize()?;\nensure!(full.starts_with(base), \"Traversal detected\");",
                attack_vector="User input → Path::new → ../ → Arbitrary file access",
                mitre_technique="T1083 - File and Directory Discovery",
            ),
        ])

        # ====================================================================
        # CATEGORY: XSS / TEMPLATE INJECTION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-XSS-001",
                name="XSS via text/template Without Escaping",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Using text/template with user input can render unsafe HTML",
                pattern=re.compile(r'(?i)(template|Template)::new\s*\([^)]*["\']'),
                context_checks=[],
                suggestion="Use html/template instead of text/template for HTML output",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example="// Use html/template which auto-escapes:\nuse std::fs;\nlet tmpl = fs::read_to_string(\"template.html\")?;\nlet rendered = tera.render(\"template.html\", &context)?;",
                attack_vector="User input → Template rendering → XSS → Session theft",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
            SecurityCheck(
                id="RS-XSS-002",
                name="Reflected XSS via HTTP Response",
                category="xss",
                severity=RiskLevel.CRITICAL,
                description="Writing user input directly to HTTP response allows XSS",
                pattern=re.compile(r'(?i)(HttpResponse\.Ok|Ok\(\)|Response::)'),
                context_checks=[],
                suggestion="Sanitize and escape all user-controlled data in HTTP responses",
                cwe_id="CWE-79",
                owasp_category="A03:2021 - Injection",
                remediation_example='// Use askama/tera templates with auto-escaping\nHtml::new(&escape(&user_input))',
                attack_vector="User input → HTTP response → JavaScript execution → XSS",
                mitre_technique="T1059 - Command and Scripting Interpreter",
            ),
        ])

        # ====================================================================
        # CATEGORY: SSRF
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-SSRF-001",
                name="SSRF via reqwest with User Input",
                category="ssrf",
                severity=RiskLevel.HIGH,
                description="Making HTTP requests to user-controlled URLs allows SSRF attacks",
                pattern=re.compile(r'(?i)(reqwest::get|Client::new|\.get|\.post|\.put)'),
                context_checks=[],
                suggestion="Validate URLs against an allowlist, block private IP ranges",
                cwe_id="CWE-918",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                remediation_example="let parsed = Url::parse(&user_url)?;\nlet allowed = [\"api.github.com\", \"api.stripe.com\"];\nif !allowed.contains(&parsed.host_str().unwrap_or(\"\")) {\n    bail!(\"URL not allowed\");\n}",
                attack_vector="User URL → reqwest → Internal network scan → Internal service compromise",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            ),
        ])

        # ====================================================================
        # CATEGORY: DESERIALIZATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-DESER-001",
                name="Unsafe Serde Deserialization Without Validation",
                category="deserialization",
                severity=RiskLevel.HIGH,
                description="Deserializing untrusted data without validation can cause unexpected behavior",
                pattern=re.compile(r'(?i)serde_json::from_str|serde::Deserialize|from_reader|from_slice'),
                context_checks=[],
                suggestion="Validate deserialized data before use. Use #[serde(deny_unknown_fields)]",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct User {\n    #[serde(deserialize_with = \"validate_name\")]\n    name: String,\n}",
                attack_vector="Malicious payload → Deserialization → Data corruption → Logic bypass",
                mitre_technique="T1055 - Process Injection",
            ),
            SecurityCheck(
                id="RS-DESER-002",
                name="Serde Deserialize Without deny_unknown_fields",
                category="deserialization",
                severity=RiskLevel.MEDIUM,
                description="Without deny_unknown_fields, extra fields in input are silently ignored — can hide injection",
                pattern=re.compile(r'(?i)#\[derive\(Deserialize\)\]'),
                context_checks=[],
                suggestion="Add #[serde(deny_unknown_fields)] to reject unexpected input",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct Input {\n    user_id: i32,\n    action: String,\n}",
                attack_vector="Extra fields → Hidden data injection → Logic bypass",
                mitre_technique="T1055 - Process Injection",
            ),
            SecurityCheck(
                id="RS-DESER-003",
                name="Unsafe YAML Deserialization",
                category="deserialization",
                severity=RiskLevel.CRITICAL,
                description="YAML deserialization from untrusted sources can lead to code execution",
                pattern=re.compile(r'(?i)(serde_yaml::from_str|yaml::from_reader|yaml::from_slice)'),
                context_checks=[],
                suggestion="Avoid YAML deserialization from untrusted sources. Use JSON or messagepack instead",
                cwe_id="CWE-502",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                remediation_example="// Prefer JSON for untrusted data\nlet data: MyStruct = serde_json::from_str(&input)?;",
                attack_vector="Malicious YAML → Deserialization → Arbitrary code execution",
                mitre_technique="T1055 - Process Injection",
            ),
        ])

        # ====================================================================
        # CATEGORY: SECRETS / AUTH
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-AUTH-001",
                name="Hardcoded API Key or Secret",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded secrets in source code are exposed in version control",
                pattern=re.compile(r'(?i)(api_key|apikey|secret|token|password|credential)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}'),
                context_checks=[],
                suggestion="Move secrets to environment variables with dotenv",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="let api_key = std::env::var(\"API_KEY\").expect(\"API_KEY must be set\");",
                attack_vector="Hardcoded secret → VCS exposure → Credential leakage → Account compromise",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RS-AUTH-002",
                name="JWT Secret Hardcoded",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="JWT signing secret hardcoded in source code",
                pattern=re.compile(r'(?i)(jwt_secret|jwt.*key|jwt.*secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}'),
                context_checks=[],
                suggestion="Load JWT secrets from environment variables or a vault service",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="let jwt_secret = std::env::var(\"JWT_SECRET\").expect(\"JWT_SECRET must be set\");",
                attack_vector="Hardcoded JWT secret → Token forgery → Authentication bypass",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RS-AUTH-003",
                name="Private Key Hardcoded in Source",
                category="secrets",
                severity=RiskLevel.CRITICAL,
                description="Private keys hardcoded in source code compromise all cryptography",
                pattern=re.compile(r'(?i)-----BEGIN\s+(RSA|EC|DSA|PRIVATE)\s+KEY-----'),
                context_checks=[],
                suggestion="Store private keys in secure key management systems or encrypted files",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="// Load key from file with restricted permissions:\nlet key = std::fs::read_to_string(\"/etc/keys/private.pem\")?;",
                attack_vector="Hardcoded private key → Key compromise → All crypto operations bypassed",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
            SecurityCheck(
                id="RS-AUTH-004",
                name="Basic Auth Credentials in URL",
                category="secrets",
                severity=RiskLevel.HIGH,
                description="Credentials in URLs can leak through logs and version control",
                pattern=re.compile(r'(?i)https?://[^:]+:[^@]+@'),
                context_checks=[],
                suggestion="Use headers or environment variables for authentication",
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="let client = reqwest::Client::new();\nlet resp = client.get(url)\n    .header(\"Authorization\", format!(\"Bearer {}\", token))\n    .send()?;",
                attack_vector="URL credentials → Log leakage → Credential exposure → Account compromise",
                mitre_technique="T1552 - Unsecured Credentials",
            ),
        ])

        # ====================================================================
        # CATEGORY: CRYPTOGRAPHY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-CRYPTO-001",
                name="Use of MD5 or SHA1 for Security",
                category="cryptography",
                severity=RiskLevel.HIGH,
                description="MD5 and SHA1 are cryptographically broken and should not be used for security",
                pattern=re.compile(r'(?i)(md5|sha1|Sha1|Md5)::'),
                context_checks=[self._is_dangerous_crypto],
                suggestion="Use SHA-256, SHA-3, or Argon2 for password hashing",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="use sha2::{Sha256, Digest};\nlet hash = Sha256::digest(b\"data\");",
                attack_vector="Weak hash → Hash collision → Signature bypass",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RS-CRYPTO-002",
                name="Use of rand::thread_rng for Cryptographic Purposes",
                category="cryptography",
                severity=RiskLevel.CRITICAL,
                description="rand::thread_rng is not cryptographically secure",
                pattern=re.compile(r'(?i)rand::(thread_rng|random)\s*\(|OsRng|StdRng'),
                context_checks=[],
                suggestion="Use rand::rngs::OsRng or getrandom for cryptographic randomness",
                cwe_id="CWE-338",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="use rand::rngs::OsRng;\nuse rand::RngCore;\nlet mut key = [0u8; 32];\nOsRng.fill_bytes(&mut key);",
                attack_vector="Predictable random → Key recovery → Crypto bypass",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RS-CRYPTO-003",
                name="Use of Hardcoded Crypto Keys or IV",
                category="cryptography",
                severity=RiskLevel.CRITICAL,
                description="Hardcoded encryption keys and IVs completely defeat encryption",
                pattern=re.compile(r'(?i)(AES_KEY|IV|NONCE|encryption_key|cipher_key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/=]{8,}'),
                context_checks=[],
                suggestion="Generate keys at runtime, store in secure key management",
                cwe_id="CWE-321",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="let key = std::env::var(\"ENCRYPTION_KEY\").expect(\"KEY must be set\");\nlet cipher = Aes256Gcm::new_from_slice(key.as_bytes())?;",
                attack_vector="Hardcoded key → Encryption bypass → Data breach",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RS-CRYPTO-004",
                name="Use of ECB Mode in AES",
                category="cryptography",
                severity=RiskLevel.CRITICAL,
                description="AES-ECB mode is deterministic and reveals patterns in plaintext",
                pattern=re.compile(r'(?i)(ecb|EcB|Mode::ECB|aes::Aes.*ecb)'),
                context_checks=[],
                suggestion="Use AES-GCM (authenticated encryption) instead of ECB",
                cwe_id="CWE-327",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="use aes_gcm::{Aes256Gcm, Key, Nonce};\nlet cipher = Aes256Gcm::new(Key::from_slice(&key));",
                attack_vector="ECB mode → Pattern leakage → Plaintext recovery",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
        ])

        # ====================================================================
        # CATEGORY: NETWORK / TLS
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-NET-001",
                name="HTTP Without TLS (http://)",
                category="network",
                severity=RiskLevel.HIGH,
                description="Using HTTP instead of HTTPS exposes data in transit",
                pattern=re.compile(r'(?i)http://[^"\'\s]*\.(com|org|net|io|app|dev|api)'),
                context_checks=[],
                suggestion="Always use HTTPS (https://) instead of HTTP",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Change http:// to https://\nlet url = format!(\"https://api.example.com/data\");",
                attack_vector="HTTP → Man-in-the-middle → Data interception → Credential theft",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RS-NET-002",
                name="TLS Certificate Verification Disabled",
                category="network",
                severity=RiskLevel.CRITICAL,
                description="Disabling TLS certificate verification allows MITM attacks",
                pattern=re.compile(r'(?i)(danger_accept_invalid_certs|danger_accept_invalid_hostnames)\s*\(\s*true\s*\)'),
                context_checks=[],
                suggestion="Never disable certificate verification in production",
                cwe_id="CWE-295",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation_example="// Remove the dangerous_accept_invalid_certs call\nlet client = reqwest::Client::builder()\n    .build()?;",
                attack_vector="TLS bypass → MITM → Credential interception → Account compromise",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
            SecurityCheck(
                id="RS-NET-003",
                name="TCP Listener Without TLS",
                category="network",
                severity=RiskLevel.HIGH,
                description="TCP listener without TLS exposes all data in plaintext",
                pattern=re.compile(r'(?i)TcpListener::bind|tokio::net::TcpListener'),
                context_checks=[],
                suggestion="Wrap TCP connections in TLS using rustls or native-tls",
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation_example="// Use tokio-rustls to wrap the TCP connection:\nlet acceptor = TlsAcceptor::from(identity);\nlet stream = acceptor.accept(tcp_stream).await?;",
                attack_vector="Plaintext TCP → Data interception → Credential theft",
                mitre_technique="T1557 - Adversary-in-the-Middle",
            ),
        ])

        # ====================================================================
        # CATEGORY: ERROR HANDLING
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-ERR-001",
                name="Unwrap Without Error Handling",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="Using .unwrap() without error handling can cause panics with user input",
                pattern=re.compile(r'\.unwrap\(\)'),
                context_checks=[self._is_unwrap_with_message],
                suggestion="Use .expect(\"message\") with descriptive messages, or proper error propagation with ?",
                cwe_id="CWE-754",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let value = result.map_err(|e| format!(\"Failed: {}\", e))?;\n// or: let value = result.expect(\"expected valid state\");",
                attack_vector="Panic → Denial of service → Application crash",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-ERR-002",
                name="Use of panic! in Library Code",
                category="error-handling",
                severity=RiskLevel.HIGH,
                description="Using panic! in library code crashes the entire application",
                pattern=re.compile(r'panic!\s*\('),
                context_checks=[],
                suggestion="Return Result with meaningful error types instead of panicking",
                cwe_id="CWE-754",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="return Err(MyError::InvalidInput(input.to_string()));",
                attack_vector="panic! → Application crash → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-ERR-003",
                name="Use of todo!() or unimplemented!() in Production Code",
                category="error-handling",
                severity=RiskLevel.MEDIUM,
                description="todo!() or unimplemented!() will panic at runtime",
                pattern=re.compile(r'todo!\s*\(|unimplemented!\s*\('),
                context_checks=[],
                suggestion="Implement the function or return an error before release",
                cwe_id="CWE-754",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="unimplemented!() → todo!() → return Err(MyError::NotImplemented)",
                attack_vector="Unimplemented code → Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
        ])

        # ====================================================================
        # CATEGORY: CODE QUALITY
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-QLTY-001",
                name="Missing Documentation on Public API",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Public functions require /// documentation",
                pattern=re.compile(r'pub\s+(fn|struct|enum|trait|type|const|static)\s+\w+'),
                context_checks=[],
                suggestion="Add /// documentation comments to all public API items",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="/// Returns the user by ID.\n///\n/// # Errors\n/// Returns `NotFound` if the user does not exist.\npub fn get_user(id: i32) -> Result<User, Error>",
                attack_vector="Poor documentation → Misuse → Security vulnerability",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-QLTY-002",
                name="Use of println!/eprintln! in Production Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="println! and eprintln! should use proper logging",
                pattern=re.compile(r'(?i)(println|eprintln|print!|eprint)!'),
                context_checks=[],
                suggestion="Use the log crate or tracing for production logging",
                cwe_id="CWE-532",
                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                remediation_example='log::info!("Operation completed: {}", id);\n// or\ntracing::info!(user_id = %id, "operation completed");',
                attack_vector="Console output → Log injection → Log forging",
                mitre_technique="T1565 - Data Manipulation",
            ),
            SecurityCheck(
                id="RS-QLTY-003",
                name="Magic Numbers Without Named Constants",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Numeric literals without named constants reduce readability and maintainability",
                pattern=re.compile(r'(?<!\w)(86400|3600|1024|65535|65536|2147483647|4294967295)\b'),
                context_checks=[],
                suggestion="Define named constants with const or static",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="const MAX_RETRIES: u32 = 3;\nconst PAGE_SIZE: usize = 1024;",
                attack_vector="—",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RS-QLTY-004",
                name="Use of .unwrap() in Production Code",
                category="code-quality",
                severity=RiskLevel.MEDIUM,
                description="Using .unwrap() on Results or Options in production code can crash on invalid inputs",
                pattern=re.compile(r'\.unwrap\(\)'),
                context_checks=[self._is_unwrap_with_message],
                suggestion="Use match, if let, or combinators (and_then, map, or_else) for proper error handling",
                cwe_id="CWE-754",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="match result {\n    Ok(value) => process(value),\n    Err(e) => log::error!(\"Failed: {}\", e),\n}",
                attack_vector="Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-QLTY-005",
                name="Large Function — High Complexity Risk",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Functions with too many lines indicate high complexity",
                pattern=re.compile(r'fn\s+\w+'),
                context_checks=[],
                suggestion="Extract helper functions to reduce function size below 30 lines",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Extract logic:\nfn validate_input(input: &str) -> Result<(), Error> { ... }\nfn process_data(data: Data) -> Result<Output, Error> { ... }",
                attack_vector="Complex code → Logic errors → Security vulnerabilities",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RS-QLTY-006",
                name="Use of goto equivalent (loop with break label misuse)",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Complex loop control flow with labels can indicate spaghetti code",
                pattern=re.compile(r"'(?P<label>\w+):\s*(for|while|loop)\b"),
                context_checks=[],
                suggestion="Refactor complex loop logic into separate functions",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Refactor labeled loop into a function:\nfn find_item(items: &[Item], target: &str) -> Option<&Item> { ... }",
                attack_vector="—",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RS-QLTY-007",
                name="Hardcoded Localhost Address",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Hardcoded localhost address may accidentally be deployed to production",
                pattern=re.compile(r'(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0)'),
                context_checks=[],
                suggestion="Make bind addresses configurable via environment variables or config file",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let bind_addr = std::env::var(\"BIND_ADDR\").unwrap_or_else(|_| \"127.0.0.1:8080\".to_string());",
                attack_vector="Hardcoded localhost → Accidental production exposure",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-QLTY-008",
                name="Unused Variable or Import",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Unused variables and imports indicate dead code",
                pattern=re.compile(r'(?i)let\s+_\s*=|use\s+\S+;\s*$'),
                context_checks=[],
                suggestion="Remove unused code and use `#[allow(unused)]` judiciously",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Instead of `let _ = result;`, actually use it:\nresult.map_err(|e| log::error!(\"{}\", e)).ok();",
                attack_vector="Dead code → Confusion → Missing security controls",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RS-QLTY-009",
                name="Unsafe FFI Function Declaration",
                category="ffi",
                severity=RiskLevel.CRITICAL,
                description="FFI function declarations can lead to undefined behavior if types mismatch",
                pattern=re.compile(r'extern\s+"C"\s*\{|extern\s+"C"\s+fn'),
                context_checks=[self._has_unsafe_annotation],
                suggestion="Document safety invariants for all FFI functions",
                cwe_id="CWE-676",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="/// SAFETY:\n/// - `ptr` must be a valid, non-null, aligned pointer to a C string\n/// - The function must not panic\n#[link(name = \"c\")]\nextern \"C\" {\n    fn strlen(ptr: *const c_char) -> usize;\n}",
                attack_vector="FFI mismatch → Memory corruption → Arbitrary code execution",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-QLTY-010",
                name="Use of #[allow(dead_code)] Suppressing Warnings",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="Suppressing dead_code warnings can hide unused and potentially insecure code",
                pattern=re.compile(r'#\[allow\(dead_code\)\]|#\[allow\(unused\)\]'),
                context_checks=[],
                suggestion="Remove unused code instead of suppressing warnings",
                cwe_id="CWE-1113",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="// Remove the #[allow(dead_code)] attribute\n// and the unused function/field",
                attack_vector="Dead code → Unmaintained code → Security vulnerability",
                mitre_technique="—",
            ),
            SecurityCheck(
                id="RS-QLTY-011",
                name="Use of unreachable!() — Incomplete Code",
                category="code-quality",
                severity=RiskLevel.LOW,
                description="unreachable!() will panic if reached — indicates incomplete pattern matching",
                pattern=re.compile(r'unreachable!\s*\('),
                context_checks=[],
                suggestion="Handle all enum variants in match arms instead of using unreachable!()",
                cwe_id="CWE-754",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="match status {\n    Status::Active => process_active(),\n    Status::Inactive => process_inactive(),\n    // All variants covered — no unreachable needed\n}",
                attack_vector="unreachable! → Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
        ])

        # ====================================================================
        # CATEGORY: INTEGER AND INPUT VALIDATION
        # ====================================================================

        checks.extend([
            SecurityCheck(
                id="RS-VAL-001",
                name="Integer Overflow — Unchecked Arithmetic",
                category="input-validation",
                severity=RiskLevel.HIGH,
                description="Integer overflow without overflow checking can cause logic errors",
                pattern=re.compile(r'(?<!\w)as\s+\w+|\w+\s*\+\s*\w+|\w+\s*\*\s*\w+'),
                context_checks=[],
                suggestion="Use checked_add, checked_mul, or wrapping_* for controlled arithmetic",
                cwe_id="CWE-190",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let sum = a.checked_add(b).ok_or(ArithmeticError::Overflow)?;",
                attack_vector="Integer overflow → Logic bypass → Unexpected behavior → Security breach",
                mitre_technique="T1204 - User Execution",
            ),
            SecurityCheck(
                id="RS-VAL-002",
                name="Division by Zero Risk",
                category="input-validation",
                severity=RiskLevel.HIGH,
                description="Division or modulo by zero causes a panic",
                pattern=re.compile(r'(?<!\w)/(\s*\w+|\s*\d+)|\w+\s*%\s*\w+'),
                context_checks=[],
                suggestion="Always check divisor for zero before division",
                cwe_id="CWE-369",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="if divisor == 0 {\n    return Err(DivisionByZero);\n}\nlet result = numerator / divisor;",
                attack_vector="Division by zero → Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-VAL-003",
                name="Unchecked Index Access (could panic)",
                category="input-validation",
                severity=RiskLevel.MEDIUM,
                description="Index access with [] will panic if out of bounds",
                pattern=re.compile(r'\w+\[\s*\w+\s*\]'),
                context_checks=[],
                suggestion="Use .get(index) or .get_mut(index) for safe access",
                cwe_id="CWE-129",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="if let Some(element) = array.get(index) {\n    process(element);\n}",
                attack_vector="OOB access → Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
            SecurityCheck(
                id="RS-VAL-004",
                name="Unchecked Parse From User Input",
                category="input-validation",
                severity=RiskLevel.MEDIUM,
                description="Parsing user input without error handling can cause panics",
                pattern=re.compile(r'(?i)(\.parse::|\.parse\s*\(|from_str)\s*[<(]'),
                context_checks=[],
                suggestion="Always handle parse errors: input.parse::<i32>().map_err(|_| InvalidInput)?",
                cwe_id="CWE-20",
                owasp_category="A04:2021 - Insecure Design",
                remediation_example="let num: i32 = input.parse()\n    .map_err(|_| AppError::InvalidInput(input.to_string()))?;",
                attack_vector="Invalid input → Panic → Denial of service",
                mitre_technique="T1499 - Endpoint Denial of Service",
            ),
        ])

        return checks

    # ======================================================================
    # TAINT ANALYSIS
    # ======================================================================

    TAINT_SOURCE_PATTERNS = {
        "http_request": [
            r'(?i)request\.(uri|path|query_string|method|headers|body)',
            r'(?i)req\.(uri|path|query|params|body)',
            r'(?i)HttpRequest',
            r'(?i)web::Query',
            r'(?i)web::Form',
            r'(?i)web::Json',
            r'(?i)Extract<Query|Form|Json|Path>',
            r'(?i)Form<|Json<',
        ],
        "input_parameter": [
            r'(?i)std::env::args',
            r'(?i)std::io::stdin',
            r'(?i)io::stdin\(\)',
            r'(?i)read_line',
            r'(?i)read_to_string',
        ],
        "file_input": [
            r'(?i)fs::read_to_string',
            r'(?i)File::open',
            r'(?i)read_to_end',
            r'(?i)read_exact',
        ],
        "environment": [
            r'(?i)std::env::var',
            r'(?i)env::var',
        ],
    }

    TAINT_SINK_PATTERNS = {
        "sql_execution": [
            r'(?i)(execute|query|prepare|exec)\s*\(',
            r'(?i)sql_query',
            r'(?i)diesel::',
            r'(?i)sqlx::query',
        ],
        "command_execution": [
            r'(?i)Command::new',
            r'(?i)std::process::Command',
            r'(?i)tokio::process::Command',
        ],
        "file_write": [
            r'(?i)fs::write',
            r'(?i)File::create',
            r'(?i)write_all',
            r'(?i)write!',
        ],
        "network_request": [
            r'(?i)reqwest::',
            r'(?i)Client::',
            r'(?i)\.get\(',
            r'(?i)\.post\(',
            r'(?i)\.put\(',
        ],
    }

    def _extract_taint_sources(self, lines: List[str]) -> Set[str]:
        """Extract taint source variable names from lines."""
        sources = set()
        for category, patterns in self.TAINT_SOURCE_PATTERNS.items():
            for i, line in enumerate(lines):
                for pattern in patterns:
                    if re.search(pattern, line):
                        var_match = re.search(r'let\s+(mut\s+)?(\w+)\s*=', line)
                        if var_match:
                            sources.add(var_match.group(2))
        return sources

    def _run_taint_analysis(self, content: str, lines: List[str], result: AnalysisResult,
                           frameworks: List[str]) -> None:
        """Track tainted variables from sources to sinks."""
        if not self._taint_sources:
            return

        tainted_vars: Set[str] = self._taint_sources.copy()
        propagation_patterns = [
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*format!',
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*(' + '|'.join(re.escape(s) for s in tainted_vars) + r')',
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*&\s*(' + '|'.join(re.escape(s) for s in tainted_vars) + r')',
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*(' + '|'.join(re.escape(s) for s in tainted_vars) + r')\.clone\(\)',
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*(' + '|'.join(re.escape(s) for s in tainted_vars) + r')\.to_string\(\)',
            r'(?i)let\s+(mut\s+)?(\w+)\s*=\s*(' + '|'.join(re.escape(s) for s in tainted_vars) + r')\.as_str\(\)',
        ]

        for _ in range(3):
            new_tainted: Set[str] = set()
            for i, line in enumerate(lines):
                for pp in propagation_patterns:
                    m = re.search(pp, line)
                    if m:
                        target = m.group(2)
                        if target not in tainted_vars:
                            new_tainted.add(target)

            if not new_tainted:
                break
            tainted_vars |= new_tainted
            propagation_patterns = [
                re.sub(r'\) + ' + '|'.join(re.escape(s) for s in tainted_vars), ')', pp)
                for pp in propagation_patterns
            ]

        tainted_sinks: Dict[str, List[Tuple[int, str]]] = {}
        for sink_cat, patterns in self.TAINT_SINK_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line):
                        for var in tainted_vars:
                            if var in line and re.search(r'\b' + re.escape(var) + r'\b', line):
                                if sink_cat not in tainted_sinks:
                                    tainted_sinks[sink_cat] = []
                                tainted_sinks[sink_cat].append((i, line.strip()))
                                break

        for sink_cat, positions in tainted_sinks.items():
            for line_num, code in positions:
                severity = RiskLevel.CRITICAL if sink_cat in ("sql_execution", "command_execution") else RiskLevel.HIGH
                cwe = "CWE-89" if "sql" in sink_cat else ("CWE-78" if "command" in sink_cat else ("CWE-22" if "file" in sink_cat else "CWE-918"))
                issue_id = f"RS-TAINT-{sink_cat.upper()[:4]}-001"
                result.findings.append(Finding(
                    file=str(result.file_path),
                    line=line_num,
                    column=1,
                    issue_type=issue_id,
                    message=f"Tainted data from user input flows to {sink_cat} — possible injection",
                    risk_level=severity,
                    code_snippet=code[:200],
                    suggestion=f"Validate and sanitize all user input before reaching {sink_cat}",
                ))

    # ======================================================================
    # CROSS-LINE ANALYSIS
    # ======================================================================

    def _run_cross_line_analysis(self, content: str, lines: List[str], result: AnalysisResult,
                                frameworks: List[str]) -> None:
        """Detect patterns that span multiple lines."""
        self._check_multiline_sql(content, lines, result)
        self._check_large_unsafe_blocks(content, lines, result)

    def _check_multiline_sql(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Detect multi-line SQL concatenation that spans several lines."""
        sql_keywords = r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s'
        concat_lines: List[int] = []

        for i, line in enumerate(lines):
            if re.search(sql_keywords, line):
                # Check if this line ends with + or format! continuation
                if re.search(r'[\+\&]\s*$|format!\s*\(|concat!\s*\(', line):
                    concat_lines.append(i + 1)
                    # Continue checking next lines
                    j = i + 1
                    while j < len(lines) and re.search(r'[\+\&]\s*$|".*"', lines[j]):
                        if re.search(r'[\+\&]\s*$', lines[j]):
                            j += 1
                        else:
                            break

        for line_num in concat_lines[:5]:
            result.findings.append(Finding(
                file=str(result.file_path),
                line=line_num,
                column=1,
                issue_type="RS-SQL-MULTI",
                message="Multi-line SQL concatenation detected — potential injection if user input is included",
                risk_level=RiskLevel.HIGH,
                code_snippet=lines[line_num - 1].strip()[:200],
                suggestion="Refactor multi-line SQL into a parameterized query with bind parameters",
            ))

    def _check_large_unsafe_blocks(self, content: str, lines: List[str], result: AnalysisResult) -> None:
        """Detect large unsafe blocks that are hard to audit."""
        in_unsafe = False
        unsafe_start = 0
        brace_depth = 0

        for i, line in enumerate(lines):
            if "unsafe {" in line or "unsafe{" in line:
                in_unsafe = True
                unsafe_start = i + 1
                brace_depth = line.count("{") - line.count("}")
            elif in_unsafe:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    block_size = (i + 1) - unsafe_start
                    if block_size > 20:
                        result.findings.append(Finding(
                            file=str(result.file_path),
                            line=unsafe_start,
                            column=1,
                            issue_type="RS-MEM-LARGE-UNSAFE",
                            message=f"Large unsafe block ({block_size} lines) — difficult to audit for safety invariants",
                            risk_level=RiskLevel.HIGH,
                            code_snippet=lines[unsafe_start - 1].strip()[:200],
                            suggestion="Refactor large unsafe blocks into smaller, documented safe abstractions",
                        ))
                    in_unsafe = False

    # ======================================================================
    # UTILITY METHODS
    # ======================================================================

    def get_file_patterns(self) -> List[str]:
        return ["*.rs"]

    def can_analyze(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in [".rs"]
