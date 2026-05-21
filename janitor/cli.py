"""CLI principal do repo-janitor."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from janitor.scanner import Scanner
from janitor.language_detector import LanguageDetector
from janitor.analyzer import Finding, RiskLevel
from janitor.analyzers import ANALYZER_REGISTRY, get_analyzer
from janitor.llm import LLMClient
from janitor.legacy.manager import BackupManager, DiffManager, RollbackManager, CodeModifier
from janitor.dependency_scanner import DependencyScanner
from janitor.outputs.html_report import generate_html_report
from janitor.hooks import install_hook, uninstall_hook, run_pre_commit

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "red",
    "high": "magenta",
    "medium": "yellow",
    "low": "cyan",
}


class RepoJanitor:
    """Principal orquestrador do repo-janitor."""

    def __init__(self, root_path: str, dry_run: bool = True,
                 apply_changes: bool = False, use_llm: bool = True,
                 min_severity: str = "low", categories: Optional[List[str]] = None,
                 output_json: bool = False, model: Optional[str] = None,
                 use_cache: bool = True, min_language_threshold: float = 1.0,
                 scan_dependencies: bool = False):
        self.root_path = Path(root_path).resolve()
        self.dry_run = dry_run
        self.apply_changes = apply_changes
        self.use_llm = use_llm
        self.min_severity = min_severity
        self.categories = categories or []
        self.output_json = output_json
        self.min_language_threshold = min_language_threshold
        self.scan_dependencies = scan_dependencies

        self.scanner = Scanner(str(self.root_path))
        self.language_detector = LanguageDetector(str(self.root_path), min_threshold=min_language_threshold)
        self.backup_manager = BackupManager()
        self.diff_manager = DiffManager()
        self.rollback_manager = RollbackManager(self.backup_manager)
        self.code_modifier = CodeModifier()

        self._llm_client: Optional[LLMClient] = None
        if use_llm:
            try:
                self._llm_client = LLMClient(model=model, use_cache=use_cache)
            except ValueError as e:
                logger.warning(f"LLM not configured: {e}")
                self.use_llm = False

        self.findings: List[Dict[str, Any]] = []
        self.diffs: List[Dict[str, Any]] = []
        self.language_distribution: Dict[str, float] = {}

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _sort_findings_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity: critical > high > medium > low."""
        return sorted(findings, key=lambda f: self.SEVERITY_ORDER.get(f.get('risk_level', 'low'), 3))

    def _passes_filters(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding passes the severity and category filters."""
        severity = finding.get("risk_level", "low")
        issue_type = finding.get("issue_type", "")

        if self.SEVERITY_ORDER.get(severity, 3) > self.SEVERITY_ORDER.get(self.min_severity, 3):
            return False

        if self.categories:
            category_map = {
                "security": ["dangerous_function", "subprocess_shell_true", "potential_secret"],
                "quality": ["syntax_error", "file_write"],
            }
            finding_category = None
            for cat, types in category_map.items():
                if issue_type in types:
                    finding_category = cat
                    break
            if finding_category and finding_category not in self.categories:
                return False

        return True

    def _detect_languages(self) -> Dict[str, float]:
        """Detect languages in the codebase and return distribution."""
        self.language_distribution = self.language_detector.detect()
        return self.language_distribution

    def _get_analyzers_for_languages(self) -> Dict[str, Any]:
        """Get analyzer instances for detected languages above threshold."""
        dominant_languages = self.language_detector.get_dominant_languages(self.min_language_threshold)
        analyzers = {}

        for lang, percentage in dominant_languages:
            analyzer_cls = get_analyzer(lang)
            if analyzer_cls:
                analyzers[lang] = {
                    "analyzer": analyzer_cls(),
                    "percentage": percentage,
                    "display_name": self.language_detector.get_display_name(lang),
                }
            else:
                logger.warning(f"No analyzer available for {lang} ({percentage:.1f}%)")

        return analyzers

    def run(self) -> Dict[str, Any]:
        """Executa a auditoria completa."""
        if self.output_json:
            return self._run_json()

        console.print(Panel(
            f"[bold blue]repo-janitor[/bold blue] - Repository Auditor\n"
            f"Scanning: [cyan]{self.root_path}[/cyan]",
            title="Starting Audit",
            border_style="blue"
        ))

        console.print("[dim]Detecting languages...[/dim]")
        lang_dist = self._detect_languages()

        if lang_dist:
            lang_table = Table(title="Language Distribution", border_style="blue")
            lang_table.add_column("Language", style="cyan")
            lang_table.add_column("Percentage", style="bold white")
            for lang, pct in sorted(lang_dist.items(), key=lambda x: x[1], reverse=True):
                display_name = self.language_detector.get_display_name(lang)
                lang_table.add_row(display_name, f"{pct:.1f}%")
            console.print(lang_table)
        else:
            console.print("[yellow]No supported languages detected[/yellow]")

        console.print("[dim]Scanning files...[/dim]")
        files = list(self.scanner.scan())
        console.print(f"[dim]Found {len(files)} files[/dim]")

        analyzers = self._get_analyzers_for_languages()

        if not analyzers:
            console.print("[yellow]No analyzers available for detected languages[/yellow]")
            return self._build_result(files, [], [])

        total_files_analyzed = 0
        for lang, info in analyzers.items():
            analyzer = info["analyzer"]
            lang_files = [f for f in files if analyzer.can_analyze(f)]
            if lang_files:
                console.print(f"[dim]Analyzing {len(lang_files)} {info['display_name']} files...[/dim]")
                for idx, file_path in enumerate(lang_files, 1):
                    if idx % 25 == 0 or idx == len(lang_files):
                        console.print(f"[dim]  [{idx}/{len(lang_files)}] {file_path.name}[/dim]")
                    self._analyze_file(file_path, analyzer)
                total_files_analyzed += len(lang_files)

        filtered_findings = self._sort_findings_by_severity([f for f in self.findings if self._passes_filters(f)])

        result = self._build_result(files, lang_files, filtered_findings)
        result['language_distribution'] = lang_dist
        result['languages_analyzed'] = list(analyzers.keys())
        result['total_files_analyzed'] = total_files_analyzed

        # Dependency vulnerability scan
        if self.scan_dependencies:
            console.print("[dim]Scanning dependencies for known vulnerabilities...[/dim]")
            dep_scanner = DependencyScanner(self.root_path)
            dep_findings, dep_stats = dep_scanner.scan()
            # Add dep findings to the global list and result
            for f in dep_findings:
                self.findings.append({
                    'file': f.file,
                    'line': f.line,
                    'column': f.column,
                    'issue_type': f.issue_type,
                    'message': f.message,
                    'risk_level': f.risk_level.value,
                    'code_snippet': f.code_snippet,
                    'suggestion': f.suggestion,
                })
            result['dependency_scan'] = dep_stats
            result['dependency_findings'] = len(dep_findings)

            if dep_stats['vulnerabilities_found']:
                console.print(f"[bold red]Found {dep_stats['vulnerabilities_found']} dependency vulnerabilities[/bold red]")
            else:
                console.print("[green]No dependency vulnerabilities found[/green]")

            # Re-filter findings with deps included
            all_filtered = self._sort_findings_by_severity([f for f in self.findings if self._passes_filters(f)])
            result['findings'] = all_filtered
            result['total_issues'] = len(all_filtered)
            result['critical'] = sum(1 for f in all_filtered if f.get('risk_level') == 'critical')
            result['high'] = sum(1 for f in all_filtered if f.get('risk_level') == 'high')
            result['medium'] = sum(1 for f in all_filtered if f.get('risk_level') == 'medium')
            result['low'] = sum(1 for f in all_filtered if f.get('risk_level') == 'low')

        if self.use_llm and self._llm_client:
            result['llm_analysis'] = self._run_llm_analysis()

        return result

    def _build_result(self, files, lang_files, filtered_findings) -> Dict[str, Any]:
        """Build the result dictionary."""
        return {
            'timestamp': datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'dry_run': self.dry_run,
            'files_scanned': len(files),
            'python_files_analyzed': len([f for f in lang_files if f.suffix == '.py']) if lang_files else 0,
            'js_files_analyzed': len([f for f in lang_files if f.suffix in ('.js', '.ts', '.jsx', '.tsx')]) if lang_files else 0,
            'findings': filtered_findings,
            'total_findings': len(self.findings),
            'total_issues': len(filtered_findings),
            'critical': sum(1 for f in filtered_findings if f.get('risk_level') == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('risk_level') == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('risk_level') == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('risk_level') == 'low'),
        }

    def _run_json(self) -> Dict[str, Any]:
        """Run in JSON mode (no rich output)."""
        files = list(self.scanner.scan())
        lang_dist = self._detect_languages()
        analyzers = self._get_analyzers_for_languages()

        total_files_analyzed = 0
        all_lang_files = []
        for lang, info in analyzers.items():
            analyzer = info["analyzer"]
            lang_files = [f for f in files if analyzer.can_analyze(f)]
            if lang_files:
                for file_path in lang_files:
                    self._analyze_file(file_path, analyzer)
                total_files_analyzed += len(lang_files)
                all_lang_files.extend(lang_files)

        filtered_findings = self._sort_findings_by_severity([f for f in self.findings if self._passes_filters(f)])

        result = {
            'timestamp': datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'dry_run': self.dry_run,
            'files_scanned': len(files),
            'language_distribution': lang_dist,
            'languages_analyzed': list(analyzers.keys()),
            'total_files_analyzed': total_files_analyzed,
            'findings': filtered_findings,
            'total_issues': len(filtered_findings),
            'critical': sum(1 for f in filtered_findings if f.get('risk_level') == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('risk_level') == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('risk_level') == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('risk_level') == 'low'),
        }

        if self.scan_dependencies:
            dep_scanner = DependencyScanner(self.root_path)
            dep_findings, dep_stats = dep_scanner.scan()
            for f in dep_findings:
                self.findings.append({
                    'file': f.file, 'line': f.line, 'column': f.column,
                    'issue_type': f.issue_type, 'message': f.message,
                    'risk_level': f.risk_level.value, 'code_snippet': f.code_snippet,
                    'suggestion': f.suggestion,
                })
            result['dependency_scan'] = dep_stats
            result['dependency_findings'] = len(dep_findings)
            # Re-filter
            all_filtered = self._sort_findings_by_severity([f for f in self.findings if self._passes_filters(f)])
            result['findings'] = all_filtered
            result['total_issues'] = len(all_filtered)
            result['critical'] = sum(1 for f in all_filtered if f.get('risk_level') == 'critical')
            result['high'] = sum(1 for f in all_filtered if f.get('risk_level') == 'high')
            result['medium'] = sum(1 for f in all_filtered if f.get('risk_level') == 'medium')
            result['low'] = sum(1 for f in all_filtered if f.get('risk_level') == 'low')

        if self.use_llm and self._llm_client:
            result['llm_analysis'] = self._run_llm_analysis()

        return result

    def _analyze_file(self, file_path: Path, analyzer) -> None:
        """Analyze a file using the given analyzer."""
        try:
            result = analyzer.analyze_file(file_path)

            for finding in result.findings:
                self.findings.append({
                    'file': str(file_path.relative_to(self.root_path)),
                    'line': finding.line,
                    'column': finding.column,
                    'issue_type': finding.issue_type,
                    'message': finding.message,
                    'risk_level': finding.risk_level.value,
                    'code_snippet': finding.code_snippet,
                    'suggestion': finding.suggestion,
                })

            if result.has_errors:
                logger.warning(f"Error analyzing {file_path}: {result.error_message}")

        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")

    def _run_llm_analysis(self) -> Dict[str, Any]:
        """Execute LLM analysis with graceful fallback."""
        if not self._llm_client:
            return {'error': 'LLM not configured', 'stats': {}}

        llm_findings = []
        files_to_analyze = [
            f for f in list(self.scanner.scan())[:5]
            if f.suffix in ('.py', '.js', '.ts', '.jsx', '.tsx')
        ]

        try:
            batch_files = []
            for file_path in files_to_analyze:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                static_findings = [
                    f for f in self.findings
                    if f['file'] == str(file_path.relative_to(self.root_path))
                ]
                batch_files.append({
                    'path': str(file_path),
                    'content': content,
                    'findings': static_findings,
                })

            batch_results = self._llm_client.analyze_batch(batch_files)
            for batch_result in batch_results:
                if 'error' not in batch_result:
                    llm_findings.append(batch_result)

        except Exception as e:
            logger.warning(f"Batch analysis failed, falling back to individual: {e}")
            for file_path in files_to_analyze:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    static_findings = [
                        f for f in self.findings
                        if f['file'] == str(file_path.relative_to(self.root_path))
                    ]

                    response = self._llm_client.analyze_code(
                        str(file_path), content, static_findings
                    )

                    try:
                        analysis = json.loads(response.content)
                        llm_findings.append({
                            'file': str(file_path),
                            'analysis': analysis,
                            'cached': response.cached,
                        })
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid LLM response for {file_path}")

                except Exception as e:
                    logger.error(f"LLM error for {file_path}: {e}")

        return {
            'files_analyzed': len(llm_findings),
            'findings': llm_findings,
            'stats': self._llm_client.get_stats(),
        }

    def apply_recommendations(self, recommendations: List[Dict[str, Any]]) -> int:
        """Aplica recomendacoes de alteracao."""
        if self.dry_run:
            logger.info("Dry-run mode: no changes will be applied")
            return 0

        if not self.apply_changes:
            logger.info("Use --apply to apply changes")
            return 0

        applied = 0
        for rec in recommendations:
            file_path = Path(rec['file'])
            new_content = rec.get('new_content')

            if new_content:
                success, msg = self.code_modifier.apply_changes(
                    file_path, new_content, self.backup_manager
                )
                if success:
                    applied += 1
                    logger.info(f"Applied: {file_path}")

        return applied

    def generate_security_audit_report(self, output_path: str = "SECURITY_AUDIT.md") -> str:
        """Gera relatorio SECURITY_AUDIT.md."""
        report = self._generate_report_content()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)

        logger.info(f"Report generated: {output_path}")
        return output_path

    def _generate_report_content(self) -> str:
        """Gera conteudo do relatorio."""
        lines = [
            "# SECURITY AUDIT REPORT",
            "",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Repository:** {self.root_path}",
            f"**Mode:** {'DRY-RUN' if self.dry_run else 'APPLY'}",
            "",
            "## LANGUAGE DISTRIBUTION",
            "",
        ]

        for lang, pct in sorted(self.language_distribution.items(), key=lambda x: x[1], reverse=True):
            display_name = self.language_detector.get_display_name(lang)
            lines.append(f"- **{display_name}:** {pct:.1f}%")

        lines.extend([
            "",
            "## SUMMARY",
            "",
            f"- **Total Issues:** {len(self.findings)}",
            f"- **Critical:** {sum(1 for f in self.findings if f.get('risk_level') == 'critical')}",
            f"- **High:** {sum(1 for f in self.findings if f.get('risk_level') == 'high')}",
            f"- **Medium:** {sum(1 for f in self.findings if f.get('risk_level') == 'medium')}",
            f"- **Low:** {sum(1 for f in self.findings if f.get('risk_level') == 'low')}",
            "",
            "## FINDINGS",
            "",
        ])

        sorted_findings = self._sort_findings_by_severity(self.findings)
        for i, finding in enumerate(sorted_findings, 1):
            lines.extend([
                f"### {i}. {finding['issue_type']}",
                "",
                f"- **File:** `{finding['file']}`",
                f"- **Line:** {finding['line']}",
                f"- **Risk:** {finding['risk_level'].upper()}",
                f"- **Message:** {finding['message']}",
                "",
            ])
            if finding.get('suggestion'):
                lines.append(f"**Suggestion:** {finding['suggestion']}")
                lines.append("")

        lines.extend([
            "## RECOMMENDATIONS",
            "",
            "1. Review all CRITICAL and HIGH severity issues immediately",
            "2. Implement suggested fixes for security vulnerabilities",
            "3. Add comprehensive test coverage",
            "4. Consider using a secrets management solution",
            "5. Enable pre-commit hooks for security scanning",
            "",
            "## BACKUPS",
            "",
            f"Backups created in: {self.backup_manager.backup_dir}",
            "",
        ])

        return "\n".join(lines)

    def print_results(self, result: Dict[str, Any]) -> None:
        """Print results using rich."""
        if self.output_json:
            print(json.dumps(result, indent=2))
            return

        console.print()

        table = Table(title="Audit Results", border_style="blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white")

        table.add_row("Files Scanned", str(result['files_scanned']))
        table.add_row("Languages Analyzed", ", ".join(result.get('languages_analyzed', [])))
        table.add_row("Total Files Analyzed", str(result.get('total_files_analyzed', 0)))
        table.add_row("Total Issues", str(result['total_issues']))
        table.add_row("Critical", f"[red]{result['critical']}[/red]")
        table.add_row("High", f"[magenta]{result['high']}[/magenta]")
        table.add_row("Medium", f"[yellow]{result['medium']}[/yellow]")
        table.add_row("Low", f"[cyan]{result['low']}[/cyan]")
        if result.get('dependency_scan'):
            dep = result['dependency_scan']
            table.add_row("Dependency Vulns", f"[red]{dep['vulnerabilities_found']}[/red] ({dep['dependencies_tracked']} deps)")

        console.print(table)

        if result.get('llm_analysis'):
            llm_info = result.get('llm_analysis', {})
            stats = llm_info.get('stats', {})
            stats_text = ""
            if stats:
                stats_text = f"\nRequests: {stats.get('requests', 0)} | Cache hits: {stats.get('cache_hits', 0)} | Errors: {stats.get('errors', 0)}"
            console.print(Panel(
                f"[green]LLM analysis completed[/green]{stats_text}",
                title="AI Analysis",
                border_style="green"
            ))

        if result['total_issues'] > 0:
            findings_table = Table(title="Findings", border_style="red")
            findings_table.add_column("#", style="dim")
            findings_table.add_column("File", style="cyan")
            findings_table.add_column("Line", style="dim")
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Issue", style="white")
            findings_table.add_column("Suggestion", style="dim")

            for i, f in enumerate(result['findings'], 1):
                severity = f.get('risk_level', 'low')
                color = SEVERITY_COLORS.get(severity, 'white')
                findings_table.add_row(
                    str(i),
                    f['file'],
                    str(f['line']),
                    f"[{color}]{severity.upper()}[/{color}]",
                    f['issue_type'],
                    f.get('suggestion', '')[:50] + '...' if len(f.get('suggestion', '')) > 50 else f.get('suggestion', ''),
                )

            console.print()
            console.print(findings_table)

        if self.dry_run and not self.apply_changes:
            console.print()
            console.print(Panel(
                "[yellow]DRY-RUN mode[/yellow] - Use [bold]--apply[/bold] to apply recommended changes",
                border_style="yellow"
            ))


def load_config(path: Path) -> Dict[str, Any]:
    """Load configuration from .repo-janitor.toml if it exists."""
    import tomllib
    config_file = path / ".repo-janitor.toml"
    if config_file.exists():
        try:
            with open(config_file, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    return {}


def main():
    """Funcao principal do CLI."""
    config = load_config(Path.cwd())

    parser = argparse.ArgumentParser(
        description='repo-janitor: Multi-language repository security auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repo-janitor .                           # Dry-run analysis
  repo-janitor ./myproject --apply         # Apply recommendations
  repo-janitor . --min-severity high       # Only high/critical issues
  repo-janitor . --category security       # Only security issues
  repo-janitor . --json                    # JSON output for CI/CD
  repo-janitor . --json                    # JSON output for CI/CD
  repo-janitor . --html                    # Interactive HTML report
  repo-janitor . --html report.html        # Custom HTML report filename
  repo-janitor --install-hooks             # Install pre-commit hook
  repo-janitor --uninstall-hooks           # Remove pre-commit hook
  repo-janitor . -v                        # Verbose output
  repo-janitor . --min-lang-threshold 5    # Only audit languages > 5
        """
    )

    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Path to repository (default: current directory)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        default=True,
        help='Show findings without applying changes (default)'
    )

    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply recommended changes (requires confirmation)'
    )

    parser.add_argument(
        '--no-llm',
        action='store_true',
        default=config.get('general', {}).get('no_llm', False),
        help='Disable LLM analysis'
    )

    parser.add_argument(
        '--min-severity',
        choices=['critical', 'high', 'medium', 'low'],
        default=config.get('general', {}).get('min_severity', 'low'),
        help='Minimum severity level to report (default: low)'
    )

    parser.add_argument(
        '--category',
        choices=['security', 'quality'],
        action='append',
        help='Filter by category (can be used multiple times)'
    )

    parser.add_argument(
        '--json',
        dest='output_json',
        action='store_true',
        default=config.get('output', {}).get('json_output', False),
        help='Output results as JSON (for CI/CD integration)'
    )

    parser.add_argument(
        '--model',
        type=str,
        default=config.get('llm', {}).get('model', None),
        help='LLM model to use (default: meta/llama-3.1-70b-instruct)'
    )

    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable LLM response caching'
    )

    parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='Clear LLM cache and exit'
    )

    parser.add_argument(
        '--deps',
        action='store_true',
        default=config.get('general', {}).get('scan_dependencies', False),
        help='Scan dependencies for known CVEs via OSV.dev API'
    )

    parser.add_argument(
        '--min-lang-threshold',
        type=float,
        default=config.get('general', {}).get('min_language_threshold', 1.0),
        help='Minimum language percentage threshold to audit (default: 1.0)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--output',
        type=str,
        default=config.get('output', {}).get('report_file', 'SECURITY_AUDIT.md'),
        help='Output file for security audit report'
    )

    parser.add_argument(
        '--html',
        nargs='?',
        const='security_report.html',
        default=None,
        metavar='FILE',
        help='Generate interactive HTML report (optional filename, default: security_report.html)'
    )

    parser.add_argument(
        '--install-hooks',
        action='store_true',
        help='Install repo-janitor pre-commit hook'
    )

    parser.add_argument(
        '--uninstall-hooks',
        action='store_true',
        help='Uninstall repo-janitor pre-commit hook'
    )

    parser.add_argument(
        '--pre-commit',
        action='store_true',
        help='Run in pre-commit mode (reads staged file list from stdin)'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.clear_cache:
        from janitor.llm import LLMCache
        cache = LLMCache()
        cache.clear()
        console.print("[green]LLM cache cleared[/green]")
        return 0

    if args.install_hooks:
        root = Path(args.path).resolve()
        if install_hook(root):
            console.print(f"[green]Pre-commit hook installed[/green] at [cyan]{root / '.git' / 'hooks' / 'pre-commit'}[/cyan]")
        else:
            console.print("[yellow]Hook installation failed — check if .git/hooks exists and no hook already present[/yellow]")
        return 0

    if args.uninstall_hooks:
        root = Path(args.path).resolve()
        if uninstall_hook(root):
            console.print("[green]Pre-commit hook removed[/green]")
        else:
            console.print("[yellow]No pre-commit hook found to remove[/yellow]")
        return 0

    if args.pre_commit:
        import sys as _sys
        files = [f.strip() for f in _sys.stdin.read().strip().split('\n') if f.strip()]
        if not files:
            print(json.dumps({"files_checked": 0, "findings": [], "total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}))
            return 0
        result = run_pre_commit(files, args.min_severity)
        print(json.dumps(result, indent=2))
        return 0 if result['critical'] == 0 and result['high'] == 0 else 1

    janitor = RepoJanitor(
        root_path=args.path,
        dry_run=args.dry_run and not args.apply,
        apply_changes=args.apply,
        use_llm=not args.no_llm,
        min_severity=args.min_severity,
        categories=args.category,
        output_json=args.output_json,
        model=args.model,
        use_cache=not args.no_cache,
        min_language_threshold=args.min_lang_threshold,
        scan_dependencies=args.deps,
    )

    result = janitor.run()
    janitor.print_results(result)
    janitor.generate_security_audit_report(args.output)

    if args.html is not None:
        html_path = generate_html_report(result, args.html)
        console.print(f"[green]HTML report generated:[/green] [cyan]{html_path}[/cyan]")

    return 0 if result['critical'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
