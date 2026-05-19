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
from janitor.analyzer import PythonAnalyzer, Finding, RiskLevel
from janitor.js_analyzer import JSAnalyzer
from janitor.llm import LLMClient
from janitor.manager import BackupManager, DiffManager, RollbackManager, CodeModifier

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
                 use_cache: bool = True):
        self.root_path = Path(root_path).resolve()
        self.dry_run = dry_run
        self.apply_changes = apply_changes
        self.use_llm = use_llm
        self.min_severity = min_severity
        self.categories = categories or []
        self.output_json = output_json

        self.scanner = Scanner(str(self.root_path))
        self.python_analyzer = PythonAnalyzer()
        self.js_analyzer = JSAnalyzer()
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

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

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

        console.print("[dim]Scanning files...[/dim]")
        files = list(self.scanner.scan())
        console.print(f"[dim]Found {len(files)} files[/dim]")

        python_files = [f for f in files if f.suffix == '.py']
        js_files = [f for f in files if f.suffix in ('.js', '.ts', '.jsx', '.tsx')]

        console.print(f"[dim]Analyzing {len(python_files)} Python files...[/dim]")
        for file_path in python_files:
            self._analyze_python_file(file_path)

        if js_files:
            console.print(f"[dim]Analyzing {len(js_files)} JS/TS files...[/dim]")
            for file_path in js_files:
                self._analyze_js_file(file_path)

        filtered_findings = [f for f in self.findings if self._passes_filters(f)]

        result = {
            'timestamp': datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'dry_run': self.dry_run,
            'files_scanned': len(files),
            'python_files_analyzed': len(python_files),
            'js_files_analyzed': len(js_files),
            'js_files_analyzed': len(js_files),
            'findings': filtered_findings,
            'total_findings': len(self.findings),
            'total_issues': len(filtered_findings),
            'critical': sum(1 for f in filtered_findings if f.get('risk_level') == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('risk_level') == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('risk_level') == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('risk_level') == 'low'),
        }

        if self.use_llm and self._llm_client:
            result['llm_analysis'] = self._run_llm_analysis()

        return result

    def _run_json(self) -> Dict[str, Any]:
        """Run in JSON mode (no rich output)."""
        files = list(self.scanner.scan())
        python_files = [f for f in files if f.suffix == '.py']
        js_files = [f for f in files if f.suffix in ('.js', '.ts', '.jsx', '.tsx')]

        for file_path in python_files:
            self._analyze_python_file(file_path)

        for file_path in js_files:
            self._analyze_js_file(file_path)

        filtered_findings = [f for f in self.findings if self._passes_filters(f)]

        result = {
            'timestamp': datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'dry_run': self.dry_run,
            'files_scanned': len(files),
            'python_files_analyzed': len(python_files),
            'js_files_analyzed': len(js_files),
            'js_files_analyzed': len(js_files),
            'findings': filtered_findings,
            'total_issues': len(filtered_findings),
            'critical': sum(1 for f in filtered_findings if f.get('risk_level') == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('risk_level') == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('risk_level') == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('risk_level') == 'low'),
        }

        if self.use_llm and self._llm_client:
            result['llm_analysis'] = self._run_llm_analysis()

        return result

    def _analyze_js_file(self, file_path: Path) -> None:
        """Analyze a JS/TS file."""
        try:
            result = self.js_analyzer.analyze_file(file_path)

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

    def _analyze_python_file(self, file_path: Path) -> None:
        """Analisa um ficheiro Python."""
        try:
            result = self.python_analyzer.analyze_file(file_path)

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

        # Try batch analysis first
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
            # Fallback to individual analysis
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
        ]

        for i, finding in enumerate(self.findings, 1):
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
        table.add_row("Python Files Analyzed", str(result['python_files_analyzed']))
        table.add_row("Total Issues", str(result['total_issues']))
        table.add_row("Critical", f"[red]{result['critical']}[/red]")
        table.add_row("High", f"[magenta]{result['high']}[/magenta]")
        table.add_row("Medium", f"[yellow]{result['medium']}[/yellow]")
        table.add_row("Low", f"[cyan]{result['low']}[/cyan]")

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
        description='repo-janitor: Python/Node/TypeScript repository auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repo-janitor .                           # Dry-run analysis
  repo-janitor ./myproject --apply         # Apply recommendations
  repo-janitor . --min-severity high       # Only high/critical issues
  repo-janitor . --category security       # Only security issues
  repo-janitor . --json                    # JSON output for CI/CD
  repo-janitor . -v                        # Verbose output
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

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.clear_cache:
        from janitor.llm import LLMCache
        cache = LLMCache()
        cache.clear()
        console.print("[green]LLM cache cleared[/green]")
        return 0

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
    )

    result = janitor.run()
    janitor.print_results(result)
    janitor.generate_security_audit_report(args.output)

    return 0 if result['critical'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
