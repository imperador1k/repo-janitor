"""Pre-commit hook installation and management for repo-janitor."""

import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

HOOK_SCRIPT = r"""#!/usr/bin/env python
""" + '"' + r"""repo-janitor pre-commit hook - blocks commits with critical/high issues.""" + '"' + r"""

import subprocess, sys, json, os

SUPPORTED = ('.py','.js','.ts','.jsx','.tsx','.kt','.java','.go','.rs','.cs','.php','.rb','.cpp','.c','.cc','.cxx','.h','.hpp','.hxx','.dart','.swift')

def _find_python():
    for cmd in [sys.executable, 'python', 'python3', 'py -3']:
        if not cmd:
            continue
        try:
            parts = cmd.split() if ' ' in cmd else [cmd]
            r = subprocess.run(parts + ['--version'], capture_output=True, text=True)
            if r.returncode == 0:
                return cmd
        except FileNotFoundError:
            continue
    return None

def main():
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, cwd=os.getcwd()
        )
    except FileNotFoundError:
        print("repo-janitor: git not found. Is this a git repository?")
        sys.exit(1)

    if result.returncode != 0:
        print("repo-janitor: Failed to get staged files")
        sys.exit(1)

    staged = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    if not staged:
        sys.exit(0)

    to_scan = [f for f in staged if any(f.endswith(ext) for ext in SUPPORTED)]
    if not to_scan:
        sys.exit(0)

    python = _find_python()
    if not python:
        print("repo-janitor: Python not found. Install Python or use 'git commit --no-verify'")
        sys.exit(1)

    input_data = "\n".join(to_scan)
    cmd = python.split() if ' ' in python else [python]
    cmd += ["-m", "janitor.cli", "--pre-commit", "--min-severity", "critical", "--no-llm", "--json"]
    proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, cwd=os.getcwd())

    if proc.returncode != 0:
        print()
        print("=" * 60)
        print("  [repo-janitor] SECURITY ISSUES DETECTED")
        print("  Commit blocked - fix issues or use --no-verify")
        print("=" * 60)
        try:
            data = json.loads(proc.stdout)
            findings = data.get('findings', [])
            if findings:
                for f in findings:
                    level = f.get('risk_level', 'UNKNOWN').upper()
                    path = f.get('file', '?')
                    line = f.get('line', '?')
                    issue = f.get('issue_type', '?')
                    print(f"    [{level}] {path}:{line} - {issue}")
                print(f"  Total: {len(findings)} issue(s)")
        except Exception:
            if proc.stderr:
                print(proc.stderr[:500])
        print("=" * 60)
        print("  To bypass: git commit --no-verify")
        print("=" * 60)
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
"""


def install_hook(project_root: Path) -> bool:
    """Install the pre-commit hook. Returns True on success."""
    hooks_dir = project_root / ".git" / "hooks"
    if not hooks_dir.exists():
        logger.error("No .git/hooks directory found at %s", hooks_dir)
        return False

    hook_path = hooks_dir / "pre-commit"
    if hook_path.exists():
        logger.warning("Pre-commit hook already exists at %s", hook_path)
        return False

    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    hook_path.chmod(0o755)

    if sys.platform == "win32":
        bat_path = hooks_dir / "pre-commit.bat"
        python_path = sys.executable
        bat_content = f'@"{python_path}" "%~dp0pre-commit" %*\n'
        bat_path.write_text(bat_content, encoding="utf-8")
        logger.info("Windows .bat wrapper created at %s", bat_path)

    logger.info("Pre-commit hook installed at %s", hook_path)
    return True


def uninstall_hook(project_root: Path) -> bool:
    """Remove the pre-commit hook. Returns True on success."""
    hook_path = project_root / ".git" / "hooks" / "pre-commit"
    removed = False

    if hook_path.exists():
        hook_path.unlink()
        logger.info("Pre-commit hook removed from %s", hook_path)
        removed = True

    if sys.platform == "win32":
        bat_path = project_root / ".git" / "hooks" / "pre-commit.bat"
        if bat_path.exists():
            bat_path.unlink()
            logger.info("Windows .bat wrapper removed from %s", bat_path)

    if not removed:
        logger.warning("No pre-commit hook found at %s", hook_path)
        return False
    return True


def run_pre_commit(files: List[str], min_severity: str = "critical") -> dict:
    """Analyze a list of staged files. Returns result dict with findings."""
    from janitor.analyzers import get_analyzer_for_file
    from janitor.types import RiskLevel
    from pathlib import Path

    findings = []
    severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_weight = severity_map.get(min_severity, 0)

    for file_path in files:
        fpath = Path(file_path)
        if not fpath.exists():
            continue
        try:
            analyzer = get_analyzer_for_file(fpath)
            if not analyzer:
                continue
            result = analyzer.analyze_file(fpath)
            for finding in result.findings:
                rl = finding.risk_level.value if hasattr(finding.risk_level, 'value') else str(finding.risk_level)
                fw = severity_map.get(rl, 99)
                if fw <= min_weight:
                    findings.append({
                        "file": str(file_path),
                        "line": finding.line,
                        "column": finding.column,
                        "issue_type": finding.issue_type,
                        "message": finding.message,
                        "risk_level": rl,
                        "code_snippet": finding.code_snippet or "",
                        "suggestion": finding.suggestion or "",
                    })
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug("Error analyzing %s: %s", file_path, e)

    critical = sum(1 for f in findings if f.get("risk_level") == "critical")
    high = sum(1 for f in findings if f.get("risk_level") == "high")
    medium = sum(1 for f in findings if f.get("risk_level") == "medium")
    low = sum(1 for f in findings if f.get("risk_level") == "low")

    return {
        "files_checked": len(files),
        "findings": findings,
        "total_issues": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }
