# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- JavaScript/TypeScript static analysis (js_analyzer.py)
- Batch LLM analysis for multiple files
- LLM response caching with configurable TTL
- Graceful fallback when LLM API is unavailable
- Configurable LLM model via --model flag
- --clear-cache command to clear LLM cache
- --no-cache flag to disable caching
- LLM statistics in output (requests, cache hits, errors)
- .env file support via python-dotenv
- .repo-janitor.toml configuration file support
- Rich terminal output with colored tables
- --min-severity filter (critical, high, medium, low)
- --category filter (security, quality)
- --json output for CI/CD integration
- SQL injection pattern detection
- XSS vulnerability detection
- Debug mode detection (DEBUG=True)
- Hardcoded URL with credentials detection
- Unsafe pickle detection
- Cyclomatic complexity calculation
- Missing docstring detection
- Unused import detection
- ny type detection in TypeScript
- @ts-ignore and @ts-nocheck detection

### Fixed
- Scanner ignoring nested directories
- BackupManager failing with paths outside cwd
- Subprocess detection for subprocess.run() pattern
- BOM encoding issues in Python files

### Changed
- Updated dependencies to use openai, python-dotenv, ich
- Improved CLI output with rich formatting
- Reorganized package structure under janitor/

## [0.1.0] - 2026-05-19

### Added
- Initial release
- Python AST-based static analysis
- NVIDIA NIM API integration
- Recursive file scanner with ignore patterns
- Security audit report generation (SECURITY_AUDIT.md)
- Backup and rollback system
- Dry-run mode by default
- CLI with argparse
- Unit tests (24 tests)
