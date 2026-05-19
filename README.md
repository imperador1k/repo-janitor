# repo-janitor

> AI-powered repository auditor and refactoring assistant for Python, JavaScript, and TypeScript projects.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-24%20passed-brightgreen.svg)](https://github.com/)

**repo-janitor** is a professional CLI tool that performs comprehensive security, performance, and quality audits on your codebase. It combines static analysis with AI-powered insights to help you write safer, cleaner code.

## Features

### Static Analysis (No AI Required)
- **Python AST Analysis**: Detects dangerous functions (`eval`, `exec`, `compile`), unsafe `subprocess` usage, hardcoded secrets, SQL injection patterns, XSS vulnerabilities, and more
- **JavaScript/TypeScript Analysis**: Detects `eval()`, `innerHTML` XSS, `console.log` statements, `any` types, `@ts-ignore` directives
- **Code Quality Metrics**: Cyclomatic complexity, missing docstrings, unused imports
- **Recursive Scanner**: Intelligently scans your project while ignoring `.git`, `node_modules`, `venv`, `__pycache__`, and other common directories

### AI-Powered Analysis (Optional)
- **NVIDIA NIM Integration**: Uses OpenAI-compatible API for advanced code review
- **Batch Processing**: Sends multiple files in a single request for efficiency
- **Response Caching**: Avoids re-analyzing unchanged files (24h TTL)
- **Graceful Fallback**: Continues with static analysis if AI is unavailable

### Safety First
- **Dry-Run by Default**: Never modifies files without explicit `--apply` flag
- **Automatic Backups**: Creates backups before any file modification
- **Syntax Validation**: Validates Python syntax before applying changes
- **Rollback Support**: Easy rollback to original state

### Developer Experience
- **Rich Output**: Beautiful colored tables and panels in the terminal
- **JSON Output**: `--json` flag for CI/CD pipeline integration
- **Configurable Filters**: Filter by severity (`--min-severity`) and category (`--category`)
- **Config File**: `.repo-janitor.toml` for persistent project settings
- **Environment Variables**: `.env` file support for API keys

## Installation

### From PyPI (Recommended)

```bash
pip install repo-janitor
```

### From Source

```bash
git clone https://github.com/your-username/repo-janitor.git
cd repo-janitor
pip install -e .
```

### With Development Dependencies

```bash
pip install -e ".[dev]"
```

## Quick Start

### Basic Usage

```bash
# Analyze current directory (dry-run mode)
repo-janitor .

# Analyze a specific project
repo-janitor /path/to/my-project

# Verbose output
repo-janitor . -v
```

### Filtering Results

```bash
# Only show critical and high severity issues
repo-janitor . --min-severity high

# Only show security-related issues
repo-janitor . --category security

# Only show quality issues
repo-janitor . --category quality

# Combine filters
repo-janitor . --min-severity medium --category security
```

### AI-Powered Analysis

```bash
# Set your NVIDIA NIM API key
export NIM_API_KEY="your-api-key-here"

# Run with AI analysis
repo-janitor .

# Use a specific model
repo-janitor . --model meta/llama-3.1-405b-instruct

# Disable caching
repo-janitor . --no-cache

# Clear the LLM cache
repo-janitor --clear-cache
```

### CI/CD Integration

```bash
# JSON output for pipeline processing
repo-janitor . --json > audit-results.json

# Fail on critical issues (exit code 1)
repo-janitor . --min-severity critical --json
```

## Configuration

### Environment Variables

Create a `.env` file in your project root:

```env
# Required for AI analysis
NIM_API_KEY=your-nvidia-nim-api-key

# Optional: Custom API endpoint
NIM_BASE_URL=https://integrate.api.nvidia.com/v1

# Optional: Custom model
NIM_MODEL=meta/llama-3.1-70b-instruct
```

### Project Configuration

Create a `.repo-janitor.toml` file in your project root:

```toml
[general]
min_severity = "low"
categories = ["security", "quality"]
no_llm = false

[output]
report_file = "SECURITY_AUDIT.md"
json_output = false

[llm]
base_url = "https://integrate.api.nvidia.com/v1"
model = "meta/llama-3.1-70b-instruct"
```

## What It Detects

### Python Security Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| `eval()` / `exec()` | HIGH | Dangerous function execution |
| `subprocess` with `shell=True` | HIGH | Command injection risk |
| `pickle.load()` | HIGH | Arbitrary code execution on deserialization |
| Hardcoded secrets | CRITICAL | API keys, passwords, tokens |
| SQL injection patterns | CRITICAL | String formatting in queries |
| XSS patterns | HIGH | Unescaped user input |
| Debug mode enabled | MEDIUM | `DEBUG=True` in production code |
| Hardcoded URLs with credentials | HIGH | Database connection strings |

### JavaScript/TypeScript Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| `eval()` / `Function()` | HIGH | Dangerous function execution |
| `innerHTML` / `document.write` | HIGH | XSS vulnerability |
| `console.log` statements | LOW | Debug code left in production |
| `debugger` statements | MEDIUM | Debugger left in code |
| Passwords in `localStorage` | CRITICAL | Insecure credential storage |
| `any` type in TypeScript | MEDIUM | Defeats type checking |
| `@ts-ignore` / `@ts-nocheck` | MEDIUM/HIGH | Suppresses type checking |

### Code Quality Issues

| Issue | Severity | Description |
|-------|----------|-------------|
| High cyclomatic complexity | MEDIUM | Functions too complex (>10) |
| Missing docstrings | LOW | Undocumented functions/classes |
| Unused imports | LOW | Dead code |
| Syntax errors | MEDIUM | Invalid Python syntax |

## Command Reference

```
usage: repo-janitor [-h] [--dry-run] [--apply] [--no-llm]
                    [--min-severity {critical,high,medium,low}]
                    [--category {security,quality}] [--json] [--model MODEL]
                    [--no-cache] [--clear-cache] [-v] [--output OUTPUT]
                    [path]

positional arguments:
  path                  Path to repository (default: current directory)

options:
  -h, --help            Show this help message and exit
  --dry-run             Show findings without applying changes (default)
  --apply               Apply recommended changes (requires confirmation)
  --no-llm              Disable LLM analysis
  --min-severity        Minimum severity level to report (default: low)
  --category            Filter by category (can be used multiple times)
  --json                Output results as JSON (for CI/CD integration)
  --model MODEL         LLM model to use
  --no-cache            Disable LLM response caching
  --clear-cache         Clear LLM cache and exit
  -v, --verbose         Verbose output
  --output OUTPUT       Output file for security audit report
```

## Project Structure

```
repo-janitor/
??? janitor/                 # Main package
?   ??? __init__.py          # Package metadata
?   ??? cli.py               # CLI entry point with rich output
?   ??? scanner.py           # Recursive file scanner
?   ??? analyzer.py          # Python static analyzer (AST)
?   ??? js_analyzer.py       # JavaScript/TypeScript analyzer
?   ??? llm.py               # NVIDIA NIM API client with caching
?   ??? manager.py           # Backup, diff, and rollback
?   ??? core.py              # Module exports
?   ??? tests/               # Unit tests
?       ??? test_scanner.py
?       ??? test_analyzer.py
?       ??? test_manager.py
?       ??? example_vulnerable.*
??? pyproject.toml           # Project configuration
??? requirements.txt         # Dependencies
??? README.md                # This file
??? LICENSE                  # MIT License
??? .env.example             # Environment variables template
??? .repo-janitor.toml.example # Config file template
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest janitor/tests/ -v

# Run with coverage
pytest janitor/tests/ -v --cov=janitor --cov-report=term-missing

# Run specific test file
pytest janitor/tests/test_analyzer.py -v
```

### Code Style

This project uses:
- **ruff** for linting and formatting
- **mypy** for type checking

```bash
# Lint
ruff check janitor/

# Format
ruff format janitor/

# Type check
mypy janitor/
```

## CI/CD Example

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install repo-janitor
        run: pip install repo-janitor
      - name: Run security audit
        run: repo-janitor . --min-severity high --json > audit.json
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-audit
          path: audit.json
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Author

repo-janitor team
