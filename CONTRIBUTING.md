# Contributing to repo-janitor

Thank you for your interest in contributing to repo-janitor! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Bugs

Before creating a bug report:

1. Check the [existing issues](https://github.com/your-username/repo-janitor/issues) to see if the problem has already been reported
2. Collect information about the bug:
   - repo-janitor version (epo-janitor --version or pip show repo-janitor)
   - Python version (python --version)
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior

When submitting a bug report, include:

- A clear and descriptive title
- Detailed steps to reproduce
- Expected behavior
- Actual behavior
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- A clear and descriptive title
- A detailed description of the proposed feature
- Why this feature would be useful
- Any alternative solutions you've considered

### Pull Requests

1. Fork the repository
2. Create a new branch from main:
   `ash
   git checkout -b feature/your-feature-name
   `
3. Make your changes
4. Add or update tests as needed
5. Ensure all tests pass:
   `ash
   pytest janitor/tests/ -v
   `
6. Commit your changes with a clear message:
   `ash
   git commit -m "feat: add new security pattern detection"
   `
7. Push to your fork:
   `ash
   git push origin feature/your-feature-name
   `
8. Open a Pull Request

## Development Setup

1. Clone your fork:
   `ash
   git clone https://github.com/your-username/repo-janitor.git
   cd repo-janitor
   `

2. Create a virtual environment:
   `ash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   `

3. Install development dependencies:
   `ash
   pip install -e ".[dev]"
   `

4. Run tests:
   `ash
   pytest janitor/tests/ -v
   `

## Code Style

This project uses:

- **ruff** for linting and formatting
- **mypy** for type checking

Before submitting a PR, run:

`ash
# Lint
ruff check janitor/

# Format
ruff format janitor/

# Type check
mypy janitor/

# Run tests
pytest janitor/tests/ -v
`

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- eat: New feature
- ix: Bug fix
- docs: Documentation changes
- style: Code style changes (formatting, etc.)
- efactor: Code refactoring
- 	est: Adding or updating tests
- chore: Maintenance tasks

Examples:

`
feat: add TypeScript any type detection
fix: resolve scanner infinite loop on symlink cycles
docs: update README with new CLI options
test: add tests for SQL injection patterns
`

## Testing

- Write tests for new features
- Ensure existing tests pass
- Aim for high test coverage

`ash
# Run all tests
pytest janitor/tests/ -v

# Run with coverage
pytest janitor/tests/ -v --cov=janitor --cov-report=term-missing

# Run specific test file
pytest janitor/tests/test_analyzer.py -v
`

## Questions?

Feel free to open an issue for any questions not covered here.
