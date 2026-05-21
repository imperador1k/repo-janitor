"""Language detector - analyzes codebase composition by language."""

import os
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

LANGUAGE_EXTENSIONS: Dict[str, List[str]] = {
    "python": [".py", ".pyi"],
    "typescript": [".ts", ".tsx"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "kotlin": [".kt", ".kts", ".ktm"],
    "java": [".java"],
    "csharp": [".cs", ".csx"],
    "go": [".go"],
    "rust": [".rs"],
    "cpp": [".cpp", ".cxx", ".cc", ".c", ".hpp", ".hxx", ".hh", ".h"],
    "php": [".php", ".phtml", ".php3", ".php4", ".php5"],
    "ruby": [".rb", ".rbw", ".rake"],
    "swift": [".swift"],
    "html": [".html", ".htm"],
    "css": [".css", ".scss", ".sass", ".less"],
    "sql": [".sql"],
    "shell": [".sh", ".bash", ".zsh", ".fish"],
    "dockerfile": [],
    "terraform": [".tf", ".tfvars", ".hcl"],
    "yaml": [".yaml", ".yml"],
    "json": [".json"],
    "markdown": [".md", ".mdx"],
    "toml": [".toml"],
}

LANGUAGE_FILE_PATTERNS: Dict[str, List[str]] = {
    "dockerfile": ["Dockerfile", "Dockerfile.*", "Containerfile"],
    "terraform": [],
}

LANGUAGE_DISPLAY_NAMES: Dict[str, str] = {
    "python": "Python",
    "typescript": "TypeScript",
    "javascript": "JavaScript",
    "kotlin": "Kotlin",
    "java": "Java",
    "csharp": "C#",
    "go": "Go",
    "rust": "Rust",
    "cpp": "C/C++",
    "php": "PHP",
    "ruby": "Ruby",
    "swift": "Swift",
    "html": "HTML",
    "css": "CSS/SCSS",
    "sql": "SQL",
    "shell": "Shell",
    "dockerfile": "Dockerfile",
    "terraform": "Terraform/HCL",
    "yaml": "YAML",
    "json": "JSON",
    "markdown": "Markdown",
    "toml": "TOML",
}

IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", ".env",
    "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache",
    "coverage", ".coverage", "htmlcov", ".eggs", "vendor",
    ".idea", ".vscode", "target", "bin", "obj",
    ".gradle", ".m2", ".cache", "vendor",
}


class LanguageDetector:
    """Detects programming languages in a codebase and calculates their distribution."""

    def __init__(self, root_path: str, min_threshold: float = 1.0):
        self.root_path = Path(root_path).resolve()
        self.min_threshold = min_threshold
        self._ext_to_lang: Dict[str, str] = {}
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            for ext in exts:
                self._ext_to_lang[ext] = lang

    def detect(self) -> Dict[str, float]:
        """Analyze codebase and return language distribution as percentages."""
        if not self.root_path.exists():
            logger.warning(f"Path does not exist: {self.root_path}")
            return {}

        lang_lines: Dict[str, int] = defaultdict(int)
        total_lines = 0

        for dirpath, dirnames, filenames in os.walk(self.root_path):
            dirpath_path = Path(dirpath)
            if dirpath_path.name in IGNORE_DIRS:
                dirnames.clear()
                continue

            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]

            for filename in filenames:
                file_path = dirpath_path / filename
                lang = self._detect_file_language(filename, file_path)
                if lang:
                    try:
                        lines = self._count_lines(file_path)
                        lang_lines[lang] += lines
                        total_lines += lines
                    except Exception:
                        pass

        if total_lines == 0:
            return {}

        result = {}
        for lang, lines in lang_lines.items():
            percentage = (lines / total_lines) * 100
            result[lang] = round(percentage, 2)

        logger.info(f"Language detection complete. Found {len(result)} languages, {total_lines} total lines")
        return result

    def get_dominant_languages(self, threshold: float = None) -> List[Tuple[str, float]]:
        """Return languages above the minimum threshold, sorted by percentage."""
        threshold = threshold or self.min_threshold
        distribution = self.detect()
        filtered = [(lang, pct) for lang, pct in distribution.items() if pct >= threshold]
        return sorted(filtered, key=lambda x: x[1], reverse=True)

    def get_language_for_extension(self, ext: str) -> str:
        """Get language name for a given file extension."""
        return self._ext_to_lang.get(ext.lower(), "unknown")

    def get_display_name(self, lang: str) -> str:
        """Get human-readable display name for a language."""
        return LANGUAGE_DISPLAY_NAMES.get(lang, lang.title())

    def _detect_file_language(self, filename: str, file_path: Path) -> str:
        """Detect the language of a single file."""
        ext = file_path.suffix.lower()

        if ext in self._ext_to_lang:
            return self._ext_to_lang[ext]

        for lang, patterns in LANGUAGE_FILE_PATTERNS.items():
            for pattern in patterns:
                if filename == pattern or filename.startswith(pattern.replace("*", "")):
                    return lang

        return ""

    def _count_lines(self, file_path: Path) -> int:
        """Count non-empty lines in a file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0
