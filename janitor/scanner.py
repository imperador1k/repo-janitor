"""Scanner recursivo para repositorios Python/Node/TypeScript."""

import os
import logging
from pathlib import Path
from typing import Generator, Set
from fnmatch import fnmatch

logger = logging.getLogger(__name__)

IGNORE_DIRS: Set[str] = {
    '.git', 'node_modules', 'venv', '.venv', 'env', '.env',
    'dist', 'build', '__pycache__', '.pytest_cache', '.mypy_cache',
    'coverage', '.coverage', 'htmlcov', '.eggs', 'vendor',
    '.idea', '.vscode', 'target'
}

IGNORE_EXTENSIONS: Set[str] = {
    '.pyc', '.pyo', '.pyd', '.so', '.o', '.class',
    '.min.js', '.min.css', '.map', '.lock'
}

SUPPORTED_EXTENSIONS: Set[str] = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.json', '.yaml', '.yml', '.toml', '.md',
    '.html', '.css', '.scss', '.sql'
}


class Scanner:
    """Scanner recursivo de ficheiros com suporte a ignore patterns."""

    def __init__(self, root_path: str, use_gitignore: bool = True):
        self.root_path = Path(root_path).resolve()
        self.use_gitignore = use_gitignore
        self._gitignore_patterns: Set[str] = set()
        if use_gitignore:
            self._load_gitignore()

    def _load_gitignore(self) -> None:
        """Carrega padroes do .gitignore se existir."""
        gitignore_path = self.root_path / '.gitignore'
        if gitignore_path.exists():
            try:
                with open(gitignore_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self._gitignore_patterns.add(line)
                logger.debug(f'Carregados {len(self._gitignore_patterns)} padroes do .gitignore')
            except Exception as e:
                logger.warning(f'Nao foi possivel ler .gitignore: {e}')

    def _should_ignore_dir(self, path: Path) -> bool:
        """Check if a directory should be ignored."""
        name = path.name
        if name in IGNORE_DIRS or name.startswith('.'):
            return True
        if any(fnmatch(name, pattern) for pattern in ['*.egg-info']):
            return True
        return False

    def _should_ignore_file(self, path: Path) -> bool:
        """Check if a file should be ignored."""
        if path.suffix in IGNORE_EXTENSIONS:
            return True
        if path.suffix not in SUPPORTED_EXTENSIONS:
            return True
        for pattern in self._gitignore_patterns:
            if fnmatch(path.name, pattern) or fnmatch(str(path), f'*/{pattern}'):
                return True
        return False

    def _should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored."""
        parts = path.parts
        for part in parts:
            if part in IGNORE_DIRS or part.startswith("."):
                return True
        if path.is_dir():
            return self._should_ignore_dir(path)
        return self._should_ignore_file(path)
        for part in parts:
            if part in IGNORE_DIRS or part.startswith('.'):
                return True
            if any(fnmatch(part, pattern) for pattern in ['*.egg-info']):
                return True

        if path.suffix in IGNORE_EXTENSIONS:
            return True

        if path.suffix not in SUPPORTED_EXTENSIONS:
            return True

        for pattern in self._gitignore_patterns:
            if fnmatch(path.name, pattern) or fnmatch(str(path), f'*/{pattern}'):
                return True

        return False

    def scan(self) -> Generator[Path, None, None]:
        """Scanner recursivo que gera Paths de ficheiros relevantes."""
        logger.info(f'Iniciando scanner em: {self.root_path}')
        file_count = 0

        for dirpath, dirnames, filenames in os.walk(self.root_path):
            dirpath = Path(dirpath)

            dirnames[:] = [
                d for d in dirnames
                if not self._should_ignore(dirpath / d)
            ]

            for filename in filenames:
                file_path = dirpath / filename
                if not self._should_ignore(file_path):
                    file_count += 1
                    yield file_path

        logger.info(f'Scanner concluido. Ficheiros encontrados: {file_count}')
