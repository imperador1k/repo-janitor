"""Testes para o scanner."""

import pytest
from pathlib import Path
import tempfile
import os

from janitor.scanner import Scanner, IGNORE_DIRS, SUPPORTED_EXTENSIONS


class TestScanner:
    """Testes da classe Scanner."""

    @pytest.fixture
    def temp_dir(self):
        """Cria um diret?rio tempor?rio para testes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_scanner_initialization(self, temp_dir):
        """Testa inicializa??o do scanner."""
        scanner = Scanner(str(temp_dir))
        assert scanner.root_path == temp_dir.resolve()
        assert scanner.use_gitignore is True

    def test_scan_empty_directory(self, temp_dir):
        """Testa scanner em diret?rio vazio."""
        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())
        assert len(files) == 0

    def test_scan_with_python_files(self, temp_dir):
        """Testa scanner com ficheiros Python."""
        (temp_dir / 'test.py').touch()
        (temp_dir / 'main.py').touch()
        (temp_dir / 'README.md').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert len(files) == 3

    def test_scan_ignores_git_directory(self, temp_dir):
        """Testa que .git ? ignorado."""
        git_dir = temp_dir / '.git'
        git_dir.mkdir()
        (git_dir / 'config').touch()

        (temp_dir / 'main.py').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert all('.git' not in str(f) for f in files)

    def test_scan_ignores_node_modules(self, temp_dir):
        """Testa que node_modules ? ignorado."""
        node_modules = temp_dir / 'node_modules'
        node_modules.mkdir()
        (node_modules / 'package').touch()

        (temp_dir / 'index.js').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert all('node_modules' not in str(f) for f in files)

    def test_scan_ignores_venv(self, temp_dir):
        """Testa que venv ? ignorado."""
        venv = temp_dir / 'venv'
        venv.mkdir()
        (venv / 'bin').touch()

        (temp_dir / 'app.py').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert all('venv' not in str(f) for f in files)

    def test_scan_recursive(self, temp_dir):
        """Testa scanner recursivo."""
        subdir = temp_dir / 'subdir'
        subdir.mkdir()
        (subdir / 'nested.py').touch()

        (temp_dir / 'main.py').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert len(files) == 2
        assert any('nested.py' in str(f) for f in files)

    def test_scan_ignores_pycache(self, temp_dir):
        """Testa que __pycache__ ? ignorado."""
        pycache = temp_dir / '__pycache__'
        pycache.mkdir()
        (pycache / 'module.pyc').touch()

        (temp_dir / 'module.py').touch()

        scanner = Scanner(str(temp_dir))
        files = list(scanner.scan())

        assert all('__pycache__' not in str(f) for f in files)
        assert len(files) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
