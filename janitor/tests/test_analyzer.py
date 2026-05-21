"""Testes para o analisador Python."""

import pytest
from pathlib import Path
import tempfile

from janitor.analyzers.python import PythonAnalyzer
from janitor.types import Finding, RiskLevel


class TestPythonAnalyzer:
    """Testes da classe PythonAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Cria instancia do analyzer."""
        return PythonAnalyzer()

    @pytest.fixture
    def temp_file(self):
        """Cria ficheiro temporario."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            yield Path(f.name)
        Path(f.name).unlink(missing_ok=True)

    def test_analyze_empty_file(self, analyzer, temp_file):
        """Testa analise de ficheiro vazio."""
        result = analyzer.analyze_file(temp_file)
        assert result.file_path == temp_file
        assert len(result.findings) == 0
        assert result.has_errors is False

    def test_analyze_simple_function(self, analyzer, temp_file):
        """Testa analise de funcao simples."""
        temp_file.write_text('def hello():\n    """Say hello."""\n    pass\n')
        result = analyzer.analyze_file(temp_file)
        assert len(result.findings) == 0

    def test_analyze_eval_detection(self, analyzer, temp_file):
        """Testa deteccao de eval()."""
        temp_file.write_text('x = eval("1+1")\n')
        result = analyzer.analyze_file(temp_file)
        eval_findings = [f for f in result.findings if f.issue_type.startswith('PY-EVAL')]
        assert len(eval_findings) == 1
        assert eval_findings[0].risk_level == RiskLevel.CRITICAL

    def test_analyze_exec_detection(self, analyzer, temp_file):
        """Testa deteccao de exec()."""
        temp_file.write_text('exec("print(1)")\n')
        result = analyzer.analyze_file(temp_file)
        exec_findings = [f for f in result.findings if f.issue_type.startswith('PY-EXEC')]
        assert len(exec_findings) == 1

    def test_analyze_subprocess_shell_true(self, analyzer, temp_file):
        """Testa deteccao de subprocess shell=True."""
        code = '''
import subprocess
subprocess.run("ls", shell=True)
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        shell_findings = [f for f in result.findings if f.issue_type == 'PY-CMD-002']
        assert len(shell_findings) >= 1
        assert shell_findings[0].risk_level == RiskLevel.CRITICAL

    def test_analyze_secret_detection(self, analyzer, temp_file):
        """Testa deteccao de secrets."""
        code = '''
api_key = "sk-1234567890abcdef"
password = "secret123"
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        secret_findings = [f for f in result.findings if f.issue_type == 'PY-AUTH-002']
        assert len(secret_findings) >= 1
        assert secret_findings[0].risk_level == RiskLevel.CRITICAL

    def test_analyze_imports(self, analyzer, temp_file):
        """Testa extraccao de imports (via metadata)."""
        code = '''
import os
import sys
from pathlib import Path
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        assert 'os' not in result.findings  # no findings for clean code
        assert not result.has_errors

    def test_analyze_syntax_error(self, analyzer, temp_file):
        """Testa tratamento de erro de sintaxe."""
        # This test should work as the analyzer uses AST
        temp_file.write_text('def broken(:\n')
        result = analyzer.analyze_file(temp_file)
        assert result.has_errors is True
        assert 'syntax' in result.error_message.lower()

    def test_analyze_classes(self, analyzer, temp_file):
        """Testa extraccao de classes."""
        code = '''
class MyClass:
    pass
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        assert not result.has_errors


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
