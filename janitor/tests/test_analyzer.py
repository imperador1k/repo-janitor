"""Testes para o analisador Python."""

import pytest
from pathlib import Path
import tempfile

from janitor.analyzer import PythonAnalyzer, Finding, RiskLevel


class TestPythonAnalyzer:
    """Testes da classe PythonAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Cria inst?ncia do analyzer."""
        return PythonAnalyzer()

    @pytest.fixture
    def temp_file(self):
        """Cria ficheiro tempor?rio."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            yield Path(f.name)
        Path(f.name).unlink(missing_ok=True)

    def test_analyze_empty_file(self, analyzer, temp_file):
        """Testa an?lise de ficheiro vazio."""
        result = analyzer.analyze_file(temp_file)
        assert result.file_path == temp_file
        assert len(result.findings) == 0
        assert result.has_errors is False

    def test_analyze_simple_function(self, analyzer, temp_file):
        """Testa an?lise de fun??o simples."""
        temp_file.write_text('def hello():\n    """Say hello."""\n    pass\n')
        result = analyzer.analyze_file(temp_file)
        assert 'hello' in result.functions
        assert len(result.findings) == 0

    def test_analyze_eval_detection(self, analyzer, temp_file):
        """Testa detec??o de eval()."""
        temp_file.write_text('x = eval("1+1")\n')
        result = analyzer.analyze_file(temp_file)
        eval_findings = [f for f in result.findings if f.issue_type == 'dangerous_function']
        assert len(eval_findings) == 1
        assert eval_findings[0].risk_level == RiskLevel.HIGH

    def test_analyze_exec_detection(self, analyzer, temp_file):
        """Testa detec??o de exec()."""
        temp_file.write_text('exec("print(1)")\n')
        result = analyzer.analyze_file(temp_file)
        exec_findings = [f for f in result.findings if f.issue_type == 'dangerous_function']
        assert len(exec_findings) == 1

    def test_analyze_subprocess_shell_true(self, analyzer, temp_file):
        """Testa detec??o de subprocess shell=True."""
        code = '''
import subprocess
subprocess.run("ls", shell=True)
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        shell_findings = [f for f in result.findings if f.issue_type == 'subprocess_shell_true']
        assert len(shell_findings) == 1
        assert shell_findings[0].risk_level == RiskLevel.HIGH

    def test_analyze_secret_detection(self, analyzer, temp_file):
        """Testa detec??o de secrets."""
        code = '''
api_key = "sk-1234567890abcdef"
password = "secret123"
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        secret_findings = [f for f in result.findings if f.issue_type == 'potential_secret']
        assert len(secret_findings) >= 1
        assert secret_findings[0].risk_level == RiskLevel.CRITICAL

    def test_analyze_imports(self, analyzer, temp_file):
        """Testa extra??o de imports."""
        code = '''
import os
import sys
from pathlib import Path
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        assert 'os' in result.imports
        assert 'sys' in result.imports
        assert 'pathlib.Path' in result.imports

    def test_analyze_syntax_error(self, analyzer, temp_file):
        """Testa tratamento de erro de sintaxe."""
        temp_file.write_text('def broken(:\n')
        result = analyzer.analyze_file(temp_file)
        assert result.has_errors is True
        assert 'syntax' in result.error_message.lower()

    def test_analyze_classes(self, analyzer, temp_file):
        """Testa extra??o de classes."""
        code = '''
class MyClass:
    pass
'''
        temp_file.write_text(code)
        result = analyzer.analyze_file(temp_file)
        assert 'MyClass' in result.classes


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
