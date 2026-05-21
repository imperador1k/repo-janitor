"""Testes para o gerenciador de backup e diff."""

import pytest
from pathlib import Path
import tempfile
import shutil

from janitor.legacy.manager import BackupManager, DiffManager, RollbackManager, CodeModifier


class TestBackupManager:
    """Testes da classe BackupManager."""

    @pytest.fixture
    def backup_manager(self):
        """Cria inst?ncia do BackupManager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BackupManager(Path(tmpdir) / 'backups')
            yield manager

    @pytest.fixture
    def test_file(self):
        """Cria ficheiro de teste."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write('print("hello")\n')
            yield Path(f.name)
        Path(f.name).unlink(missing_ok=True)

    def test_create_backup(self, backup_manager, test_file):
        """Testa cria??o de backup."""
        backup = backup_manager.create_backup(test_file)
        assert backup.original_path == test_file
        assert backup.backup_path.exists()
        assert backup.checksum is not None

    def test_list_backups(self, backup_manager, test_file):
        """Testa listagem de backups."""
        backup_manager.create_backup(test_file)
        backups = backup_manager.list_backups()
        assert len(backups) == 1

    def test_calculate_checksum(self, backup_manager, test_file):
        """Testa c?lculo de checksum."""
        original_content = test_file.read_text()
        checksum1 = backup_manager._calculate_checksum(test_file)
        checksum2 = backup_manager._calculate_checksum(test_file)
        assert checksum1 == checksum2


class TestDiffManager:
    """Testes da classe DiffManager."""

    def test_generate_diff(self):
        """Testa gera??o de diff."""
        original = "line1\nline2\nline3\n"
        modified = "line1\nline2_modified\nline3\n"

        diff_result = DiffManager.generate_diff(original, modified, "test.py")

        assert diff_result.original == original
        assert diff_result.modified == modified
        assert diff_result.additions >= 0
        assert diff_result.deletions >= 0


class TestRollbackManager:
    """Testes da classe RollbackManager."""

    @pytest.fixture
    def rollback_setup(self):
        """Configura teste de rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / 'backups'
            backup_manager = BackupManager(backup_dir)
            rollback_manager = RollbackManager(backup_manager)

            test_file = Path(tmpdir) / 'test.py'
            test_file.write_text('original content\n')

            backup_manager.create_backup(test_file)
            test_file.write_text('modified content\n')

            yield test_file, rollback_manager, backup_manager

    def test_rollback(self, rollback_setup):
        """Testa rollback."""
        test_file, rollback_manager, backup_manager = rollback_setup

        original_content = test_file.read_text()
        assert 'modified' in original_content

        success = rollback_manager.rollback(test_file)
        assert success is True

        restored_content = test_file.read_text()
        assert 'original' in restored_content


class TestCodeModifier:
    """Testes da classe CodeModifier."""

    def test_validate_python_valid(self):
        """Testa valida??o de Python v?lido."""
        modifier = CodeModifier()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('def hello():\n    pass\n')
            f.flush()
            file_path = Path(f.name)

        is_valid, msg = modifier.validate_syntax(file_path)
        assert is_valid is True
        file_path.unlink()

    def test_validate_python_invalid(self):
        """Testa valida??o de Python inv?lido."""
        modifier = CodeModifier()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('def broken(:\n')
            f.flush()
            file_path = Path(f.name)

        is_valid, msg = modifier.validate_syntax(file_path)
        assert is_valid is False
        file_path.unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
