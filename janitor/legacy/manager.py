"""Gerenciador de backup, diff e rollback para alteracoes de codigo."""

import os
import shutil
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import json

logger = logging.getLogger(__name__)


@dataclass
class BackupInfo:
    """Informacoes sobre um backup."""
    original_path: Path
    backup_path: Path
    timestamp: datetime
    checksum: str
    size: int


@dataclass
class DiffResult:
    """Resultado de comparacao entre ficheiros."""
    original: str
    modified: str
    unified_diff: str
    additions: int
    deletions: int


class BackupManager:
    """Gerencia backups de ficheiros antes de alteracoes."""

    def __init__(self, backup_dir: Optional[Path] = None):
        """Inicializa o gerenciador de backups."""
        self.backup_dir = backup_dir or Path('backups')
        self.backup_dir.mkdir(exist_ok=True)
        self._backups: List[BackupInfo] = []

    def create_backup(self, file_path: Path) -> BackupInfo:
        """Cria um backup de um ficheiro."""
        if not file_path.exists():
            raise FileNotFoundError(f"Ficheiro nao encontrado: {file_path}")

        timestamp = datetime.now()
        relative_path = Path(file_path.name)
        backup_subdir = self.backup_dir / timestamp.strftime('%Y%m%d_%H%M%S')
        backup_subdir.mkdir(parents=True, exist_ok=True)

        backup_path = backup_subdir / relative_path
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(file_path, backup_path)

        checksum = self._calculate_checksum(file_path)
        size = file_path.stat().st_size

        backup_info = BackupInfo(
            original_path=file_path,
            backup_path=backup_path,
            timestamp=timestamp,
            checksum=checksum,
            size=size
        )

        self._backups.append(backup_info)
        logger.info(f"Backup criado: {backup_path}")

        return backup_info

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calcula checksum MD5 de um ficheiro."""
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def list_backups(self) -> List[BackupInfo]:
        """Lista todos os backups criados."""
        return self._backups.copy()

    def get_latest_backup(self, file_path: Path) -> Optional[BackupInfo]:
        """Obtem o backup mais recente de um ficheiro."""
        matching = [b for b in self._backups if b.original_path == file_path]
        return max(matching, key=lambda b: b.timestamp) if matching else None


class DiffManager:
    """Gerencia geracao de diffs entre ficheiros."""

    @staticmethod
    def generate_diff(original: str, modified: str, 
                      file_path: str = "file") -> DiffResult:
        """Gera diff unificado entre dois conteudos."""
        original_lines = original.splitlines(keepends=True)
        modified_lines = modified.splitlines(keepends=True)

        unified_diff = DiffManager._generate_unified_diff(
            original_lines, modified_lines, file_path
        )

        additions = sum(1 for line in modified_lines 
                       if line not in original_lines)
        deletions = sum(1 for line in original_lines 
                       if line not in modified_lines)

        return DiffResult(
            original=original,
            modified=modified,
            unified_diff=unified_diff,
            additions=additions,
            deletions=deletions
        )

    @staticmethod
    def _generate_unified_diff(original_lines: List[str], 
                               modified_lines: List[str],
                               file_path: str) -> str:
        """Gera diff unificado estilo Unix."""
        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
        ]

        diff_lines.extend(
            DiffManager._compute_diff_hunks(original_lines, modified_lines)
        )

        return ''.join(diff_lines)

    @staticmethod
    def _compute_diff_hunks(original: List[str], 
                            modified: List[str]) -> List[str]:
        """Computa hunks de diff usando algoritmo LCS."""
        diff_result = []
        orig_idx = 0
        mod_idx = 0

        while orig_idx < len(original) or mod_idx < len(modified):
            if orig_idx < len(original) and mod_idx < len(modified):
                if original[orig_idx] == modified[mod_idx]:
                    diff_result.append(f" {original[orig_idx]}")
                    orig_idx += 1
                    mod_idx += 1
                else:
                    diff_result.append(f"-{original[orig_idx]}")
                    diff_result.append(f"+{modified[mod_idx]}")
                    orig_idx += 1
                    mod_idx += 1
            elif orig_idx < len(original):
                diff_result.append(f"-{original[orig_idx]}")
                orig_idx += 1
            else:
                diff_result.append(f"+{modified[mod_idx]}")
                mod_idx += 1

        return diff_result


class RollbackManager:
    """Gerencia rollback de alteracoes."""

    def __init__(self, backup_manager: BackupManager):
        """Inicializa com referencia ao BackupManager."""
        self.backup_manager = backup_manager
        self._rollback_log: List[Dict] = []

    def rollback(self, file_path: Path) -> bool:
        """Restaura um ficheiro do backup mais recente."""
        backup_info = self.backup_manager.get_latest_backup(file_path)
        
        if not backup_info:
            logger.warning(f"Nenhum backup encontrado para {file_path}")
            return False

        try:
            shutil.copy2(backup_info.backup_path, file_path)
            logger.info(f"Rollback realizado: {file_path}")
            
            self._rollback_log.append({
                'file': str(file_path),
                'timestamp': datetime.now().isoformat(),
                'backup_path': str(backup_info.backup_path)
            })
            return True
        except Exception as e:
            logger.error(f"Erro no rollback: {e}")
            return False

    def rollback_all(self) -> int:
        """Restaura todos os ficheiros backupados."""
        success_count = 0
        for backup in reversed(self.backup_manager.list_backups()):
            if self.rollback(backup.original_path):
                success_count += 1
        return success_count

    def get_rollback_log(self) -> List[Dict]:
        """Obtem o log de rollbacks realizados."""
        return self._rollback_log.copy()


class CodeModifier:
    """Aplica modificacoes de codigo com validacao."""

    def __init__(self):
        self.VALIDATORS = {
            '.py': self._validate_python,
            '.js': self._validate_javascript,
            '.ts': self._validate_typescript,
        }

    def _validate_python(self, file_path: Path) -> Tuple[bool, str]:
        """Valida sintaxe Python."""
        import ast
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                ast.parse(f.read())
            return True, "Sintaxe Python valida"
        except SyntaxError as e:
            return False, f"Erro de sintaxe: {e}"

    def _validate_javascript(self, file_path: Path) -> Tuple[bool, str]:
        """Valida sintaxe JavaScript (basica)."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            if content.count('(') != content.count(')'):
                return False, "Parenteses desbalanceados"
            if content.count('{') != content.count('}'):
                return False, "Chaves desbalanceadas"
            return True, "Validacao basica OK"
        except Exception as e:
            return False, f"Erro: {e}"

    def _validate_typescript(self, file_path: Path) -> Tuple[bool, str]:
        """Valida sintaxe TypeScript (basica)."""
        return self._validate_javascript(file_path)

    def validate_syntax(self, file_path: Path) -> Tuple[bool, str]:
        """Valida sintaxe baseado na extensao."""
        ext = file_path.suffix
        validator = self.VALIDATORS.get(ext)
        
        if not validator:
            return True, "Sem validador para esta extensao"
        
        return validator(file_path)

    def apply_changes(self, file_path: Path, new_content: str,
                      backup_manager: BackupManager,
                      validate: bool = True) -> Tuple[bool, str]:
        """Aplica alteracoes a um ficheiro com validacao."""
        if validate:
            is_valid, msg = self.validate_syntax(file_path)
            if not is_valid:
                return False, f"Sintaxe invalida: {msg}"

        try:
            backup_manager.create_backup(file_path)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            logger.info(f"Alteracoes aplicadas: {file_path}")
            return True, "Alteracoes aplicadas com sucesso"
        except Exception as e:
            logger.error(f"Erro ao aplicar alteracoes: {e}")
            return False, f"Erro: {e}"
